let healthChart;
let latencyChart;
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>\"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));

async function api(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function toast(message) {
  $("toast").textContent = message;
  $("toast").style.display = "block";
  setTimeout(() => $("toast").style.display = "none", 3500);
}

function setBusy(button, busy, label) {
  if (!button) return;
  if (busy) button.dataset.label = button.textContent;
  button.disabled = busy;
  button.textContent = busy ? label : (button.dataset.label || button.textContent);
}

function display(value, fallback = "Unknown") {
  return value ? esc(value) : `<span class="muted">${fallback}</span>`;
}

function renderDeviceRows(devices) {
  const body = $("device-rows");
  if (!devices.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No devices match this filter.</td></tr>';
    return;
  }
  body.innerHTML = devices.map((device) => `
    <tr>
      <td><b>${display(device.hostname, "Unknown device")}</b></td>
      <td class="mono">${esc(device.ip_address)}</td>
      <td class="mono">${display(device.mac_address, "Unavailable")}</td>
      <td>${display(device.vendor, "Unknown")}</td>
      <td><span class="status-pill ${esc(device.status)}">${esc(device.status)}</span></td>
      <td>${device.last_seen ? new Date(device.last_seen).toLocaleString() : "—"}</td>
      <td><a class="button" href="/devices/${device.id}">Details</a></td>
    </tr>`).join("");
}

async function refresh() {
  try {
    const summary = await api("/api/summary");
    $("total").textContent = summary.total;
    $("online").textContent = summary.online;
    $("offline").textContent = summary.offline;
    $("health").textContent = `${summary.health}%`;
    $("latency").textContent = `${summary.latency} ms`;
    $("open-ports-count").textContent = summary.total_open_ports;
    $("findings-count").textContent = summary.total_findings;
    const query = encodeURIComponent($("search").value);
    // Force showing only online devices in the inventory per UI preference
    const list = await api(`/api/devices?q=${query}&status=online`);
    renderDeviceRows(list);
    const findings = await api("/api/findings");
    $("finding-rows").innerHTML = findings.length ? findings.slice(0, 10).map((f) => `<tr><td><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></td><td>${esc(f.finding_type)}</td><td>${esc(f.title)}</td><td>${f.first_detected ? new Date(f.first_detected).toLocaleString() : "—"}</td></tr>`).join("") : '<tr><td colspan="4" class="empty">No findings</td></tr>';
    if (healthChart) {
      healthChart.data.datasets[0].data = [summary.online, summary.offline];
      healthChart.update();
    } else if (window.Chart) {
      healthChart = new Chart($("healthChart"), {type:"doughnut", data:{labels:["Online","Offline"],datasets:[{data:[summary.online,summary.offline],backgroundColor:["#43d9cb","#ff6e83"],borderWidth:0}]},options:{cutout:72,plugins:{legend:{position:'bottom',labels:{usePointStyle:true}}}}});
    }
    if (!latencyChart && window.Chart) {
      latencyChart = new Chart($("latencyChart"), {type:"bar", data:{labels:["Current average"],datasets:[{data:[summary.latency],backgroundColor:"#8eaeff",borderRadius:6,maxBarThickness:62}]},options:{scales:{y:{beginAtZero:true}},plugins:{legend:{display:false}}}});
    } else if (latencyChart) {
      latencyChart.data.datasets[0].data = [summary.latency];
      latencyChart.update();
    }
    $("updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    toast("Unable to load monitoring data");
  }
}

async function loadSettings() {
  const settings = await api("/api/settings");
  for (const key of ["network_range", "scan_interval", "ping_timeout", "refresh_rate"]) $(key).value = settings[key];
}

async function portScan(id) {
  if (!window.confirm("Confirm that you own or are authorized to test this device.")) return;
  toast("Starting authorized quick port scan…");
  try {
    const scan = await api(`/api/devices/${id}/port-scans`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scan_type:"quick",authorization_confirmed:true})});
    const poll = async () => {
      const result = await api(`/api/port-scans/${scan.id}`);
      if (["queued", "running", "cancelling"].includes(result.status)) {
        toast(`Port scan: ${result.scanned_ports}/${result.total_ports}`);
        window.setTimeout(poll, 750);
        return;
      }
      const open = result.ports.map((entry) => `${entry.port} ${entry.service}`).join(", ") || "No open ports found";
      toast(result.status === "completed" ? open : `Port scan ${result.status}`);
    };
    poll();
  } catch (_) { toast("Could not start port scan"); }
}

$("scan").onclick = async () => {
  const button = $("scan");
  setBusy(button, true, "Scanning…");
  toast("Scanning authorized local network…");
  try {
    const result = await api("/api/scan", {method:"POST"});
    toast(`Scan complete: ${result.found} responding device(s)`);
    refresh();
  } catch (error) { toast("Scan failed — see server logs for ARP/permission details"); }
  finally { setBusy(button, false); }
};
$("search").oninput = refresh;
$("status").onchange = refresh;
$("settings-form").onsubmit = async (event) => {
  event.preventDefault();
  const payload = {};
  for (const key of ["network_range", "scan_interval", "ping_timeout", "refresh_rate"]) payload[key] = Number.isNaN(Number($(key).value)) ? $(key).value : Number($(key).value);
  try { await api("/api/settings", {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); toast("Settings saved"); }
  catch (_) { toast("Invalid settings"); }
};

$("assessment-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setBusy(button, true, "Starting…");
  const payload = {target: $("target").value, scan_type: $("scan_type").value, timeout_seconds: Number($("scan_timeout").value), worker_count: Number($("scan_workers").value), authorization_confirmed: true};
  try {
    const result = await api("/api/assessments", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
    $("assessment-status").textContent = `Started ${result.scans.length} scan(s): ${result.scans.map((s) => s.id).join(", ")}.`;
    toast("Assessment started"); refresh();
  } catch (error) { $("assessment-status").textContent = "Could not start assessment: " + error.message; toast("Assessment request rejected"); }
  finally { setBusy(button, false); }
};

loadSettings().catch(() => toast("Unable to load settings"));
refresh();
setInterval(refresh, 30000);
