let healthChart;
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));

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
      <td><button onclick="portScan(${device.id})" title="Scan common ports">Ports</button></td>
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
    const query = encodeURIComponent($("search").value);
    const list = await api(`/api/devices?q=${query}&status=${$("status").value}`);
    renderDeviceRows(list);
    if (healthChart) {
      healthChart.data.datasets[0].data = [summary.online, summary.offline];
      healthChart.update();
    } else if (window.Chart) {
      healthChart = new Chart($("healthChart"), {type:"doughnut", data:{labels:["Online","Offline"],datasets:[{data:[summary.online,summary.offline],backgroundColor:["#43d9cb","#ff6e83"],borderWidth:0}]},options:{plugins:{legend:{display:false}},cutout:"76%",maintainAspectRatio:false}});
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
  toast("Scanning common ports…");
  try {
    const result = await api(`/api/devices/${id}/ports`, {method:"POST"});
    const open = result.results.filter((entry) => entry.state === "open").map((entry) => `${entry.port} ${entry.service}`).join(", ") || "No open common ports";
    toast(`${result.ip}: ${open}`);
  } catch (_) { toast("Port scan failed"); }
}

$("scan").onclick = async () => {
  toast("Scanning authorized local network…");
  try {
    const result = await api("/api/scan", {method:"POST"});
    toast(`Scan complete: ${result.found} responding device(s)`);
    refresh();
  } catch (error) { toast("Scan failed — see server logs for ARP/permission details"); }
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

loadSettings().catch(() => toast("Unable to load settings"));
refresh();
setInterval(refresh, 30000);
