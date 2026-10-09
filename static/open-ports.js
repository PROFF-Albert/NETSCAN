const rows = document.getElementById('open-port-rows');
const search = document.getElementById('port-search');
const service = document.getElementById('service-search');
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

async function loadOpenPorts() {
  rows.innerHTML = '<tr><td colspan="7" class="empty">Loading saved port findings…</td></tr>';
  try {
    const params = new URLSearchParams({q: search.value, service: service.value});
    const response = await fetch(`/api/open-ports?${params}`);
    if (!response.ok) throw new Error('Could not load open ports');
    const ports = await response.json();
    if (!ports.length) {
      rows.innerHTML = '<tr><td colspan="7" class="empty">No open ports have been found yet. Run a port scan from a device on the dashboard.</td></tr>';
      return;
    }
    rows.innerHTML = ports.map((port) => `<tr>
      <td><b>${escapeHtml(port.hostname || 'Unknown device')}</b></td>
      <td class="mono">${escapeHtml(port.ip_address)}</td>
      <td class="mono"><span class="port-number">${port.port}</span></td>
      <td>${escapeHtml(port.protocol || 'tcp').toUpperCase()}</td>
      <td>${escapeHtml(port.service || 'unknown')}</td>
      <td>${port.scanned_at ? new Date(port.scanned_at).toLocaleString() : '—'}</td>
      <td><a class="scan-link" href="/api/port-scans/${port.scan_id}/export/json">#${port.scan_id} · ${escapeHtml(port.scan_type)}</a></td>
    </tr>`).join('');
  } catch (_) {
    rows.innerHTML = '<tr><td colspan="7" class="empty">Could not load saved port findings. Try refreshing the page.</td></tr>';
  }
}

let timer;
function queueLoad() { clearTimeout(timer); timer = setTimeout(loadOpenPorts, 220); }
search.addEventListener('input', queueLoad);
service.addEventListener('input', queueLoad);
document.getElementById('refresh-ports').addEventListener('click', loadOpenPorts);
loadOpenPorts();
