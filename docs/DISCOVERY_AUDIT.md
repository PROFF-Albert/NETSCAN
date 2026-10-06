# NETSCAN Discovery Pipeline Audit

## Root cause

The active ARP path captured an IP address and MAC address, but did not resolve
or return a vendor. The scan route then never assigned `Device.vendor`.
The ICMP fallback intentionally cannot obtain a MAC address, yet it also lacked
the keys expected by the persistence path. Hostname resolution was only an
inline best-effort call with no discovery diagnostics. Finally, the dashboard
table did not include a Vendor column and had duplicate `id="devices"` values:
the browser selected the first one, so JavaScript could replace the inventory
container instead of the table body.

## Pipeline after the fix

1. **Network scan:** `backend/scanner.py:discover()` runs ARP broadcast through
   Scapy for the user-configured private CIDR. If raw ARP cannot be used, it
   emits a clear warning and falls back to ICMP responders without crashing.
2. **Enrichment:** each ARP response supplies an IP/MAC pair. `_hostname()`
   uses reverse DNS with safe fallback. `vendor_for()` uses
   `mac-vendor-lookup` and safely returns `None` when an OUI cannot be found.
3. **Logging:** each response produces a `[DISCOVERED]` structured log line;
   persistence produces a second log line with the saved values.
4. **Database insertion:** `backend/main.py:run_scan()` assigns hostname, MAC,
   vendor, status, and last-seen fields while preserving existing non-empty
   enrichment if a later lookup is unavailable. `Device` already maps each of
   these columns.
5. **API:** `device_payload()` explicitly returns hostname, IP, MAC, vendor,
   status, first seen, and last seen instead of depending on implicit ORM
   serialization.
6. **Frontend:** the inventory table uses a unique `device-rows` identifier and
   renders Device Name, IP Address, MAC Address, Vendor, Status, and Last Seen.

## Files modified

- `backend/scanner.py` — ARP enrichment, vendor lookup, fallbacks, logging.
- `backend/main.py` — explicit API serialization and complete persistence.
- `templates/index.html` — corrected table identifiers and Vendor column.
- `static/app.js` — corrected table rendering and safe empty-value display.
- `requirements.txt` — adds `mac-vendor-lookup`.

## Test procedure

1. Install the new dependency: `pip install -r requirements.txt`.
2. Restart NETSCAN and ensure its Settings network range matches the authorized
   local private subnet.
3. Click **Scan now** and inspect the server terminal for `[DISCOVERED]` lines.
4. Confirm the dashboard table includes MAC and Vendor columns.
5. Inspect SQLite, if desired:

   ```bash
   sqlite3 database/netscan.db 'SELECT ip_address, hostname, mac_address, vendor, status FROM devices;'
   ```

6. Visit `/api/devices` and confirm every returned record has the same fields.

An unknown hostname/vendor is a valid result: many devices have no reverse DNS,
and randomized MAC addresses intentionally have no globally attributable vendor.
