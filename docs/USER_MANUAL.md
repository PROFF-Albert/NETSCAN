# User Manual

## Dashboard

The five summary cards describe the persisted inventory and last monitoring results. “Network health” is the current online-device ratio. Charts appear after monitoring data exists. Use **Scan network** only for a network you are authorized to inspect.

## Devices

Search by hostname, IP, or vendor. Filter by status and sort by IP, hostname, or last seen. Click **Details** to see device metadata and its recorded activity.

## Port scanner

The device page offers a TCP connect check for ports 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, and 3389. It cannot be started until you tick the authorization confirmation. Closed/filtered ports are intentionally not listed as open services.

## Settings and reports

Settings are local to the SQLite database. The network range must be private and cannot exceed 1,024 addresses. Reports download immediately and are archived locally under `reports/`.

## Troubleshooting

- **No devices found:** verify the CIDR and local network, and check OS packet permissions. Guest Wi-Fi and client isolation commonly block ARP replies.
- **All devices show offline:** ICMP may be blocked by device firewalls; this is not proof that a device is disconnected.
- **Charts empty:** run a monitor cycle and allow a few history samples to accumulate.
- **Port scan errors:** use only a private/loopback IP and verify authorization; a timeout can mean filtering, not necessarily an unavailable host.
