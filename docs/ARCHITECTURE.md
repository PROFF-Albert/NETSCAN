# Architecture Guide

```text
Browser (HTML/CSS/JS + Chart.js)
            │ fetch /api/*
            ▼
FastAPI routes ── schemas / validation / rate-limit middleware
            │
            ├── discovery: authorized ARP, hostname/vendor lookup, ping monitor
            ├── scan worker: cancellable bounded TCP connect checks and safe banner/TLS observations
            ├── assessment rules: potential/confirmed/informational findings
            ├── NVD client: optional exact-CPE lookup with local CVE cache
            ├── reporting: CSV/JSON/PDF exports
            ▼
SQLAlchemy models ── SQLite (devices, scans, uptime_logs, settings, port_scans,
                              open_ports, vulnerability_findings, vulnerability_references)
```

`backend/main.py` owns application startup, static/template routing, rate limiting, and the background known-device monitor. `routes/api.py` keeps HTTP contracts separate from business logic. `services/network.py` contains all packet and socket operations. This separation makes it straightforward to replace SQLite with PostgreSQL, add authenticated users, or run monitoring in a task queue.

`backend/main.py` is the active application route surface. `backend/port_scanner.py` owns the background worker and never executes shell commands. `backend/vulnerabilities.py` records exposure observations separately from confirmed CVEs. A port, guessed service label, or raw banner never creates a CVE finding; NVD integration is reserved for trusted exact-CPE matching and stores only normalized CVE metadata.

`port_scans` is the durable job/history record and `open_ports` retains TCP state observations (the legacy table name is preserved for compatibility). Findings are deduplicated per device/rule fingerprint while retaining first/last detection timestamps and current scan linkage. Device availability remains append-only in `uptime_logs`.
