# Architecture Guide

```text
Browser (HTML/CSS/JS + Chart.js)
            │ fetch /api/*
            ▼
FastAPI routes ── schemas / validation / rate-limit middleware
            │
            ├── network service: authorized ARP, ping monitor, bounded TCP checks
            ├── reporting service: CSV/PDF exports
            ▼
SQLAlchemy models ── SQLite (devices, scans, uptime_logs, settings, port_scans)
```

`backend/main.py` owns application startup, static/template routing, rate limiting, and the background known-device monitor. `routes/api.py` keeps HTTP contracts separate from business logic. `services/network.py` contains all packet and socket operations. This separation makes it straightforward to replace SQLite with PostgreSQL, add authenticated users, or run monitoring in a task queue.

The data model follows the requested core tables and adds `port_scans` for historical port-scan results. Device history is append-only `uptime_logs`; dashboard values are derived from those logs rather than duplicated.
