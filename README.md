# NETSCAN

NetWatch is a local-first network monitoring and device-discovery dashboard built with FastAPI, SQLAlchemy, SQLite, Scapy, Ping3, and Chart.js. It is designed as a computer-science portfolio project: it has a responsive cybersecurity-themed UI, a documented API, persistent history, migrations, reporting, and conservative network safeguards.

## Features

- Explicit ARP discovery of an authorized private network (maximum 1,024 addresses).
- Persistent device inventory: IP, MAC, hostname, locally recognized vendor, first/last seen, and status.
- Recurring monitoring of *known* devices using ICMP ping; response time, loss, and history are stored.
- Dashboard cards, availability, presence, latency, and new-device charts.
- Search, status filters, sorting, device detail and uptime history.
- Cancellable background TCP connect scans: Quick (100), Standard (1,000), and Full (1–65535), with bounded concurrency and progress.
- Evidence-led vulnerability findings for insecure exposure and safe TLS observations; confirmed CVEs require trusted matching data, never a guessed banner.
- Optional NVD 2.0 cache integration for exact trusted CPE queries; runs safely without an API key.
- CSV, JSON, and PDF assessment reports, archived under `reports/`.
- SQLite by default plus an Alembic initial migration.
- Input validation, structured errors, in-memory local rate limiting, environment configuration, and application logging.

## Safety and scope

Use only on networks and devices you own or have explicit permission to administer. Discovery is never automatic: use **Scan network**. Port scanning is limited to private/loopback IPs by default and requires confirmation; public IPs require a second explicit acknowledgement. NETSCAN neither attempts credential access nor exploits services.

## Installation and launch

Requires Python 3.13 or newer. From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                   # Windows PowerShell: Copy-Item .env.example .env
python run.py
```

Open `http://127.0.0.1:8000` in a browser. The default bind address deliberately permits local access only. Set `NETWATCH_HOST=0.0.0.0` in `.env` only when you understand the implications and have protected the host.

On Linux, raw ARP discovery may require packet-capture privileges. If discovery returns a permission error, grant the Python interpreter the minimum appropriate local capability or run the application according to your operating system's documented packet-capture policy. Do not run a web service as root just to scan.

## Quick user guide

1. Open **Settings** and set your own authorized private CIDR (for example `192.168.1.0/24`). Save it.
2. Go to **Dashboard** or **Devices** and click **Scan network**. This sends ARP requests in that CIDR and records responders.
3. Use **Monitor now**, or wait for the configured interval, to ping known devices. The monitor does not discover new addresses.
4. Select **Details** for a device to view availability history. For a port check, confirm that you have authorization, then scan the listed common TCP ports only.
5. Use **Reports** to export a CSV or PDF. Generated copies are stored in `reports/` and excluded from Git.

## Configuration

Copy `.env.example` to `.env`; no secrets are hardcoded.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETWATCH_DATABASE_URL` | `sqlite:///database/netwatch.db` | SQLAlchemy connection URL |
| `NETWATCH_HOST` | `127.0.0.1` | Bind interface |
| `NETWATCH_PORT` | `8000` | HTTP port |
| `NETWATCH_LOG_LEVEL` | `INFO` | Python log verbosity |
| `NETWATCH_RATE_LIMIT_PER_MINUTE` | `60` | Per-client request limit |

## Database and migrations

The application creates its SQLite schema on first launch for a simple local developer experience. The matching production migration is in `alembic/versions/`. To apply migrations explicitly:

```bash
source .venv/bin/activate
alembic upgrade head
```

If upgrading an existing development database created by an older release that used `create_all` and has no Alembic version, preserve it and stamp the initial revision once before upgrading:

```bash
alembic stamp 20261005_0001
alembic upgrade head
```

## Project layout

```text
netwatch/
├── backend/             FastAPI app, models, routes, schemas, services
├── templates/           Jinja pages
├── static/              responsive CSS and vanilla JavaScript
├── database/            SQLite database (runtime, gitignored)
├── scans/               reserved scan artifacts (gitignored)
├── reports/             generated report archive (gitignored)
├── alembic/             migration environment and initial schema revision
├── docs/                installation, architecture, and user guides
├── requirements.txt
└── run.py
```

See [Installation Guide](docs/INSTALLATION.md), [Architecture Guide](docs/ARCHITECTURE.md), and [User Manual](docs/USER_MANUAL.md) for fuller documentation.

## API overview

- `GET /api/dashboard` — aggregated metrics/chart data.
- `GET /api/devices` and `GET /api/devices/{id}` — device list/detail.
- `POST /api/discover` — explicit authorized ARP discovery.
- `POST /api/monitor` — one known-device monitoring cycle.
- `POST /api/ports` — authorized common-port check.
- `POST /api/assessments` — authorized target IP/CIDR assessment.
- `GET /api/findings` — persisted potential, confirmed, and informational findings.
- `POST /api/devices/{id}/nvd-cves` — optional exact-CPE NVD matching after a completed authorized scan.
- `GET /api/port-scans/{id}` and `POST /api/port-scans/{id}/cancel` — progress and cancellation.
- `GET /api/reports/csv` and `/api/reports/pdf` — report downloads.
- `GET/PUT /api/settings` — local configuration.

Interactive OpenAPI documentation is available at `/docs` while running.
