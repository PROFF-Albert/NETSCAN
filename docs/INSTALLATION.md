# Installation Guide

1. Install Python 3.13+ and `pip` using your operating system's package manager.
2. In `NETSCAN/`, create and activate a virtual environment.
3. Run `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env`. Defaults are safe for a local laptop.
5. Run `python run.py`, then browse to `http://127.0.0.1:8000`.

For an explicit database setup, run `alembic upgrade head` after installing requirements. For an older local database created before Alembic tracked revisions, preserve its records with `alembic stamp 20261005_0001` once, then run `alembic upgrade head`.

### Fedora

```bash
sudo dnf install python3 python3-pip
cd NETSCAN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Use `Ctrl-C` to stop the local server. Do not expose it publicly without adding authentication, TLS, and a production-grade persistent rate-limit store.

ARP discovery may require Linux packet-capture privileges (for example a narrowly granted capability under your local policy). The dashboard, TCP connect scanning, reporting, and normal operation do not require starting the web service as root. Configure `NETSCAN_NVD_API_KEY` only if you want higher NVD API limits; it is optional and must stay out of source control.

## Tests

```bash
source .venv/bin/activate
python -m pytest -q
```

The tests use SQLite fixtures and mocks/direct handler validation; they do not discover hosts or open real network connections.
