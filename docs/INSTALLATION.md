# Installation Guide

1. Install Python 3.13+ and `pip` using your operating system's package manager.
2. In `netwatch/`, create and activate a virtual environment.
3. Run `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env`. Defaults are safe for a local laptop.
5. Run `python run.py`, then browse to `http://127.0.0.1:8000`.

For an explicit database setup, run `alembic upgrade head` after installing requirements. NetWatch will also create its default local schema on first startup.

### Fedora

```bash
sudo dnf install python3 python3-pip
cd netwatch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Use `Ctrl-C` to stop the local server. Do not expose it publicly without adding authentication, TLS, and a production-grade persistent rate-limit store.
