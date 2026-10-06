# NetWatch - Secure Network Monitoring Dashboard

NetWatch is a **local-first, admin-only network monitoring and device-discovery dashboard** built with FastAPI, SQLAlchemy, SQLite, Scapy, Ping3, and Chart.js. It is designed as a portfolio project with enterprise-grade security features.

## 🔒 Security-First Design

This version includes:
- ✅ **Admin-Only Access** - All endpoints require authentication
- ✅ **JWT Token Authentication** - Secure session management
- ✅ **Rate Limiting** - Protection against brute force attacks
- ✅ **Input Validation** - CIDR and port scan validation
- ✅ **Private Networks Only** - Restricted to RFC1918 ranges
- ✅ **Audit Logging** - All admin actions logged
- ✅ **Local Binding by Default** - Localhost-only access
- ✅ **Environment-Based Secrets** - No hardcoded credentials

## Features

- Explicit ARP discovery of authorized private networks (maximum 1,024 addresses)
- Persistent device inventory: IP, MAC, hostname, locally recognized vendor, first/last seen, and status
- Recurring monitoring of *known* devices using ICMP ping; response time, loss, and history are stored
- Dashboard cards: availability, presence, latency, and new-device charts
- Search, status filters, sorting, device detail and uptime history
- Bounded common-port TCP connect scan, requiring authorization confirmation
- CSV and PDF exports, archived under `reports/`
- SQLite by default plus Alembic migration support
- **NEW:** Input validation, structured errors, in-memory local rate limiting, environment configuration, and application logging
- **NEW:** Admin authentication with JWT tokens
- **NEW:** Audit trail for all administrative actions

## Safety and Scope

**Use only on networks and devices you own or have explicit permission to administer.**

- Discovery is never automatic: use **Scan network**
- Port scanning is limited to private/loopback IPs and requires explicit authorization
- The app binds to `127.0.0.1` by default (localhost only)
- All actions are logged and require admin authentication
- Network ranges are validated to ensure they are private networks

## Installation and Launch

Requires Python 3.13 or newer. From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                   # Windows PowerShell: Copy-Item .env.example .env
python run.py
```

Open `http://127.0.0.1:8000` in a browser. The default bind address deliberately permits local access only.

## Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETSCAN_HOST` | `127.0.0.1` | Bind interface (localhost only by default) |
| `NETSCAN_PORT` | `8000` | HTTP port |
| `NETSCAN_USERNAME` | `admin` | Admin username for login |
| `NETSCAN_PASSWORD` | *(required)* | Strong admin password for login |
| `NETSCAN_SECRET_KEY` | *(required)* | JWT signing secret (generate a long random string) |
| `NETSCAN_API_TOKEN` | *(optional)* | Bearer token for API access (if using token auth) |
| `NETSCAN_DB_NAME` | `netscan.db` | Database file name |

## Security Setup

### Step 1: Generate Strong Credentials

```bash
# Generate random secrets
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Run this 2-3 times to get unique values for `NETSCAN_SECRET_KEY` and `NETSCAN_API_TOKEN`.

### Step 2: Create Your .env File

```env
NETSCAN_HOST=127.0.0.1
NETSCAN_PORT=8000
NETSCAN_USERNAME=admin
NETSCAN_PASSWORD=YourStrongPassword123!
NETSCAN_SECRET_KEY=your-generated-secret-key-here
NETSCAN_API_TOKEN=your-generated-api-token-here
NETSCAN_DB_NAME=netscan.db
```

**Important:** Never commit `.env` to Git. Add it to `.gitignore` (already done).

### Step 3: Start and Log In

```bash
python run.py
```

Visit `http://127.0.0.1:8000` and log in with your credentials.

## Quick User Guide

1. **Log In** - Enter your admin username and password on the login screen
2. **Open Settings** and set your authorized private CIDR (e.g., `192.168.1.0/24`). Save it.
3. Go to **Dashboard** or **Devices** and click **Scan network**. This sends ARP requests in that CIDR and records responders.
4. Use **Monitor now**, or wait for the configured interval, to ping known devices. The monitor does not discover new addresses.
5. Select **Details** for a device to view availability history. For a port check, confirm that you have authorization, then scan the listed common TCP ports only.
6. Use **Reports** to export a CSV or PDF. Generated copies are stored in `reports/` and excluded from Git.

## API Access

### Login to Get a Token

```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourPassword"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

### Use the Token

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:8000/api/devices
```

## Database and Migrations

The application creates its SQLite schema on first launch. To apply migrations explicitly:

```bash
source .venv/bin/activate
alembic upgrade head
```

## Project Layout

```text
netwatch/
├── backend/             FastAPI app, models, routes, schemas, services
│   ├── auth.py         Authentication and JWT token handling
│   ├── main.py         FastAPI application with admin-only routes
│   ├── database.py     SQLAlchemy database setup
│   ├── models.py       Database models
│   ├── schemas.py      Pydantic schemas and validation
│   ├── scanner.py      Network discovery and scanning logic
│   └── port_scanner.py Port scanning with job management
├── templates/           Jinja HTML pages
├── static/              Responsive CSS and vanilla JavaScript
├── database/            SQLite database (runtime, gitignored)
├── scans/               Reserved scan artifacts (gitignored)
├── reports/             Generated report archive (gitignored)
├── alembic/             Migration environment and versions
├── docs/                Documentation
├── SECURITY_AND_DEPLOYMENT.md  Comprehensive security guide
├── requirements.txt
├── .env.example         Environment variables template
├── .gitignore           Git exclusions (includes .env and database)
└── run.py               Entry point
```

See [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md) for full setup and security documentation.

## API Overview

All API endpoints require authentication via JWT bearer token.

**Authentication:**
- `POST /api/login` — Admin login (returns JWT token)

**Dashboard & Devices:**
- `GET /api/summary` — Aggregated metrics and chart data
- `GET /api/devices` — Device list with filtering and sorting
- `GET /api/devices/{id}` — Device detail and uptime history

**Scanning:**
- `POST /api/scan` — Explicit authorized ARP discovery
- `GET /api/port-scans` — List port scans
- `GET /api/port-scans/{scan_id}` — Port scan details
- `POST /api/devices/{device_id}/port-scans` — Start port scan
- `POST /api/port-scans/{scan_id}/cancel` — Cancel running scan
- `GET /api/port-scans/{scan_id}/export/{format}` — Export (json, csv, pdf)

**Settings & Reports:**
- `GET /api/settings` — Get current settings
- `PUT /api/settings` — Update settings (admin only)
- `GET /api/report/{kind}` — Generate reports (csv, pdf)

Interactive OpenAPI documentation available at `/docs` while running.

## Deploying to Other Networks

### Local Network Only (Recommended)

Update `.env`:
```env
NETSCAN_HOST=0.0.0.0
NETSCAN_PORT=8000
NETSCAN_USERNAME=admin
NETSCAN_PASSWORD=VeryStrongPassword!2026
NETSCAN_SECRET_KEY=your-long-random-secret
```

Access from another device on the same network:
```
http://<your-machine-ip>:8000
```

**Requirements:**
- Use a strong password (12+ characters, mixed case, numbers, symbols)
- Both machines on same private network
- Behind a firewall
- Admin login enforced

### VPN Access (More Secure)

1. Set up VPN (OpenVPN, Wireguard, etc.)
2. Keep `NETSCAN_HOST=127.0.0.1` or private IP
3. Access only through VPN tunnel

### Reverse Proxy with HTTPS (Production)

Use nginx or Caddy:

```nginx
server {
    listen 443 ssl;
    server_name netscan.local;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        # Restrict to trusted IPs
        allow 192.168.1.0/24;
        deny all;
    }
}
```

### SSH Tunnel (Remote Access)

```bash
ssh -L 8000:127.0.0.1:8000 user@remote-host
```

Then access: `http://127.0.0.1:8000`

## Security Checklist

Before exposing NETSCAN beyond localhost:

- [ ] Change default username and password
- [ ] Generate unique `NETSCAN_SECRET_KEY` (32+ random characters)
- [ ] Generate unique `NETSCAN_API_TOKEN` (32+ random characters)
- [ ] Never commit `.env` to Git
- [ ] Use HTTPS if exposing to untrusted networks
- [ ] Restrict access by firewall or reverse proxy
- [ ] Use VPN for remote access
- [ ] Keep `NETSCAN_HOST=127.0.0.1` unless you need LAN access
- [ ] Review audit logs regularly
- [ ] Use strong passwords (12+ chars, mixed case, numbers, symbols)
- [ ] Rotate credentials every 90 days if shared

## For Contributors and Forked Repos

If you fork this repo and want to share it with others:

1. **Document your setup** in a `DEPLOYMENT_NOTES.md` file
2. **Never include `.env`** - it's in `.gitignore` for a reason
3. **Guide users to generate their own credentials**
4. **Include security warnings** in your fork's README
5. **Keep the app updated** for security patches

Example for your fork:

```markdown
## Setup for Contributors

1. Clone and install (see Installation section)
2. Copy `.env.example` to `.env`
3. Generate strong credentials:
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
4. Update `.env` with unique values
5. Run: `python run.py`
6. Access: http://127.0.0.1:8000
```

## Troubleshooting

**"Unauthorized" on login:**
- Verify username and password in `.env`
- Check `NETSCAN_SECRET_KEY` is set
- Restart app after changing `.env`

**"Connection refused" from another device:**
- Verify `NETSCAN_HOST=0.0.0.0` in `.env`
- Check firewall allows port 8000
- Run `netstat -an | grep 8000` to verify listening

**Token expired:**
- Tokens expire after 24 hours
- Log in again to get a new token
- Adjust `TOKEN_EXPIRY_HOURS` in `backend/auth.py` if needed

**Database permission errors:**
- Check `database/` directory is writable
- Run: `chmod 755 database/`

## Audit Logging

All admin actions are logged:
- Login attempts (successful and failed)
- Network scans
- Port scans
- Configuration changes
- Report exports

View logs:
```bash
grep "Admin" netscan.log
```

## Requirements

- Python 3.13+
- FastAPI 0.115.0+
- SQLAlchemy 2.0.36+
- Pydantic 2.6.0+
- Scapy 2.6.1+
- Other dependencies in `requirements.txt`

## License

[See LICENSE file]

## Support

For issues, questions, or improvements:
1. Review [SECURITY_AND_DEPLOYMENT.md](SECURITY_AND_DEPLOYMENT.md)
2. Check application logs
3. Verify `.env` configuration
4. Open an issue on GitHub with details and logs

---

**Version:** 1.0.0 (Security Hardened)
**Last Updated:** 2026-10-06
**Status:** Production-Ready with Admin Authentication
