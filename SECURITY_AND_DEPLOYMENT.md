# NETSCAN Security Hardening & Admin Access Guide

## Overview

NETSCAN is a local-first network monitoring and device-discovery dashboard. This guide covers:
- How to set it up securely
- How to create admin credentials
- How to access it safely
- How to expose it to other networks without risk

## Quick Start (Local-Only, Recommended)

### 1. Clone and Install

```bash
git clone https://github.com/PROFF-Albert/NETSCAN.git
cd NETSCAN
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Create Your .env File

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` and set strong credentials:

```env
NETSCAN_HOST=127.0.0.1
NETSCAN_PORT=8000
NETSCAN_USERNAME=your_admin_username
NETSCAN_PASSWORD=YourStrongPassword123!
NETSCAN_SECRET_KEY=generate-a-long-random-string-here
NETSCAN_API_TOKEN=generate-another-long-random-string-here
NETSCAN_DB_NAME=netscan.db
```

### 3. Generate Strong Credentials

To generate random secrets, use Python:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Run this 2-3 times to get unique values for `NETSCAN_SECRET_KEY` and `NETSCAN_API_TOKEN`.

### 4. Start the App

```bash
python run.py
```

### 5. Access the Dashboard

Open your browser and go to:
```
http://127.0.0.1:8000
```

Log in with your credentials:
- Username: `your_admin_username`
- Password: `YourStrongPassword123!`

## Security Features Enabled

✅ **Admin-Only Access** - All API endpoints require login
✅ **JWT Authentication** - Secure token-based sessions
✅ **Rate Limiting** - Protects against brute force (5 login attempts/min)
✅ **Input Validation** - CIDR ranges and port scans are validated
✅ **Private Network Only** - Scans restricted to RFC1918 ranges
✅ **Audit Logging** - All admin actions logged
✅ **Local Binding by Default** - Only accessible from localhost
✅ **Environment Configuration** - No hardcoded secrets

## Default Recommendations

If you just want to test locally without custom credentials:

```env
NETSCAN_HOST=127.0.0.1
NETSCAN_PORT=8000
NETSCAN_USERNAME=admin
NETSCAN_PASSWORD=StrongAdmin!2026NetScan
NETSCAN_SECRET_KEY=a8e9138f6e9c4607b7c0d6f6d7a7860b2dd3c98f6d14e5a0b7a9a0d003b7f7c
NETSCAN_API_TOKEN=5d89d6d0d00e41d1b4461404186d87c5
NETSCAN_DB_NAME=netscan.db
```

⚠️ **Important:** Change these values before deploying to a shared or networked environment!

## API Access

If you need to call the API from scripts or other tools:

### 1. Get a Token

```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "StrongAdmin!2026NetScan"
  }'
```

You'll get a response like:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

### 2. Use the Token

Add the token to your requests:

```bash
curl -H "Authorization: Bearer <your-token>" \
  http://127.0.0.1:8000/api/devices
```

## Exposing NETSCAN to Other Networks

If you need access from other machines on your local network or beyond, follow these steps:

### Option 1: Local Network Only (Safest)

Change your `.env`:

```env
NETSCAN_HOST=0.0.0.0
NETSCAN_PORT=8000
NETSCAN_USERNAME=admin
NETSCAN_PASSWORD=VeryStrongPassword!2026
NETSCAN_SECRET_KEY=your-long-random-secret
```

Access from another machine:
```
http://<your-machine-ip>:8000
```

⚠️ **Requirements:**
- Both machines must be on the same private network
- Both must be behind a firewall
- Use a strong password (minimum 12 characters, mixed case + numbers + symbols)

### Option 2: VPN Access (More Secure)

1. Set up a VPN on your network (OpenVPN, Wireguard, etc.)
2. Keep `NETSCAN_HOST=127.0.0.1` or use a private IP
3. Only allow access through the VPN

Example:
```env
NETSCAN_HOST=192.168.1.100
NETSCAN_PORT=8000
NETSCAN_USERNAME=vpn_admin
NETSCAN_PASSWORD=VPNAdminPassword!2026
```

### Option 3: Reverse Proxy with HTTPS (Production)

Use nginx or Caddy to expose NETSCAN securely:

**Nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name netscan.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Authorization $http_authorization;
        
        # Restrict to specific IPs
        allow 192.168.1.0/24;
        allow 10.0.0.0/8;
        deny all;
    }
}
```

Set `.env`:
```env
NETSCAN_HOST=127.0.0.1
NETSCAN_PORT=8000
NETSCAN_USERNAME=admin
NETSCAN_PASSWORD=ReverseProxyAdminPassword!2026
```

### Option 4: SSH Tunnel (Remote Access)

```bash
ssh -L 8000:127.0.0.1:8000 user@remote-host
```

Then access:
```
http://127.0.0.1:8000
```

## Security Checklist

Before exposing NETSCAN to any network:

- [ ] Change default username and password
- [ ] Generate unique `NETSCAN_SECRET_KEY` (32+ characters)
- [ ] Generate unique `NETSCAN_API_TOKEN` (32+ characters)
- [ ] Set `NETSCAN_HOST=127.0.0.1` unless you need LAN access
- [ ] Use HTTPS if exposing to untrusted networks
- [ ] Restrict access by firewall or reverse proxy
- [ ] Use VPN for remote access
- [ ] Keep credentials out of Git (never commit .env)
- [ ] Review audit logs regularly
- [ ] Use strong passwords (12+ characters, mixed case, numbers, symbols)
- [ ] Rotate credentials every 90 days if shared with others
- [ ] Keep the NETSCAN_SECRET_KEY absolutely secret

## Firewall Rules

If allowing LAN access, configure your firewall:

**Allow from trusted subnet only:**
```bash
# Example: Allow from 192.168.1.0/24
sudo ufw allow from 192.168.1.0/24 to any port 8000
```

**Deny all others:**
```bash
sudo ufw deny 8000
```

## Audit Logs

NETSCAN logs all admin actions. Check logs for:
- Failed login attempts
- Successful scans
- Configuration changes
- Report exports

View logs:
```bash
grep "Admin" netscan.log
```

## Troubleshooting

### "Unauthorized" Error on Login

- Check username and password in `.env`
- Verify `NETSCAN_SECRET_KEY` is set
- Restart the app after changing `.env`

### "Connection refused" from Another Machine

- Check if `NETSCAN_HOST=0.0.0.0` in `.env`
- Verify firewall allows port 8000
- Confirm both machines are on same network
- Run `netstat -an | grep 8000` to verify listening

### Token Expired

- Tokens expire after 24 hours
- Log in again to get a new token
- Adjust `TOKEN_EXPIRY_HOURS` in `backend/auth.py` if needed

## Database

- SQLite database stored in `database/netscan.db`
- Automatically created on first run
- Keep this file secure if it contains sensitive network data
- Never commit to Git (in `.gitignore`)

## Deployment Best Practices

1. **Always use environment variables** for secrets
2. **Never commit `.env` to Git**
3. **Use HTTPS** for remote access
4. **Enable firewall rules** to restrict access
5. **Keep strong passwords** and rotate them
6. **Review audit logs** regularly
7. **Use VPN or reverse proxy** for external access
8. **Keep the app updated** for security patches

## For Contributors

If you're forking this repo and want to share with others:

1. Create a `SETUP_GUIDE.md` in your fork
2. Document custom credentials for your deployment
3. Never include `.env` in your commits
4. Use `.env.example` to show required variables
5. Document any additional security measures you've added

## Support & Issues

If you encounter issues:

1. Check logs: `tail -f netscan.log`
2. Verify `.env` configuration
3. Confirm port 8000 is available
4. Test API endpoint: `curl http://127.0.0.1:8000/`
5. Open an issue on GitHub with logs and error details

## License

See LICENSE file in the repository.

---

**Last Updated:** 2026-10-06
**Version:** 1.0.0 (Security Hardened)
