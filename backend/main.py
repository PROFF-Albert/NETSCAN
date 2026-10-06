import asyncio
import csv
import io
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import create_access_token, verify_credentials, verify_token
from .database import Base, SessionLocal, engine, get_db
from .models import Device, OpenPort, PortScan, Scan, Setting, UptimeLog
from .port_scanner import cancel_scan, job_status, submit_scan
from .reports import csv_report, pdf_report, port_scan_pdf
from .schemas import LoginRequest, LoginResponse, PortScanStart, SettingsIn
from .scanner import default_local_network, discover, probe

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("netscan")
ROOT = Path(__file__).resolve().parents[1]

limiter = Limiter(key_func=get_remote_address)


def verify_bearer_token(authorization: str | None = Header(default=None)) -> str:
    """Verify JWT bearer token and return username."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "", 1).strip()
    username = verify_token(token)
    
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return username


def device_payload(device: Device) -> dict:
    """Stable, explicit API representation for the dashboard."""
    return {
        "id": device.id,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "vendor": device.vendor,
        "status": device.status,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
    }


def port_payload(port: OpenPort) -> dict:
    return {
        "id": port.id,
        "port": port.port,
        "protocol": port.protocol,
        "service": port.service,
        "banner": port.banner,
        "state": port.state,
    }


def scan_payload(scan: PortScan) -> dict:
    return {
        "id": scan.id,
        "device_id": scan.device_id,
        "scan_type": scan.scan_type,
        "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
        "status": scan.status,
        "total_ports": scan.total_ports,
        "scanned_ports": scan.scanned_ports,
        "open_ports_found": scan.open_ports_found,
        "timeout_seconds": scan.timeout_seconds,
        "worker_count": scan.worker_count,
        "error": scan.error,
    }


def persist_port_scan_progress(job, results, finalized: bool) -> None:
    """Persist worker progress in its own short-lived SQLAlchemy session."""
    db = SessionLocal()
    try:
        scan = db.get(PortScan, job.scan_id)
        if not scan:
            return
        snapshot = job.snapshot()
        scan.status = snapshot["status"]
        scan.scanned_ports = snapshot["scanned_ports"]
        scan.open_ports_found = snapshot["open_ports_found"]
        scan.error = snapshot["error"]
        for result in results or []:
            db.add(
                OpenPort(
                    scan_id=scan.id,
                    port=result["port"],
                    protocol=result["protocol"],
                    service=result["service"],
                    banner=result["banner"],
                    state=result["state"],
                )
            )
        db.commit()
    except Exception:
        db.rollback()
        log.exception("Could not persist port scan %s progress", job.scan_id)
    finally:
        db.close()


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.get(Setting, 1):
            db.add(Setting(id=1, network_range=default_local_network() or "192.168.1.0/24"))
        db.commit()
    finally:
        db.close()


async def background_monitor():
    while True:
        db = SessionLocal()
        try:
            setting = db.get(Setting, 1)
            timeout = setting.ping_timeout if setting else 1
            for d in db.query(Device).all():
                r = await asyncio.to_thread(probe, d.ip_address, timeout)
                d.hostname = r["hostname"] or d.hostname
                d.status = r["status"]
                if r["status"] == "online":
                    d.last_seen = r["last_seen"]
                db.add(UptimeLog(device_id=d.id, response_time=r["latency"], status=r["status"]))
            db.commit()
            wait = setting.scan_interval if setting else 60
        except Exception:
            log.exception("monitor cycle failed")
            wait = 60
        finally:
            db.close()
        await asyncio.sleep(wait)


@asynccontextmanager
async def lifespan(app):
    seed()
    task = asyncio.create_task(background_monitor())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="NETSCAN - Admin Only", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT / "templates" / "index.html").read_text().replace("NetWatch", "NETSCAN")


@app.get("/port-scans", response_class=HTMLResponse)
def port_scans_page():
    return (ROOT / "templates" / "port_scans.html").read_text().replace("NetWatch", "NETSCAN")


@app.post("/api/login")
@limiter.limit("5/minute")
def login(request: Request, credentials: LoginRequest) -> LoginResponse:
    """Admin login endpoint. Returns JWT token on successful authentication."""
    if not verify_credentials(credentials.username, credentials.password):
        log.warning("Failed login attempt for user: %s", credentials.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token, expires_in = create_access_token(credentials.username)
    log.info("User %s successfully logged in", credentials.username)
    return LoginResponse(access_token=token, expires_in=expires_in)


@app.get("/api/summary")
def summary(db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    total = db.query(Device).count()
    online = db.query(Device).filter_by(status="online").count()
    avg = (
        db.query(func.avg(UptimeLog.response_time))
        .filter(UptimeLog.status == "online", UptimeLog.response_time != None)
        .scalar()
    )
    health = round(online / total * 100) if total else 0
    return {"total": total, "online": online, "offline": max(total - online, 0), "health": health, "latency": round(avg or 0, 2)}


@app.get("/api/devices")
@limiter.limit("60/minute")
def devices(
    request: Request,
    q: str = Query(default="", min_length=0, max_length=100),
    status: str = Query(default=""),
    sort: str = Query(default="last_seen"),
    db: Session = Depends(get_db),
    _username: str = Depends(verify_bearer_token),
):
    query = db.query(Device)
    if q:
        query = query.filter((Device.ip_address.contains(q)) | (Device.hostname.contains(q)) | (Device.vendor.contains(q)))
    if status in ("online", "offline"):
        query = query.filter_by(status=status)
    col = {"ip": Device.ip_address, "hostname": Device.hostname, "last_seen": Device.last_seen}.get(sort, Device.last_seen)
    return [device_payload(device) for device in query.order_by(col.desc()).all()]


@app.get("/api/devices/{device_id}")
def device(request: Request, device_id: int, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    logs = db.query(UptimeLog).filter_by(device_id=device_id).order_by(UptimeLog.timestamp.desc()).limit(100).all()
    return {
        "device": device_payload(d),
        "logs": [{"timestamp": x.timestamp.isoformat(), "status": x.status, "response_time": x.response_time} for x in logs],
    }


@app.post("/api/scan")
@limiter.limit("5/minute")
async def run_scan(request: Request, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    s = db.get(Setting, 1)
    results = await asyncio.to_thread(discover, s.network_range, s.ping_timeout)
    for r in results:
        d = db.query(Device).filter_by(ip_address=r["ip_address"]).first() or Device(ip_address=r["ip_address"], first_seen=r["last_seen"])
        d.hostname = r.get("hostname") or d.hostname
        d.mac_address = r.get("mac_address") or d.mac_address
        d.vendor = r.get("vendor") or d.vendor
        d.status = r["status"]
        d.last_seen = r["last_seen"]
        db.add(d)
        db.flush()
        db.add(UptimeLog(device_id=d.id, response_time=r["latency"], status=r["status"]))
        log.info("Saved device %s: hostname=%s mac=%s vendor=%s", d.ip_address, d.hostname or "Unknown", d.mac_address or "Unknown", d.vendor or "Unknown")
    db.add(Scan(devices_found=sum(r["status"] == "online" for r in results)))
    db.commit()
    log.info("Network scan completed by admin: %s. Found %d devices", _username, sum(r["status"] == "online" for r in results))
    return {"found": sum(r["status"] == "online" for r in results)}


@app.post("/api/devices/{device_id}/port-scans")
@limiter.limit("10/minute")
async def start_port_scan(request: Request, device_id: int, payload: PortScanStart, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    if not payload.authorization_confirmed:
        raise HTTPException(400, "Confirm that you own or are authorized to test this device")
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    from .port_scanner import ports_for

    total = len(ports_for(payload.scan_type))
    scan = PortScan(
        device_id=d.id,
        scan_type=payload.scan_type,
        status="queued",
        total_ports=total,
        timeout_seconds=payload.timeout_seconds,
        worker_count=payload.worker_count,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    job = submit_scan(scan.id, d.ip_address, payload.scan_type, payload.worker_count, payload.timeout_seconds, persist_port_scan_progress)
    log.info("Admin %s authorized %s port scan %s started for device %s (%s)", _username, payload.scan_type, scan.id, d.ip_address, total)
    return {**scan_payload(scan), **job.snapshot()}


@app.get("/api/port-scans")
def list_port_scans(request: Request, device_id: int | None = None, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    query = db.query(PortScan)
    if device_id is not None:
        query = query.filter_by(device_id=device_id)
    return [scan_payload(scan) for scan in query.order_by(PortScan.timestamp.desc()).limit(100).all()]


@app.get("/api/port-scans/{scan_id}")
def port_scan_detail(
    request: Request,
    scan_id: int,
    open_only: bool = True,
    service: str = "",
    min_port: int = Query(default=1, ge=1, le=65535),
    max_port: int = Query(default=65535, ge=1, le=65535),
    db: Session = Depends(get_db),
    _username: str = Depends(verify_bearer_token),
):
    if min_port > max_port:
        raise HTTPException(422, "min_port must be less than or equal to max_port")
    scan = db.get(PortScan, scan_id)
    if not scan:
        raise HTTPException(404, "Port scan not found")
    query = db.query(OpenPort).filter(OpenPort.scan_id == scan_id, OpenPort.port.between(min_port, max_port))
    if open_only:
        query = query.filter(OpenPort.state == "open")
    if service:
        query = query.filter(OpenPort.service.ilike(f"%{service}%"))
    payload = scan_payload(scan)
    live = job_status(scan_id)
    if live:
        payload.update(live)
    payload["ports"] = [port_payload(port) for port in query.order_by(OpenPort.port).all()]
    return payload


@app.post("/api/port-scans/{scan_id}/cancel")
def cancel_port_scan(request: Request, scan_id: int, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    scan = db.get(PortScan, scan_id)
    if not scan:
        raise HTTPException(404, "Port scan not found")
    if not cancel_scan(scan_id):
        raise HTTPException(409, "Scan is not currently cancellable")
    scan.status = "cancelling"
    db.commit()
    log.info("Admin %s cancelled port scan %s", _username, scan_id)
    return {"scan_id": scan_id, "status": "cancelling"}


@app.get("/api/port-scans/{scan_id}/export/{format}")
def export_port_scan(request: Request, scan_id: int, format: str, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    scan = db.get(PortScan, scan_id)
    if not scan:
        raise HTTPException(404, "Port scan not found")
    ports = db.query(OpenPort).filter_by(scan_id=scan_id).order_by(OpenPort.port).all()
    rows = [port_payload(port) for port in ports]
    log.info("Admin %s exported port scan %s as %s", _username, scan_id, format)
    if format == "json":
        content = json.dumps({"scan": scan_payload(scan), "open_ports": rows}, indent=2).encode()
        return Response(content, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="netscan-port-scan-{scan_id}.json"'})
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["port", "protocol", "service", "banner", "state"])
        writer.writeheader()
        writer.writerows(rows)
        return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="netscan-port-scan-{scan_id}.csv"'})
    if format == "pdf":
        path = port_scan_pdf(scan, rows)
        return FileResponse(path, filename=path.name)
    raise HTTPException(404, "Supported formats are csv, json, and pdf")


@app.get("/api/settings")
def get_settings(request: Request, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    return db.get(Setting, 1)


@app.put("/api/settings")
def put_settings(request: Request, payload: SettingsIn, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    s = db.get(Setting, 1)
    s.scan_interval = payload.scan_interval
    s.network_range = payload.network_range
    s.refresh_rate = payload.refresh_rate
    s.ping_timeout = payload.ping_timeout
    db.commit()
    log.info("Admin %s updated settings", _username)
    return {"status": "updated", "network_range": s.network_range}


@app.get("/api/report/{kind}")
def report(request: Request, kind: str, db: Session = Depends(get_db), _username: str = Depends(verify_bearer_token)):
    if kind not in ("csv", "pdf"):
        raise HTTPException(400, "Unsupported report type")
    path = csv_report(db.query(Device).all()) if kind == "csv" else pdf_report(db.query(Device).all())
    log.info("Admin %s generated %s report", _username, kind)
    return FileResponse(path, filename=path.name)
