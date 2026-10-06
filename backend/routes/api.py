from datetime import datetime, timedelta
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Device, PortScan, Scan, Setting, UptimeLog
from ..schemas import DiscoveryRequest, PortScanRequest, SettingsUpdate
from ..services.network import discover, monitor_devices, scan_ports
from ..services.reporting import archive_report, build_csv, build_pdf

router = APIRouter(prefix="/api", tags=["api"])


def setting(db: Session) -> Setting:
    item = db.get(Setting, 1)
    if item is None:
        item = Setting(id=1); db.add(item); db.commit(); db.refresh(item)
    return item


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    devices = db.scalars(select(Device)).all(); total = len(devices); online = sum(d.status == "online" for d in devices)
    logs = db.scalars(select(UptimeLog).order_by(UptimeLog.timestamp.desc()).limit(500)).all()
    latency = [log.response_time for log in logs if log.response_time is not None]
    health = round(100 * online / total, 1) if total else 0
    day = datetime.utcnow() - timedelta(days=7)
    availability = {d.strftime("%a"): [] for d in [day + timedelta(days=i) for i in range(8)]}
    for log in logs:
        if log.timestamp >= day: availability.setdefault(log.timestamp.strftime("%a"), []).append(log.status == "online")
    return {"total": total, "online": online, "offline": total - online, "network_health": health, "average_latency": round(sum(latency) / len(latency), 1) if latency else 0,
            "availability": [{"label": key, "value": round(100 * sum(values) / len(values), 1) if values else 0} for key, values in availability.items()],
            "new_devices": [{"label": (day + timedelta(days=i)).strftime("%a"), "value": sum(d.first_seen.date() == (day + timedelta(days=i)).date() for d in devices)} for i in range(8)]}


@router.get("/devices")
def devices(query: str = "", status: str = "all", sort: str = "ip_address", db: Session = Depends(get_db)):
    allowed_sort = {"ip_address", "hostname", "last_seen"}
    if sort not in allowed_sort or status not in {"all", "online", "offline"}:
        raise HTTPException(422, "Invalid filter")
    items = db.scalars(select(Device)).all()
    q = query.lower().strip()
    if q: items = [d for d in items if q in (d.hostname or "").lower() or q in d.ip_address.lower() or q in (d.vendor or "").lower()]
    if status != "all": items = [d for d in items if d.status == status]
    items.sort(key=lambda d: (getattr(d, sort) is None, str(getattr(d, sort) or "")))
    return [{"id": d.id, "hostname": d.hostname or "Unknown", "ip_address": d.ip_address, "mac_address": d.mac_address or "Unknown", "vendor": d.vendor or "Unknown", "status": d.status, "first_seen": d.first_seen.isoformat(), "last_seen": d.last_seen.isoformat() if d.last_seen else None} for d in items]


@router.get("/devices/{device_id}")
def device_detail(device_id: int, db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if not device: raise HTTPException(404, "Device not found")
    logs = db.scalars(select(UptimeLog).where(UptimeLog.device_id == device_id).order_by(UptimeLog.timestamp.desc()).limit(200)).all()[::-1]
    uptime = round(100 * sum(x.status == "online" for x in logs) / len(logs), 1) if logs else 0
    return {"id": device.id, "hostname": device.hostname or "Unknown", "ip_address": device.ip_address, "mac_address": device.mac_address or "Unknown", "vendor": device.vendor or "Unknown", "status": device.status, "first_seen": device.first_seen.isoformat(), "last_seen": device.last_seen.isoformat() if device.last_seen else None, "uptime_percent": uptime,
            "history": [{"timestamp": x.timestamp.isoformat(), "response_time": x.response_time, "packet_loss": x.packet_loss, "status": x.status} for x in logs]}


@router.post("/discover")
async def start_discovery(payload: DiscoveryRequest, db: Session = Depends(get_db)):
    network_range = payload.network_range or setting(db).network_range
    try: return await asyncio.to_thread(discover, network_range, db)
    except (ValueError, RuntimeError) as exc: raise HTTPException(400, str(exc)) from exc


@router.post("/ports")
async def ports(payload: PortScanRequest, db: Session = Depends(get_db)):
    if not payload.permission_confirmed: raise HTTPException(400, "Confirm authorization before scanning ports")
    results = await asyncio.to_thread(scan_ports, payload.ip_address)
    device = db.scalar(select(Device).where(Device.ip_address == payload.ip_address))
    db.add(PortScan(device_id=device.id if device else None, ip_address=payload.ip_address, results_json=json.dumps(results))); db.commit()
    return {"ip_address": payload.ip_address, "results": results}


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    item = setting(db); return {"scan_interval": item.scan_interval, "ping_timeout": item.ping_timeout, "network_range": item.network_range, "refresh_rate": item.refresh_rate}


@router.put("/settings")
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    item = setting(db)
    for key, value in payload.model_dump().items(): setattr(item, key, value)
    db.commit(); return {"message": "Settings saved"}


@router.post("/monitor")
async def monitor(db: Session = Depends(get_db)):
    item = setting(db); count = await asyncio.to_thread(monitor_devices, db, item.ping_timeout)
    return {"monitored": count}


@router.get("/reports/{format}")
def report(format: str, db: Session = Depends(get_db)):
    if format == "csv": content, media, suffix = build_csv(db), "text/csv", "csv"
    elif format == "pdf": content, media, suffix = build_pdf(db), "application/pdf", "pdf"
    else: raise HTTPException(404, "Report format must be csv or pdf")
    path = archive_report(content, suffix)
    return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="{path.name}"'})
