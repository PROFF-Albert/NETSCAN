from datetime import datetime
import csv
import io
import json
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..config import REPORTS_DIR
from ..models import Device, OpenPort, PortScan, UptimeLog


def rows_for_report(db: Session) -> list[dict]:
    rows = []
    for device in db.scalars(select(Device).order_by(Device.ip_address)).all():
        logs = db.scalars(select(UptimeLog).where(UptimeLog.device_id == device.id)).all()
        uptime = round(100 * sum(log.status == "online" for log in logs) / len(logs), 1) if logs else 0.0
        latest_scan = db.scalar(select(PortScan).where(PortScan.device_id == device.id).order_by(PortScan.timestamp.desc()))
        ports = ", ".join(str(item.port) for item in db.scalars(select(OpenPort).where(OpenPort.scan_id == latest_scan.id).order_by(OpenPort.port))) if latest_scan else ""
        rows.append({"hostname": device.hostname or "Unknown", "ip_address": device.ip_address, "mac_address": device.mac_address or "", "vendor": device.vendor or "Unknown", "status": device.status, "first_seen": device.first_seen.isoformat(), "last_seen": device.last_seen.isoformat() if device.last_seen else "", "uptime_percent": uptime, "open_ports": ports})
    return rows


def build_csv(db: Session) -> bytes:
    output = io.StringIO()
    rows = rows_for_report(db)
    writer = csv.DictWriter(output, fieldnames=["hostname", "ip_address", "mac_address", "vendor", "status", "first_seen", "last_seen", "uptime_percent", "open_ports"])
    writer.writeheader(); writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def build_pdf(db: Session) -> bytes:
    buffer = io.BytesIO(); page = canvas.Canvas(buffer, pagesize=letter)
    page.setTitle("NetWatch Network Report"); width, height = letter
    y = height - 48
    page.setFont("Helvetica-Bold", 18); page.drawString(42, y, "NetWatch Network Report"); y -= 24
    page.setFont("Helvetica", 9); page.drawString(42, y, f"Generated: {datetime.now().isoformat(timespec='seconds')}"); y -= 24
    for row in rows_for_report(db):
        if y < 60:
            page.showPage(); y = height - 48; page.setFont("Helvetica", 9)
        text = f"{row['ip_address']} | {row['hostname'][:25]} | {row['status']} | uptime {row['uptime_percent']}% | ports {row['open_ports'] or '-'}"
        page.drawString(42, y, text[:115]); y -= 15
    page.save(); return buffer.getvalue()


def archive_report(content: bytes, suffix: str) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"netwatch-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{suffix}"
    path.write_bytes(content)
    return path
