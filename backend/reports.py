import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from .models import Device, PortScan, VulnerabilityFinding

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports"
OUT.mkdir(exist_ok=True)


def csv_report(devices, findings=()):
    path = OUT / "netwatch-devices.csv"
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["record_type", "IP Address", "Hostname", "MAC", "Vendor", "Status", "First Seen", "Last Seen", "severity", "finding", "CVE", "evidence", "confidence", "remediation"])
        for device in devices:
            writer.writerow(["device", device.ip_address, device.hostname, device.mac_address, device.vendor, device.status, device.first_seen, device.last_seen, "", "", "", "", "", ""])
        for finding in findings:
            writer.writerow(["finding", "", "", "", "", "", finding.first_detected, finding.last_detected, finding.severity, finding.title, finding.cve_id or "", finding.evidence, finding.confidence, finding.remediation])
    return path


def pdf_report(devices, findings=()):
    path = OUT / "netwatch-report.pdf"
    report = canvas.Canvas(str(path), pagesize=letter)
    y = 750
    report.setFont("Helvetica-Bold", 16)
    report.drawString(50, y, "NETSCAN Vulnerability Assessment Report")
    y -= 35
    report.setFont("Helvetica", 9)
    report.drawString(50, y, f"Generated: {datetime.now(timezone.utc).isoformat()} | Scope: locally stored authorized scans")
    y -= 20
    for device in devices:
        line = f"{device.ip_address} | {device.hostname or '-'} | {device.status} | {device.vendor or 'Unknown'}"
        report.drawString(50, y, line[:110])
        y -= 16
        if y < 50:
            report.showPage()
            y = 750
            report.setFont("Helvetica", 9)
    y -= 10
    for finding in findings:
        if y < 70:
            report.showPage(); y = 750; report.setFont("Helvetica", 9)
        line = f"[{finding.severity}] {finding.title} | {finding.cve_id or finding.finding_type} | confidence {finding.confidence}"
        report.drawString(50, y, line[:110]); y -= 13
        report.drawString(60, y, (finding.remediation or "").replace("\n", " ")[:105]); y -= 16
    report.save()
    return path


def json_report(devices, findings=()):
    path = OUT / "netscan-assessment.json"
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "limitations": "TCP connect and safe banner/TLS observations only; findings are not exploit verification.",
               "devices": [{"ip_address": x.ip_address, "hostname": x.hostname, "status": x.status, "first_seen": x.first_seen.isoformat(), "last_seen": x.last_seen.isoformat() if x.last_seen else None} for x in devices],
               "findings": [{"severity": x.severity, "confidence": x.confidence, "finding_type": x.finding_type, "title": x.title, "cve_id": x.cve_id, "evidence": x.evidence, "remediation": x.remediation, "reference_url": x.reference_url} for x in findings]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def port_scan_pdf(scan: PortScan, ports: list[dict]) -> Path:
    """Generate a printable report for a persisted port scan."""
    path = OUT / f"netscan-port-scan-{scan.id}.pdf"
    report = canvas.Canvas(str(path), pagesize=letter)
    _, height = letter
    y = height - 48
    report.setTitle(f"NETSCAN port scan {scan.id}")
    report.setFont("Helvetica-Bold", 16)
    report.drawString(48, y, "NETSCAN Port Scan Report")
    y -= 28
    report.setFont("Helvetica", 10)
    report.drawString(48, y, f"Scan ID: {scan.id} | Type: {scan.scan_type} | Status: {scan.status}")
    y -= 16
    report.drawString(48, y, f"Ports scanned: {scan.scanned_ports}/{scan.total_ports}; open: {scan.open_ports_found}")
    y -= 26
    report.setFont("Helvetica-Bold", 9)
    report.drawString(48, y, "Port")
    report.drawString(105, y, "Protocol")
    report.drawString(175, y, "Service")
    report.drawString(300, y, "State")
    report.drawString(360, y, "Banner")
    y -= 14
    report.setFont("Helvetica", 9)
    for port in ports:
        if y < 54:
            report.showPage()
            y = height - 48
            report.setFont("Helvetica", 9)
        report.drawString(48, y, str(port.get("port", "N/A")))
        report.drawString(105, y, str(port.get("protocol", "tcp"))[:12])
        report.drawString(175, y, str(port.get("service", "unknown"))[:22])
        report.drawString(300, y, str(port.get("state", "unknown"))[:12])
        banner = str(port.get("banner") or "").replace("\n", " ").replace("\r", " ")
        report.drawString(360, y, banner[:38])
        y -= 14
    report.save()
    return path
