import csv
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from .models import Device, PortScan

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports"
OUT.mkdir(exist_ok=True)


def csv_report(devices):
    path = OUT / "netwatch-devices.csv"
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP Address", "Hostname", "MAC", "Vendor", "Status", "First Seen", "Last Seen"])
        for d in devices:
            w.writerow([d.ip_address, d.hostname, d.mac_address, d.vendor, d.status, d.first_seen, d.last_seen])
    return path


def pdf_report(devices):
    path = OUT / "netwatch-report.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    y = 750
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "NetWatch Network Report")
    y -= 35
    c.setFont("Helvetica", 9)
    for d in devices:
        line = f"{d.ip_address} | {d.hostname or '-'} | {d.status} | {d.vendor or 'Unknown'}"
        c.drawString(50, y, line[:110])
        y -= 16
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    return path


def port_scan_pdf(scan: PortScan, ports: list) -> Path:
    """Generate a PDF report for a port scan result."""
    filename = f"netscan-port-scan-{scan.id}.pdf"
    path = OUT / filename
    c = canvas.Canvas(str(path), pagesize=letter)
    y = 750
    
    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "NETSCAN Port Scan Report")
    y -= 35
    
    # Scan details
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Scan Details")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Scan ID: {scan.id}")
    y -= 15
    c.drawString(50, y, f"Device IP: {scan.device_id}")
    y -= 15
    c.drawString(50, y, f"Scan Type: {scan.scan_type}")
    y -= 15
    c.drawString(50, y, f"Status: {scan.status}")
    y -= 15
    c.drawString(50, y, f"Timestamp: {scan.timestamp.isoformat() if scan.timestamp else 'N/A'}")
    y -= 15
    c.drawString(50, y, f"Total Ports Scanned: {scan.scanned_ports}/{scan.total_ports}")
    y -= 15
    c.drawString(50, y, f"Open Ports Found: {scan.open_ports_found}")
    y -= 35
    
    # Port results header
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Open Ports")
    y -= 20
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Port")
    c.drawString(120, y, "Protocol")
    c.drawString(200, y, "Service")
    c.drawString(300, y, "State")
    y -= 15
    
    # Port results
    c.setFont("Helvetica", 9)
    for port in ports:
        if y < 50:
            c.showPage()
            y = 750
        port_num = str(port.get("port", "N/A"))
        protocol = str(port.get("protocol", "tcp"))
        service = str(port.get("service", "unknown"))
        state = str(port.get("state", "unknown"))
        
        c.drawString(50, y, port_num)
        c.drawString(120, y, protocol)
        c.drawString(200, y, service[:30])
        c.drawString(300, y, state)
        y -= 15
    
    c.save()
    return path
