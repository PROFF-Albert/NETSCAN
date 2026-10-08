import csv
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from .models import Device, PortScan
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'reports'; OUT.mkdir(exist_ok=True)
def csv_report(devices):
    path=OUT/'netwatch-devices.csv'
    with path.open('w', newline='') as f:
        w=csv.writer(f); w.writerow(['IP Address','Hostname','MAC','Vendor','Status','First Seen','Last Seen'])
        for d in devices: w.writerow([d.ip_address,d.hostname,d.mac_address,d.vendor,d.status,d.first_seen,d.last_seen])
    return path
def pdf_report(devices):
    path=OUT/'netwatch-report.pdf'; c=canvas.Canvas(str(path), pagesize=letter); y=750
    c.setFont('Helvetica-Bold',16); c.drawString(50,y,'NetWatch Network Report'); y-=35; c.setFont('Helvetica',9)
    for d in devices:
        line=f'{d.ip_address} | {d.hostname or "-"} | {d.status} | {d.vendor or "Unknown"}'
        c.drawString(50,y,line[:110]); y-=16
        if y<50: c.showPage(); y=750
    c.save(); return path


def port_scan_pdf(scan: PortScan, ports: list[dict]):
    """Create a compact, printable report for a persisted port scan."""
    path = OUT / f"netscan-port-scan-{scan.id}.pdf"
    report = canvas.Canvas(str(path), pagesize=letter)
    _, height = letter
    y = height - 48
    report.setTitle(f"NETSCAN port scan {scan.id}")
    report.setFont("Helvetica-Bold", 16)
    report.drawString(48, y, "NETSCAN Port Scan Report")
    y -= 24
    report.setFont("Helvetica", 9)
    report.drawString(48, y, f"Scan {scan.id} | {scan.scan_type} | status: {scan.status}")
    y -= 16
    report.drawString(48, y, f"Ports scanned: {scan.scanned_ports}/{scan.total_ports}; open: {scan.open_ports_found}")
    y -= 24
    for port in ports:
        if y < 54:
            report.showPage()
            y = height - 48
            report.setFont("Helvetica", 9)
        banner = (port.get("banner") or "").replace("\n", " ")
        line = f"{port['port']}/{port['protocol']}  {port['service']}  {port['state']}  {banner}"
        report.drawString(48, y, line[:120])
        y -= 14
    report.save()
    return path
