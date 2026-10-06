import csv
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from .models import Device
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
