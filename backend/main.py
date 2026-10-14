import asyncio, csv, io, json, logging, threading, time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address, ip_address, ip_network
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import String, func
from sqlalchemy.orm import Session
from .database import Base, engine, get_db, SessionLocal
from .config import LOG_LEVEL, RATE_LIMIT_PER_MINUTE
from .models import Device, Scan, UptimeLog, Setting, PortScan, OpenPort, VulnerabilityFinding
from .schemas import PortScanRequest, SettingsIn, PortScanStart, TargetScanStart, NvdCpeRequest
from .scanner import default_local_network, discover, probe, scan_ports
from .reports import csv_report, pdf_report, json_report, port_scan_pdf
from .port_scanner import cancel_scan, job_status, submit_scan
from .vulnerabilities import assess_scan, record_nvd_cves
from .nvd import fetch_cves_for_cpe
from .config import MAX_SCAN_CONCURRENCY

logging.basicConfig(level=LOG_LEVEL); log=logging.getLogger('netscan')
ROOT=Path(__file__).resolve().parents[1]
request_times: dict[str, deque[float]] = defaultdict(deque)
request_times_lock = threading.Lock()


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
        "average_response_time": None,
    }


def port_payload(port: OpenPort) -> dict:
    return {"id": port.id, "port": port.port, "protocol": port.protocol,
            "service": port.service, "banner": port.banner, "service_version": port.service_version,
            "evidence": port.evidence, "state": port.state}


def finding_payload(finding: VulnerabilityFinding) -> dict:
    return {key: getattr(finding, key) for key in ("id", "finding_type", "severity", "confidence", "title", "cve_id", "cvss_score", "cvss_version", "service", "detected_version", "port", "protocol", "evidence", "description", "remediation", "reference_url", "source") } | {
        "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
        "last_detected": finding.last_detected.isoformat() if finding.last_detected else None,
    }


def scan_payload(scan: PortScan) -> dict:
    return {"id": scan.id, "device_id": scan.device_id, "scan_type": scan.scan_type,
            "timestamp": scan.timestamp.isoformat() if scan.timestamp else None, "status": scan.status,
            "total_ports": scan.total_ports, "scanned_ports": scan.scanned_ports,
            "open_ports_found": scan.open_ports_found, "timeout_seconds": scan.timeout_seconds,
            "worker_count": scan.worker_count, "error": scan.error}


def persist_port_scan_progress(job, results, finalized: bool) -> None:
    """Persist worker progress in its own short-lived SQLAlchemy session."""
    db = SessionLocal()
    try:
        scan = db.get(PortScan, job.scan_id)
        if not scan: return
        snapshot = job.snapshot()
        scan.status = snapshot["status"]
        scan.scanned_ports = snapshot["scanned_ports"]
        scan.open_ports_found = snapshot["open_ports_found"]
        scan.error = snapshot["error"]
        for result in results or []:
            db.add(OpenPort(scan_id=scan.id, port=result["port"], protocol=result["protocol"],
                            service=result["service"], banner=result["banner"],
                            service_version=result.get("service_version"), evidence=result.get("evidence"), state=result["state"]))
        db.commit()
        if finalized and scan.status == "completed":
            assess_scan(db, scan)
    except Exception:
        db.rollback(); log.exception("Could not persist port scan %s progress", job.scan_id)
    finally:
        db.close()

def seed():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    if not db.get(Setting,1):
        # Select an active private subnet when one is detectable; this sends no
        # packets and is used only when the user explicitly requests a scan.
        db.add(Setting(id=1, network_range=default_local_network() or '192.168.1.0/24'))
    db.commit(); db.close()
async def background_monitor():
    while True:
        db=SessionLocal()
        try:
            setting=db.get(Setting,1); timeout=setting.ping_timeout if setting else 1
            # Startup and periodic monitoring never discover a subnet. They only
            # check devices that were previously observed by an explicit scan.
            for d in db.query(Device).all():
                r=await asyncio.to_thread(probe,d.ip_address,timeout)
                d.hostname=r['hostname'] or d.hostname; d.status=r['status']
                if r['status']=='online': d.last_seen=r['last_seen']
                db.add(UptimeLog(device_id=d.id,response_time=r['latency'],status=r['status']))
            db.commit()
            wait=setting.scan_interval if setting else 60
        except Exception: log.exception('monitor cycle failed'); wait=60
        finally: db.close()
        await asyncio.sleep(wait)
@asynccontextmanager
async def lifespan(app):
    seed(); task=asyncio.create_task(background_monitor()); yield; task.cancel()
app=FastAPI(title='NETSCAN', version='1.0.0', lifespan=lifespan)
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')

@app.middleware('http')
async def local_rate_limit(request: Request, call_next):
    """Keep the documented local API limit without rate-limiting static files."""
    if request.url.path.startswith('/api/'):
        client = request.client.host if request.client else 'unknown'
        now = time.monotonic()
        with request_times_lock:
            timestamps = request_times[client]
            while timestamps and now - timestamps[0] >= 60:
                timestamps.popleft()
            if len(timestamps) >= RATE_LIMIT_PER_MINUTE:
                return JSONResponse({'detail': 'Rate limit exceeded'}, status_code=429, headers={'Retry-After': '60'})
            timestamps.append(now)
    return await call_next(request)
@app.get('/',response_class=HTMLResponse)
def home(): return (ROOT/'templates'/'index.html').read_text().replace('NetWatch', 'NETSCAN')
@app.get('/port-scans', response_class=HTMLResponse)
def port_scans_page():
    # A prior build linked here without supplying a template. Preserve old
    # bookmarks without turning them into a server error.
    return RedirectResponse(url='/', status_code=307)

@app.get('/open-ports', response_class=HTMLResponse)
def open_ports_page():
    """Saved open-port findings from authorized scans."""
    return (ROOT / 'templates' / 'open_ports.html').read_text()
@app.get('/devices/{device_id}', response_class=HTMLResponse)
def device_page(device_id: int):
    return (ROOT / 'templates' / 'device.html').read_text().replace('{{ device_id }}', str(device_id))
@app.get('/api/summary')
@app.get('/api/dashboard')
def summary(db:Session=Depends(get_db)):
    total=db.query(Device).count(); online=db.query(Device).filter_by(status='online').count()
    avg=db.query(func.avg(UptimeLog.response_time)).filter(UptimeLog.status=='online',UptimeLog.response_time!=None).scalar()
    health=round(online/total*100) if total else 0
    open_ports = db.query(OpenPort).filter_by(state="open").count()
    findings = db.query(VulnerabilityFinding)
    return {'total':total,'online':online,'offline':max(total-online,0),'health':health,'latency':round(avg or 0,2),
            'total_open_ports': open_ports, 'total_findings': findings.count(),
            'critical_high_findings': findings.filter(VulnerabilityFinding.severity.in_(["Critical", "High"])).count(),
            'recent_scans': [scan_payload(x) for x in db.query(PortScan).order_by(PortScan.timestamp.desc()).limit(5)],
            'recent_findings': [finding_payload(x) for x in findings.order_by(VulnerabilityFinding.last_detected.desc()).limit(5)]}
@app.get('/api/devices')
def devices(q:str='', status:str='', sort:str='last_seen', db:Session=Depends(get_db)):
    query=db.query(Device)
    if q: query=query.filter((Device.ip_address.contains(q)) | (Device.hostname.contains(q)) | (Device.vendor.contains(q)))
    if status in ('online','offline'): query=query.filter_by(status=status)
    col={'ip':Device.ip_address,'hostname':Device.hostname,'last_seen':Device.last_seen}.get(sort,Device.last_seen)
    return [device_payload(device) for device in query.order_by(col.desc()).all()]
@app.get('/api/devices/{device_id}')
def device(device_id:int,db:Session=Depends(get_db)):
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,'Device not found')
    logs=db.query(UptimeLog).filter_by(device_id=device_id).order_by(UptimeLog.timestamp.desc()).limit(100).all()
    scans = db.query(PortScan).filter_by(device_id=device_id).order_by(PortScan.timestamp.desc()).limit(25).all()
    findings = db.query(VulnerabilityFinding).filter_by(device_id=device_id).order_by(VulnerabilityFinding.last_detected.desc()).all()
    latest_ports = db.query(OpenPort).filter(OpenPort.scan_id == scans[0].id).all() if scans else []
    previous = {p.port for p in db.query(OpenPort).filter_by(scan_id=scans[1].id, state="open").all()} if len(scans) > 1 else set()
    return {'device': device_payload(d), 'logs':[{'timestamp':x.timestamp.isoformat(), 'status':x.status,'response_time':x.response_time} for x in logs],
            'ports': [port_payload(x) for x in latest_ports], 'findings': [finding_payload(x) for x in findings],
            'scans': [scan_payload(x) for x in scans], 'changes_since_previous': {"new_open_ports": [x.port for x in latest_ports if x.state == "open" and x.port not in previous]}}
@app.post('/api/scan')
@app.post('/api/discover')
async def run_scan(db:Session=Depends(get_db)):
    s=db.get(Setting,1)
    if not s: raise HTTPException(503, 'Settings are not initialized yet')
    try: results=await asyncio.to_thread(discover,s.network_range,s.ping_timeout)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    for r in results:
        d=db.query(Device).filter_by(ip_address=r['ip_address']).first() or Device(ip_address=r['ip_address'],first_seen=r['last_seen'])
        d.hostname=r.get('hostname') or d.hostname
        d.mac_address=r.get('mac_address') or d.mac_address
        d.vendor=r.get('vendor') or d.vendor
        d.status=r['status']; d.last_seen=r['last_seen']
        db.add(d); db.flush()
        db.add(UptimeLog(device_id=d.id,response_time=r['latency'],status=r['status']))
        log.info("Saved device %s: hostname=%s mac=%s vendor=%s", d.ip_address,
                 d.hostname or "Unknown", d.mac_address or "Unknown", d.vendor or "Unknown")
    db.add(Scan(devices_found=sum(r['status']=='online' for r in results))); db.commit(); return {'found':sum(r['status']=='online' for r in results)}
@app.post('/api/monitor')
async def monitor_now(db: Session = Depends(get_db)):
    """Monitor known devices once, without discovering additional hosts."""
    setting = db.get(Setting, 1)
    if not setting: raise HTTPException(503, 'Settings are not initialized yet')
    monitored = 0
    for device in db.query(Device).all():
        result = await asyncio.to_thread(probe, device.ip_address, setting.ping_timeout)
        device.hostname = result['hostname'] or device.hostname
        device.status = result['status']
        if result['status'] == 'online': device.last_seen = result['last_seen']
        db.add(UptimeLog(device_id=device.id, response_time=result['latency'], status=result['status']))
        monitored += 1
    db.commit()
    return {'monitored': monitored}
@app.post('/api/ports')
async def quick_ports(payload: PortScanRequest, db: Session = Depends(get_db)):
    """Compatibility endpoint for the documented bounded common-port check."""
    if not payload.permission_confirmed:
        raise HTTPException(400, 'Confirm authorization before scanning ports')
    results = await asyncio.to_thread(scan_ports, payload.ip_address)
    device = db.query(Device).filter_by(ip_address=payload.ip_address).first()
    if device:
        open_results = [result for result in results if result['state'] == 'open']
        scan = PortScan(device_id=device.id, scan_type='quick', status='completed', total_ports=len(results),
                        scanned_ports=len(results), open_ports_found=len(open_results), timeout_seconds=.5, worker_count=16)
        db.add(scan); db.flush()
        for result in open_results:
            db.add(OpenPort(scan_id=scan.id, port=result['port'], service=result['service'], state=result['state']))
        db.commit()
    return {'ip_address': payload.ip_address, 'results': results}
@app.post('/api/devices/{device_id}/port-scans')
async def start_port_scan(device_id: int, payload: PortScanStart, db: Session = Depends(get_db)):
    if not payload.authorization_confirmed:
        raise HTTPException(400, 'Confirm that you own or are authorized to test this device')
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,'Device not found')
    try: target = ip_address(d.ip_address)
    except ValueError: raise HTTPException(400, 'Device has an invalid IP address')
    if not isinstance(target, IPv4Address) or not (target.is_private or target.is_loopback):
        raise HTTPException(400, 'Port scanning is limited to private or loopback IPv4 devices')
    from .port_scanner import ports_for
    if payload.worker_count > MAX_SCAN_CONCURRENCY:
        raise HTTPException(422, f'Concurrency may not exceed configured cap of {MAX_SCAN_CONCURRENCY}')
    active = db.query(PortScan).filter_by(device_id=d.id).filter(PortScan.status.in_(["queued", "running", "cancelling"])).first()
    if active:
        raise HTTPException(409, f'A scan is already active for this device (scan {active.id})')
    total = len(ports_for(payload.scan_type))
    scan = PortScan(device_id=d.id, scan_type=payload.scan_type, status='queued', total_ports=total,
                    timeout_seconds=payload.timeout_seconds, worker_count=payload.worker_count)
    db.add(scan); db.commit(); db.refresh(scan)
    job = submit_scan(scan.id, d.ip_address, payload.scan_type, payload.worker_count,
                      payload.timeout_seconds, persist_port_scan_progress)
    log.info('Authorized %s port scan %s started for device %s (%s)', payload.scan_type, scan.id, d.ip_address, total)
    return {**scan_payload(scan), **job.snapshot()}


@app.post('/api/assessments')
async def start_target_assessment(payload: TargetScanStart, db: Session = Depends(get_db)):
    """Start one job per explicit target; public ranges demand extra confirmation."""
    if not payload.authorization_confirmed:
        raise HTTPException(400, 'Confirm that you own or are authorized to test every target')
    values = list(ip_network(payload.target).hosts()) if "/" in payload.target else [ip_address(payload.target)]
    if any(not (x.is_private or x.is_loopback) for x in values) and not payload.public_target_confirmed:
        raise HTTPException(400, 'Public targets require explicit public_target_confirmed acknowledgement')
    if payload.worker_count > MAX_SCAN_CONCURRENCY:
        raise HTTPException(422, f'Concurrency may not exceed configured cap of {MAX_SCAN_CONCURRENCY}')
    started = []
    for value in values:
        address = str(value)
        device = db.query(Device).filter_by(ip_address=address).first()
        if device is None:
            device = Device(ip_address=address, status='unknown')
            db.add(device); db.flush()
        if db.query(PortScan).filter_by(device_id=device.id).filter(PortScan.status.in_(["queued", "running", "cancelling"])).first():
            continue
        from .port_scanner import ports_for
        scan = PortScan(device_id=device.id, scan_type=payload.scan_type, status='queued', total_ports=len(ports_for(payload.scan_type)), timeout_seconds=payload.timeout_seconds, worker_count=payload.worker_count)
        db.add(scan); db.flush()
        submit_scan(scan.id, address, payload.scan_type, payload.worker_count, payload.timeout_seconds, persist_port_scan_progress)
        started.append(scan_payload(scan))
    db.commit()
    if not started: raise HTTPException(409, 'Every requested target already has an active scan')
    return {'scans': started, 'target': payload.target}

@app.get('/api/port-scans')
def list_port_scans(device_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(PortScan)
    if device_id is not None: query = query.filter_by(device_id=device_id)
    return [scan_payload(scan) for scan in query.order_by(PortScan.timestamp.desc()).limit(100).all()]

@app.get('/api/open-ports')
def list_open_ports(q: str = '', service: str = '', db: Session = Depends(get_db)):
    """List persisted open ports with the device and scan that found them."""
    query = (db.query(OpenPort, PortScan, Device)
             .join(PortScan, OpenPort.scan_id == PortScan.id)
             .join(Device, PortScan.device_id == Device.id)
             .filter(OpenPort.state == 'open'))
    if q:
        term = f'%{q.strip()}%'
        query = query.filter(
            (Device.ip_address.ilike(term)) |
            (Device.hostname.ilike(term)) |
            (OpenPort.port.cast(String).ilike(term))
        )
    if service:
        query = query.filter(OpenPort.service.ilike(f'%{service.strip()}%'))
    rows = query.order_by(PortScan.timestamp.desc(), OpenPort.port.asc()).limit(500).all()
    return [{
        **port_payload(port),
        'device_id': device.id,
        'ip_address': device.ip_address,
        'hostname': device.hostname,
        'scan_id': scan.id,
        'scan_type': scan.scan_type,
        'scanned_at': scan.timestamp.isoformat() if scan.timestamp else None,
    } for port, scan, device in rows]

@app.get('/api/findings')
def list_findings(severity: str = '', device_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(VulnerabilityFinding)
    if severity:
        if severity not in {"Critical", "High", "Medium", "Low", "Informational"}: raise HTTPException(422, 'Invalid severity')
        query = query.filter_by(severity=severity)
    if device_id is not None: query = query.filter_by(device_id=device_id)
    return [finding_payload(x) | {'device_id': x.device_id, 'scan_id': x.scan_id} for x in query.order_by(VulnerabilityFinding.last_detected.desc()).limit(500)]

@app.post('/api/devices/{device_id}/nvd-cves')
async def match_trusted_cpe(device_id: int, payload: NvdCpeRequest, db: Session = Depends(get_db)):
    """Optional NVD lookup; requires an exact CPE from a trusted inventory source."""
    scan = db.query(PortScan).filter_by(device_id=device_id, status='completed').order_by(PortScan.timestamp.desc()).first()
    if not scan: raise HTTPException(409, 'Run a completed authorized port scan before matching NVD data')
    port = db.query(OpenPort).filter_by(scan_id=scan.id, port=payload.port, state='open').first()
    if not port: raise HTTPException(404, 'The requested open port was not found in the latest completed scan')
    cves = await asyncio.to_thread(fetch_cves_for_cpe, db, payload.cpe_name)
    count = record_nvd_cves(db, scan, port, cves, payload.cpe_name)
    return {'source': 'NVD', 'cpe_name': payload.cpe_name, 'records_cached': count, 'last_updated': datetime.now(timezone.utc).isoformat()}

@app.get('/api/port-scans/{scan_id}')
def port_scan_detail(scan_id: int, open_only: bool = True, service: str = '', min_port: int = 1, max_port: int = 65535, db: Session = Depends(get_db)):
    if not (1 <= min_port <= max_port <= 65535): raise HTTPException(422, 'Invalid port range')
    scan = db.get(PortScan, scan_id)
    if not scan: raise HTTPException(404, 'Port scan not found')
    query = db.query(OpenPort).filter(OpenPort.scan_id == scan_id, OpenPort.port.between(min_port, max_port))
    if open_only: query = query.filter(OpenPort.state == 'open')
    if service: query = query.filter(OpenPort.service.ilike(f'%{service}%'))
    payload = scan_payload(scan)
    live = job_status(scan_id)
    if live: payload.update(live)
    payload['ports'] = [port_payload(port) for port in query.order_by(OpenPort.port).all()]
    return payload

@app.post('/api/port-scans/{scan_id}/cancel')
def cancel_port_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(PortScan, scan_id)
    if not scan: raise HTTPException(404, 'Port scan not found')
    if not cancel_scan(scan_id): raise HTTPException(409, 'Scan is not currently cancellable')
    scan.status = 'cancelling'; db.commit()
    return {'scan_id': scan_id, 'status': 'cancelling'}

@app.get('/api/port-scans/{scan_id}/export/{format}')
def export_port_scan(scan_id: int, format: str, db: Session = Depends(get_db)):
    scan = db.get(PortScan, scan_id)
    if not scan: raise HTTPException(404, 'Port scan not found')
    ports = db.query(OpenPort).filter_by(scan_id=scan_id).order_by(OpenPort.port).all()
    rows = [port_payload(port) for port in ports]
    if format == 'json':
        findings = db.query(VulnerabilityFinding).filter_by(scan_id=scan_id).all()
        content = json.dumps({'scan': scan_payload(scan), 'ports': rows, 'findings': [finding_payload(x) for x in findings], 'limitations': 'TCP connect scan; service labels and banners are observations, not proof of product identity.'}, indent=2).encode()
        return Response(content, media_type='application/json', headers={'Content-Disposition': f'attachment; filename="netscan-port-scan-{scan_id}.json"'})
    if format == 'csv':
        output = io.StringIO(); writer = csv.DictWriter(output, fieldnames=['port', 'protocol', 'service', 'banner', 'state']); writer.writeheader(); writer.writerows(rows)
        return Response(output.getvalue(), media_type='text/csv', headers={'Content-Disposition': f'attachment; filename="netscan-port-scan-{scan_id}.csv"'})
    if format == 'pdf':
        path = port_scan_pdf(scan, rows)
        return FileResponse(path, filename=path.name)
    raise HTTPException(404, 'Supported formats are csv, json, and pdf')
@app.get('/api/settings')
def get_settings(db:Session=Depends(get_db)): return db.get(Setting,1)
@app.put('/api/settings')
def put_settings(payload:SettingsIn,db:Session=Depends(get_db)):
    s=db.get(Setting,1); s.scan_interval=payload.scan_interval; s.network_range=payload.network_range; s.refresh_rate=payload.refresh_rate; s.ping_timeout=payload.ping_timeout; db.commit(); return s
@app.get('/api/report/{kind}')
@app.get('/api/reports/{kind}')
def report(kind:str,db:Session=Depends(get_db)):
    if kind not in ('csv','json','pdf'): raise HTTPException(400,'Unsupported report type')
    devices, findings = db.query(Device).all(), db.query(VulnerabilityFinding).order_by(VulnerabilityFinding.last_detected.desc()).all()
    path=csv_report(devices, findings) if kind=='csv' else json_report(devices, findings) if kind=='json' else pdf_report(devices, findings)
    return FileResponse(path,filename=path.name)
