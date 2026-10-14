"""Mock-only safety and persistence tests; these never contact a network."""
from datetime import datetime, timezone
import asyncio
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base
from backend.main import start_port_scan
from backend.models import Device, OpenPort, PortScan, VulnerabilityFinding
from backend.port_scanner import ports_for, service_for
from backend.schemas import SettingsIn, TargetScanStart, PortScanStart
from backend.vulnerabilities import assess_scan

def session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fixture.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

def test_cidr_validation_rejects_public_and_broad_ranges():
    assert SettingsIn(scan_interval=60, refresh_rate=30, ping_timeout=1, network_range="10.1.2.0/24").network_range == "10.1.2.0/24"
    for value in ("8.8.8.0/24", "10.0.0.0/16"):
        try: SettingsIn(scan_interval=60, refresh_rate=30, ping_timeout=1, network_range=value)
        except ValueError: pass
        else: assert False, value
    assert TargetScanStart(target="192.168.1.10", authorization_confirmed=True).target == "192.168.1.10"

def test_profiles_and_service_identification():
    assert len(ports_for("quick")) == 100
    assert len(ports_for("standard")) == 1000
    assert len(ports_for("full")) == 65535
    assert service_for(23) == "Telnet"

def test_potential_exposure_is_persisted_without_cve(tmp_path):
    db = session(tmp_path); device = Device(ip_address="192.168.50.10", status="online")
    db.add(device); db.flush()
    scan = PortScan(device_id=device.id, scan_type="quick", status="completed", total_ports=100, scanned_ports=100, open_ports_found=1, timeout_seconds=.5, worker_count=4)
    db.add(scan); db.flush(); port = OpenPort(scan_id=scan.id, port=23, protocol="tcp", service="Telnet", state="open")
    db.add(port); db.commit()
    assert assess_scan(db, scan) == 1
    finding = db.query(VulnerabilityFinding).one()
    assert finding.finding_type == "potential" and finding.severity == "High" and finding.cve_id is None

def test_api_handler_rejects_unconfirmed_scan_without_network_work(tmp_path):
    db = session(tmp_path); device = Device(ip_address="192.168.50.10", status="online"); db.add(device); db.commit()
    try:
        asyncio.run(start_port_scan(device.id, PortScanStart(authorization_confirmed=False), db))
    except HTTPException as exc:
        assert exc.status_code == 400
    else: assert False, "unconfirmed scan was accepted"

def test_report_generation_includes_fixture_data(tmp_path, monkeypatch):
    import backend.reports as reports
    monkeypatch.setattr(reports, "OUT", tmp_path)
    now = datetime.now(timezone.utc); device = Device(ip_address="192.168.1.4", status="online", first_seen=now, last_seen=now)
    path = reports.json_report([device], [])
    assert path.exists() and "192.168.1.4" in path.read_text()
