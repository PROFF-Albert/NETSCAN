"""Authorized local-network discovery and monitoring helpers."""
from datetime import datetime
import ipaddress
import socket
from sqlalchemy import select
from sqlalchemy.orm import Session
from ping3 import ping
from ..models import Device, Scan, UptimeLog

COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}
OUI_VENDORS = {"00:1A:11": "Google", "00:17:88": "Philips", "00:1D:43": "Apple", "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox", "3C:5A:B4": "Google", "B8:27:EB": "Raspberry Pi"}


def vendor_for(mac: str | None) -> str | None:
    return OUI_VENDORS.get((mac or "").upper()[:8])


def safe_hostname(ip_address: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip_address)[0][:255]
    except (socket.herror, socket.gaierror, OSError):
        return None


def discover(network_range: str, db: Session) -> dict:
    """Send ARP only to the caller-authorized private range and persist replies."""
    network = ipaddress.ip_network(network_range, strict=False)
    if not isinstance(network, ipaddress.IPv4Network) or not network.is_private or network.num_addresses > 1024:
        raise ValueError("Discovery is limited to private networks with at most 1,024 addresses")
    try:
        from scapy.all import ARP, Ether, srp  # imported lazily; needs OS packet permission
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)), timeout=2, verbose=False)
    except PermissionError as exc:
        raise RuntimeError("ARP discovery needs packet-capture permission. Run with appropriate local privileges or use known-device monitoring.") from exc
    except OSError as exc:
        raise RuntimeError(f"Discovery could not start: {exc}") from exc
    now, found = datetime.utcnow(), []
    for _, reply in answered:
        ip_address, mac = reply.psrc, reply.hwsrc.upper()
        device = db.scalar(select(Device).where(Device.ip_address == ip_address))
        if device is None:
            device = Device(ip_address=ip_address, mac_address=mac, hostname=safe_hostname(ip_address), vendor=vendor_for(mac), status="online", first_seen=now, last_seen=now)
            db.add(device)
        else:
            device.mac_address, device.status, device.last_seen = mac, "online", now
            device.hostname = device.hostname or safe_hostname(ip_address)
            device.vendor = device.vendor or vendor_for(mac)
        db.flush()
        db.add(UptimeLog(device_id=device.id, timestamp=now, response_time=None, status="online"))
        found.append(ip_address)
    db.add(Scan(devices_found=len(found)))
    db.commit()
    return {"network_range": str(network), "devices_found": len(found), "devices": found}


def monitor_devices(db: Session, timeout: float) -> int:
    """Ping known devices once. This never performs subnet discovery."""
    now, count = datetime.utcnow(), 0
    for device in db.scalars(select(Device)).all():
        try:
            seconds = ping(device.ip_address, timeout=timeout, unit="s")
            online = seconds is not None
        except (OSError, PermissionError):
            seconds, online = None, False
        device.status = "online" if online else "offline"
        if online:
            device.last_seen = now
        db.add(UptimeLog(device_id=device.id, timestamp=now, response_time=(seconds * 1000 if seconds is not None else None), status=device.status))
        count += 1
    db.commit()
    return count


def scan_ports(ip_address: str) -> list[dict]:
    """A bounded TCP connect scan for ports explicitly listed in COMMON_PORTS."""
    results = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.75)
                state = "open" if sock.connect_ex((ip_address, port)) == 0 else "closed"
        except OSError:
            state = "filtered/error"
        if state == "open":
            results.append({"port": port, "service": service, "state": state})
    return results
