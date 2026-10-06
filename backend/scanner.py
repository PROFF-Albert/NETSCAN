import logging
import socket
import time
from datetime import datetime, timezone
from ipaddress import IPv4Network, ip_address, ip_network
from concurrent.futures import ThreadPoolExecutor
from ping3 import ping
import psutil

try:
    from mac_vendor_lookup import MacLookup
except ImportError:  # Allows a clear degradation before requirements are installed.
    MacLookup = None

log = logging.getLogger("netscan.discovery")
_vendor_lookup = None

COMMON_PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3389:"RDP"}


def vendor_for(mac_address: str | None) -> str | None:
    """Resolve an OUI vendor locally when the lookup database is available.

    Vendor resolution is best effort: randomized/private MAC addresses have no
    manufacturer OUI, and lookup failures must never discard a discovery.
    """
    global _vendor_lookup
    if not mac_address:
        return None
    if MacLookup is None:
        log.warning("Vendor lookup unavailable: install mac-vendor-lookup from requirements.txt")
        return None
    try:
        if _vendor_lookup is None:
            _vendor_lookup = MacLookup()
        return _vendor_lookup.lookup(mac_address)
    except Exception as exc:
        log.info("Vendor lookup unavailable for MAC %s: %s", mac_address, exc)
        return None

def default_local_network() -> str | None:
    """Return the first active private IPv4 subnet without sending traffic."""
    for interface, addresses in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(interface)
        if stats and not stats.isup:
            continue
        for address in addresses:
            if address.family == socket.AF_INET and address.netmask:
                candidate = ip_address(address.address)
                if candidate.is_private and not candidate.is_loopback:
                    return str(IPv4Network(f"{address.address}/{address.netmask}", strict=False))
    return None

def probe(ip: str, timeout: float):
    try:
        result = ping(ip, timeout=timeout, unit="ms")
        if result is not False and result is not None:
            return {"ip_address": ip, "hostname": _hostname(ip), "mac_address": None,
                    "vendor": None, "status":"online", "latency": round(float(result),2),
                    "last_seen":datetime.now(timezone.utc)}
    except Exception as exc:
        log.debug("ICMP probe failed for %s: %s", ip, exc)
    return {"ip_address": ip, "hostname": None, "mac_address": None, "vendor": None,
            "status":"offline", "latency": None, "last_seen":datetime.now(timezone.utc)}

def discover(cidr: str, timeout: float = 1.0):
    """Explicit ARP discovery, with a graceful ICMP-only fallback."""
    net = ip_network(cidr, strict=False)
    hosts = list(net.hosts())[:1024]
    if not net.is_private:
        raise ValueError("Discovery is limited to private IPv4 networks")
    try:
        from scapy.all import ARP, Ether, srp
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)), timeout=2, verbose=False)
        now = datetime.now(timezone.utc)
        arp_results = []
        for _, reply in answered:
            mac_address = reply.hwsrc.upper()
            hostname = _hostname(reply.psrc)
            vendor = vendor_for(mac_address)
            record = {"ip_address": reply.psrc, "mac_address": mac_address,
                      "hostname": hostname, "vendor": vendor, "status": "online",
                      "latency": None, "last_seen": now}
            arp_results.append(record)
            log.info("[DISCOVERED] IP: %s | MAC: %s | HOSTNAME: %s | VENDOR: %s",
                     record["ip_address"], mac_address, hostname or "Unknown", vendor or "Unknown")
        if arp_results:
            return arp_results
        log.info("ARP discovery received no replies on %s; trying ICMP fallback", net)
    except (ImportError, PermissionError, OSError) as exc:
        log.warning("ARP discovery unavailable on %s (%s). Falling back to ICMP; MAC and vendor may be unavailable.", net, exc)
    except Exception:
        log.exception("ARP discovery failed on %s. Falling back to ICMP; MAC and vendor may be unavailable.", net)
    with ThreadPoolExecutor(max_workers=min(64, max(1, len(hosts)))) as pool:
        results = [result for result in pool.map(lambda x: probe(str(x), timeout), hosts)
                   if result["status"] == "online"]
    for record in results:
        log.info("[DISCOVERED] IP: %s | MAC: Unknown | HOSTNAME: %s | VENDOR: Unknown (ICMP fallback)",
                 record["ip_address"], record["hostname"] or "Unknown")
    return results

def _hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError) as exc:
        log.debug("Reverse DNS unavailable for %s: %s", ip, exc)
        return None

def scan_ports(ip: str, ports=None, timeout=0.5):
    ports = ports or COMMON_PORTS
    def check(item):
        port, service = item
        sock = socket.socket(); sock.settimeout(timeout)
        try: state = "open" if sock.connect_ex((ip, port)) == 0 else "closed"
        except OSError: state = "filtered"
        finally: sock.close()
        return {"port":port, "service":service, "state":state}
    with ThreadPoolExecutor(max_workers=16) as pool: return list(pool.map(check, ports.items()))
