"""Bounded, cancellable TCP connect scanning for authorized devices only."""
from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Iterable

log = logging.getLogger("netscan.portscan")

# A curated common-port set for a low-impact quick scan. Keep this list stable
# so scan results are reproducible and clearly explainable to the user.
QUICK_PORTS = (
    7, 9, 13, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 53, 67, 68, 69, 79,
    80, 81, 88, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 194, 199, 389, 427, 443, 444, 445, 465, 500, 512, 513, 514, 515,
    520, 548, 554, 587, 631, 636, 646, 873, 902, 989, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082,
    2375, 2376, 3000, 3128, 3306, 3389, 3478, 4000, 4443, 5000, 5060, 5432,
    5601, 5672, 5900, 5984, 6379, 6443, 6667, 7001, 7070, 8000, 8008, 8080,
    8081, 8443, 8888,
)
STANDARD_PORTS = tuple(range(1, 1001))
FULL_PORTS = tuple(range(1, 65536))

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2375: "Docker", 3000: "HTTP-alt", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def ports_for(scan_type: str) -> tuple[int, ...]:
    if scan_type == "quick": return QUICK_PORTS
    if scan_type == "standard": return STANDARD_PORTS
    if scan_type == "full": return FULL_PORTS
    raise ValueError("Unsupported scan type")


def service_for(port: int) -> str:
    if port in SERVICE_NAMES: return SERVICE_NAMES[port]
    try: return socket.getservbyport(port, "tcp")
    except OSError: return "unknown"


def banner_for(sock: socket.socket, timeout: float) -> str | None:
    """Read a small unsolicited service banner; do not authenticate or exploit."""
    try:
        sock.settimeout(min(timeout, 1.0))
        data = sock.recv(512)
        if not data: return None
        banner = data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ").strip()
        return banner[:512] or None
    except (socket.timeout, OSError):
        return None


def scan_one(ip_address: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip_address, port)) != 0: return None
            return {"port": port, "protocol": "tcp", "service": service_for(port),
                    "banner": banner_for(sock, timeout), "state": "open"}
    except OSError:
        return None


@dataclass
class ScanJob:
    scan_id: int
    ip_address: str
    total_ports: int
    status: str = "queued"
    scanned_ports: int = 0
    open_ports_found: int = 0
    started_at: float | None = None
    estimated_remaining_seconds: float | None = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict:
        with self.lock:
            return {"scan_id": self.scan_id, "status": self.status, "total_ports": self.total_ports,
                    "scanned_ports": self.scanned_ports, "open_ports_found": self.open_ports_found,
                    "percentage": round(100 * self.scanned_ports / self.total_ports, 1) if self.total_ports else 0,
                    "estimated_remaining_seconds": self.estimated_remaining_seconds, "error": self.error}


jobs: dict[int, ScanJob] = {}
jobs_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="netscan-job")


def submit_scan(scan_id: int, ip_address: str, scan_type: str, worker_count: int, timeout: float,
                persist_progress: Callable[[ScanJob, list[dict] | None, bool], None]) -> ScanJob:
    ports = ports_for(scan_type)
    job = ScanJob(scan_id=scan_id, ip_address=ip_address, total_ports=len(ports))
    with jobs_lock: jobs[scan_id] = job
    executor.submit(_run_scan, job, ports, worker_count, timeout, persist_progress)
    return job


def cancel_scan(scan_id: int) -> bool:
    with jobs_lock: job = jobs.get(scan_id)
    if not job or job.status not in {"queued", "running"}: return False
    job.cancel_event.set()
    with job.lock: job.status = "cancelling"
    log.info("Port scan %s cancellation requested", scan_id)
    return True


def job_status(scan_id: int) -> dict | None:
    with jobs_lock: job = jobs.get(scan_id)
    return job.snapshot() if job else None


def _run_scan(job: ScanJob, ports: Iterable[int], worker_count: int, timeout: float,
              persist_progress: Callable[[ScanJob, list[dict] | None, bool], None]) -> None:
    with job.lock:
        job.status, job.started_at = "running", time.monotonic()
    log.info("Port scan %s started against %s (%s ports, %s workers)", job.scan_id, job.ip_address, job.total_ports, worker_count)
    persist_progress(job, None, False)
    iterator, pending, new_results, last_persist = iter(ports), set(), [], 0.0
    max_pending = max(worker_count * 4, 4)
    try:
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix=f"scan-{job.scan_id}") as pool:
            def queue_next() -> bool:
                if job.cancel_event.is_set(): return False
                try: port = next(iterator)
                except StopIteration: return False
                pending.add(pool.submit(scan_one, job.ip_address, port, timeout)); return True
            while len(pending) < max_pending and queue_next(): pass
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    result = future.result()
                    with job.lock:
                        job.scanned_ports += 1
                        if result:
                            job.open_ports_found += 1; new_results.append(result)
                    if result: log.info("Port scan %s found %s/tcp (%s)", job.scan_id, result["port"], result["service"])
                while len(pending) < max_pending and queue_next(): pass
                elapsed = max(time.monotonic() - (job.started_at or time.monotonic()), 0.001)
                with job.lock:
                    rate = job.scanned_ports / elapsed
                    job.estimated_remaining_seconds = round((job.total_ports - job.scanned_ports) / rate, 1) if rate else None
                if time.monotonic() - last_persist >= 1 or new_results:
                    persist_progress(job, new_results or None, False); new_results = []; last_persist = time.monotonic()
        with job.lock:
            job.status = "cancelled" if job.cancel_event.is_set() else "completed"
            job.estimated_remaining_seconds = 0
        persist_progress(job, new_results or None, True)
        log.info("Port scan %s %s: %s/%s ports, %s open", job.scan_id, job.status, job.scanned_ports, job.total_ports, job.open_ports_found)
    except Exception as exc:
        log.exception("Port scan %s failed", job.scan_id)
        with job.lock: job.status, job.error = "failed", str(exc)[:500]
        persist_progress(job, new_results or None, True)
