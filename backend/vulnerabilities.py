"""Evidence-led vulnerability assessment rules.

Rules intentionally report exposure as *potential* unless a trusted CVE record
matches an exact product CPE.  An open port or a banner alone is not a CVE.
"""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy.orm import Session

from .models import OpenPort, PortScan, VulnerabilityFinding


def utcnow():
    return datetime.now(timezone.utc)


EXPOSURE_RULES = {
    21: ("Unencrypted FTP service exposed", "Medium", "medium", "Use SFTP/FTPS or restrict FTP to an authorized management network."),
    23: ("Telnet service exposed", "High", "high", "Disable Telnet and use SSH with key-based authentication."),
    2375: ("Unauthenticated Docker API may be exposed", "High", "medium", "Bind Docker only to a protected socket or require mutually authenticated TLS."),
    3389: ("Remote Desktop service exposed", "Medium", "medium", "Restrict RDP by firewall/VPN and enforce MFA and current patching."),
    5900: ("VNC remote-access service exposed", "Medium", "medium", "Restrict VNC to a VPN and require strong authenticated encryption."),
    445: ("SMB service exposed", "Medium", "medium", "Restrict SMB to required subnets and keep the host patched."),
}


def _upsert(db: Session, scan: PortScan, port: OpenPort, *, fingerprint: str, title: str,
            severity: str, confidence: str, evidence: str, remediation: str,
            finding_type: str = "potential", description: str = "", cve_id: str | None = None,
            cvss_score: float | None = None, cvss_version: str | None = None,
            reference_url: str | None = None, source: str = "NETSCAN rules") -> None:
    finding = db.query(VulnerabilityFinding).filter_by(device_id=scan.device_id, fingerprint=fingerprint).first()
    values = dict(scan_id=scan.id, open_port_id=port.id, finding_type=finding_type, severity=severity,
                  confidence=confidence, title=title, cve_id=cve_id, cvss_score=cvss_score,
                  cvss_version=cvss_version, service=port.service, detected_version=port.service_version,
                  port=port.port, protocol=port.protocol, evidence=evidence, description=description,
                  remediation=remediation, reference_url=reference_url, source=source, last_detected=utcnow())
    if finding:
        for key, value in values.items():
            setattr(finding, key, value)
    else:
        db.add(VulnerabilityFinding(device_id=scan.device_id, fingerprint=fingerprint,
                                    first_detected=utcnow(), **values))


def assess_scan(db: Session, scan: PortScan) -> int:
    """Persist conservative configuration findings for a completed scan."""
    count = 0
    ports = db.query(OpenPort).filter_by(scan_id=scan.id, state="open").all()
    for port in ports:
        if port.port in EXPOSURE_RULES:
            title, severity, confidence, remediation = EXPOSURE_RULES[port.port]
            _upsert(db, scan, port, fingerprint=f"exposure:{port.protocol}:{port.port}", title=title,
                    severity=severity, confidence=confidence,
                    evidence=f"TCP connect succeeded on {port.port}/{port.protocol}; service label: {port.service}. "
                             "This is an exposure observation, not a confirmed CVE.",
                    remediation=remediation, description="The service is reachable and should be intentionally exposed and protected.")
            count += 1
        evidence = (port.evidence or "").lower()
        if port.port in {443, 4443, 8443, 9443} and evidence:
            if "tls tlsv1" in evidence or "tls tlsv1.1" in evidence:
                _upsert(db, scan, port, fingerprint=f"tls-obsolete:{port.port}", title="Obsolete TLS protocol negotiated",
                        severity="Medium", confidence="high", finding_type="confirmed",
                        evidence=port.evidence or "", description="The scanner negotiated an obsolete TLS version.",
                        remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or later.")
                count += 1
            else:
                _upsert(db, scan, port, fingerprint=f"tls-observed:{port.port}", title="TLS service observed",
                        severity="Informational", confidence="low", finding_type="informational",
                        evidence=port.evidence or "", description="A safe handshake recorded TLS metadata; this is not a complete TLS audit.",
                        remediation="Review certificate, protocol, cipher, and HTTP security settings with an authorized TLS configuration assessment.")
                count += 1
    db.commit()
    return count


def record_nvd_cves(db: Session, scan: PortScan, port: OpenPort, cves: list[dict], cpe_name: str) -> int:
    """Record CVEs only after a caller supplies an exact trusted CPE."""
    for cve in cves:
        cve_id = cve.get("id")
        if not cve_id:
            continue
        metrics = cve.get("metrics", {})
        metric = next(iter(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or metrics.get("cvssMetricV2", [])), {})
        data = metric.get("cvssData", {})
        score, vector = data.get("baseScore"), data.get("version")
        severity = data.get("baseSeverity") or ("Informational" if score is None else "Medium")
        severity = severity.title()
        description = next((item.get("value", "") for item in cve.get("descriptions", []) if item.get("lang") == "en"), "")
        _upsert(db, scan, port, fingerprint=f"cve:{port.protocol}:{port.port}:{cve_id}", title=cve_id,
                severity=severity, confidence="high", finding_type="confirmed", cve_id=cve_id,
                cvss_score=score, cvss_version=vector, evidence=f"NVD CPE match for operator-supplied exact CPE: {cpe_name}",
                description=description, remediation="Apply the vendor remediation or a supported fixed version after reviewing the NVD record.",
                reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", source="NVD")
    db.commit()
    return len(cves)
