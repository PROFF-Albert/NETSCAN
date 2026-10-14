"""Small, defensive NVD 2.0 client with durable local caching.

Callers must provide an exact trusted CPE. This module never turns a guessed
banner/version into a CVE claim.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
import requests
from sqlalchemy.orm import Session
from .config import NVD_API_KEY, NVD_API_URL, NVD_TIMEOUT_SECONDS
from .models import VulnerabilityReference


def fetch_cves_for_cpe(db: Session, cpe_name: str) -> list[dict]:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        response = requests.get(NVD_API_URL, params={"cpeName": cpe_name}, headers=headers,
                                timeout=NVD_TIMEOUT_SECONDS)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
    except requests.RequestException:
        # A cache miss stays a miss; assessment remains useful offline.
        return []
    now = datetime.now(timezone.utc)
    records = []
    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        record = db.get(VulnerabilityReference, cve_id)
        payload = json.dumps(cve, separators=(",", ":"))
        if record:
            record.cpe_name, record.payload, record.last_updated, record.fetched_at = cpe_name, payload, now, now
        else:
            db.add(VulnerabilityReference(cve_id=cve_id, cpe_name=cpe_name, payload=payload, last_updated=now, fetched_at=now))
        records.append(cve)
    db.commit()
    return records
