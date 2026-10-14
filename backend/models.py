from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def now(): return datetime.now(timezone.utc)

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(32))
    vendor: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    logs = relationship("UptimeLog", back_populates="device", cascade="all, delete-orphan")
    port_scans = relationship("PortScan", back_populates="device", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", back_populates="device", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    devices_found: Mapped[int] = mapped_column(Integer, default=0)

class UptimeLog(Base):
    __tablename__ = "uptime_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    response_time: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16))
    device = relationship("Device", back_populates="logs")

class Setting(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    scan_interval: Mapped[int] = mapped_column(Integer, default=60)
    network_range: Mapped[str] = mapped_column(String(64), default="192.168.1.0/24")
    refresh_rate: Mapped[int] = mapped_column(Integer, default=30)
    ping_timeout: Mapped[float] = mapped_column(Float, default=1.0)


class PortScan(Base):
    __tablename__ = "port_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    scan_type: Mapped[str] = mapped_column(String(16), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    total_ports: Mapped[int] = mapped_column(Integer, nullable=False)
    scanned_ports: Mapped[int] = mapped_column(Integer, default=0)
    open_ports_found: Mapped[int] = mapped_column(Integer, default=0)
    timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    worker_count: Mapped[int] = mapped_column(Integer, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    device = relationship("Device", back_populates="port_scans")
    open_ports = relationship("OpenPort", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", foreign_keys="VulnerabilityFinding.scan_id")


class OpenPort(Base):
    __tablename__ = "open_ports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("port_scans.id"), index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str] = mapped_column(String(64), default="unknown")
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="open", index=True)
    scan = relationship("PortScan", back_populates="open_ports")
    findings = relationship("VulnerabilityFinding", back_populates="open_port")


class VulnerabilityFinding(Base):
    """A de-duplicated observation, not an assertion that exploitation occurred."""
    __tablename__ = "vulnerability_findings"
    __table_args__ = (UniqueConstraint("device_id", "fingerprint", name="uq_finding_device_fingerprint"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True, nullable=False)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("port_scans.id"), index=True)
    open_port_id: Mapped[int | None] = mapped_column(ForeignKey("open_ports.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(32), default="potential", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="Informational", index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(16))
    service: Mapped[str | None] = mapped_column(String(64))
    detected_version: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    evidence: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    reference_url: Mapped[str | None] = mapped_column(String(1024))
    source: Mapped[str] = mapped_column(String(64), default="NETSCAN rules")
    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    device = relationship("Device", back_populates="findings")
    open_port = relationship("OpenPort", back_populates="findings")


class VulnerabilityReference(Base):
    """Locally cached normalized NVD CVE data; no exploit content is stored."""
    __tablename__ = "vulnerability_references"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cpe_name: Mapped[str | None] = mapped_column(String(1024), index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="NVD")
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
