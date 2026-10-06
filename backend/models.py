from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
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


class OpenPort(Base):
    __tablename__ = "open_ports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("port_scans.id"), index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str] = mapped_column(String(64), default="unknown")
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="open", index=True)
    scan = relationship("PortScan", back_populates="open_ports")
