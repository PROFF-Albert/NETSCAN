from datetime import datetime, timedelta
from typing import Literal
from ipaddress import ip_network
from pydantic import BaseModel, Field, field_validator


class SettingsIn(BaseModel):
    scan_interval: int = Field(ge=10, le=86400)
    network_range: str
    refresh_rate: int = Field(ge=5, le=3600)
    ping_timeout: float = Field(ge=0.1, le=10)

    @field_validator("network_range")
    @classmethod
    def validate_network_range(cls, value: str) -> str:
        try:
            net = ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid CIDR range") from exc
        if not net.is_private:
            raise ValueError("Only private IPv4/IPv6 ranges are allowed")
        if net.num_addresses > 1024:
            raise ValueError("CIDR range is too large for discovery")
        return str(net)


class PortResult(BaseModel):
    port: int
    service: str
    state: str


class DeviceOut(BaseModel):
    id: int
    hostname: str | None
    ip_address: str
    mac_address: str | None
    vendor: str | None
    status: str
    first_seen: datetime
    last_seen: datetime
    model_config = {"from_attributes": True}


class PortScanStart(BaseModel):
    scan_type: Literal["quick", "standard", "full"] = "quick"
    worker_count: int = Field(default=64, ge=1, le=256)
    timeout_seconds: float = Field(default=0.75, ge=0.1, le=3.0)
    authorization_confirmed: bool = False

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, value: str) -> str:
        if value not in {"quick", "standard", "full"}:
            raise ValueError("Unsupported scan type")
        return value


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=255)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
