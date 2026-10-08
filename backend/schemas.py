from datetime import datetime
from typing import Literal
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pydantic import BaseModel, Field, field_validator
class SettingsIn(BaseModel):
    scan_interval: int = Field(ge=10, le=86400)
    network_range: str
    refresh_rate: int = Field(ge=5, le=3600)
    ping_timeout: float = Field(ge=.1, le=10)

    @field_validator("network_range")
    @classmethod
    def authorized_network(cls, value: str) -> str:
        try:
            network = ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 network in CIDR notation") from exc
        if not isinstance(network, IPv4Network) or not network.is_private or network.num_addresses > 1024:
            raise ValueError("Network must be a private IPv4 CIDR with at most 1,024 addresses")
        return str(network)
class PortResult(BaseModel):
    port: int
    service: str
    state: str
class DeviceOut(BaseModel):
    id: int; hostname: str|None; ip_address: str; mac_address: str|None; vendor: str|None; status: str; first_seen: datetime; last_seen: datetime
    model_config = {"from_attributes": True}


class PortScanStart(BaseModel):
    scan_type: Literal["quick", "standard", "full"] = "quick"
    worker_count: int = Field(default=64, ge=1, le=256)
    timeout_seconds: float = Field(default=0.75, ge=0.1, le=3.0)
    authorization_confirmed: bool = False


# Compatibility request models for the optional router module. Keeping these
# here makes that module importable for applications that mount it separately.
class DiscoveryRequest(BaseModel):
    network_range: str | None = None


class PortScanRequest(BaseModel):
    ip_address: str
    permission_confirmed: bool = False

    @field_validator("ip_address")
    @classmethod
    def private_ipv4_address(cls, value: str) -> str:
        try:
            address = ip_address(value)
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 address") from exc
        if not isinstance(address, IPv4Address) or not (address.is_private or address.is_loopback):
            raise ValueError("Port scanning is limited to private or loopback IPv4 addresses")
        return str(address)


class SettingsUpdate(SettingsIn):
    pass
