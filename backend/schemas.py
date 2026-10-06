from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, IPvAnyNetwork
class SettingsIn(BaseModel):
    scan_interval: int = Field(ge=10, le=86400)
    network_range: str
    refresh_rate: int = Field(ge=5, le=3600)
    ping_timeout: float = Field(ge=.1, le=10)
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
