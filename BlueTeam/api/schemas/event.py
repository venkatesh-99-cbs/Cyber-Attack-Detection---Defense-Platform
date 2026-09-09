from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityEvent(BaseModel):
    """
    Common security event format used between the Target
    and Blue Team backend.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1)
    timestamp: datetime
    source_ip: str
    target_ip: str
    event_type: str = Field(..., min_length=1)
    endpoint: str | None = None
    method: str | None = None
    status_code: int | None = None
    message: str = Field(..., min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityEventResponse(BaseModel):
    """
    Security event response model representing a persisted record from database.
    """

    id: int
    event_id: str
    timestamp: datetime
    source_ip: str
    target_ip: str
    event_type: str
    endpoint: str | None = None
    method: str | None = None
    status_code: int | None = None
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    received_at: datetime


class EventListResponse(BaseModel):
    """
    Paginated security event list container.
    """

    total: int
    limit: int
    offset: int
    events: list[SecurityEventResponse]


class TargetSecurityEvent(BaseModel):
    """
    Schema for security events forwarded by the Target application contract.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(..., min_length=1)
    timestamp: datetime
    source_ip: str
    target_ip: str
    source: str | None = "target"
    event_type: str = Field(..., min_length=1)
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    attack_type: str | None = None
    result: str | None = None
    severity: str | None = None
    reason: str | None = None