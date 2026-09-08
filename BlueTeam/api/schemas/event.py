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