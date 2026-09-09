from datetime import datetime
from pydantic import BaseModel


class AlertResponse(BaseModel):
    alert_id: str
    event_id: str
    timestamp: datetime
    severity: str
    risk_score: int
    attack_types: list[str]
    source_ips: list[str]
    rule_names: list[str]
    detection_count: int
    reasons: list[str]
    status: str
    created_at: datetime


class AlertListResponse(BaseModel):
    """
    Response model for GET /alerts.
    """
    persisted: bool = True
    status: str = "OK"
    message: str = "Alerts are successfully persisted in the database."
    alerts: list[AlertResponse] | None = None


