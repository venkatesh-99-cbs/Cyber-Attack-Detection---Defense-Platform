from datetime import datetime
from pydantic import BaseModel


class IncidentResponse(BaseModel):
    incident_id: str
    alert_id: str
    event_id: str
    created_at: datetime
    updated_at: datetime
    severity: str
    risk_score: int
    attack_types: list[str]
    source_ips: list[str]
    rule_names: list[str]
    detection_count: int
    reasons: list[str]
    status: str


class IncidentListResponse(BaseModel):
    """
    Response model for GET /incidents.
    """
    persisted: bool = True
    status: str = "OK"
    message: str = "Incidents are successfully persisted in the database."
    incidents: list[IncidentResponse] | None = None


