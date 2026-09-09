from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel


class ExpectedConfigSchema(BaseModel):
    attack_type: str
    detection: Optional[str] = None
    risk_level: Optional[str] = None
    alert: Optional[bool] = None
    incident: Optional[bool] = None
    response: Optional[str] = None


class ValidationRequestSchema(BaseModel):
    event_id: str
    expected: Optional[ExpectedConfigSchema] = None


class ValidationResponseSchema(BaseModel):
    validation_id: str
    event_id: str
    attack_type: str
    checks: Dict[str, bool]
    overall_result: str
    reasons: List[str]
    created_at: datetime


class ReplayTimelineEvent(BaseModel):
    stage: str
    timestamp: str
    status: str
    detail: Optional[str] = None
    rule: Optional[str] = None
    score: Optional[int] = None
    mode: Optional[str] = None
    validation_id: Optional[str] = None


class ReplayResponseSchema(BaseModel):
    validation_id: Optional[str] = None
    event_id: str
    timeline: List[ReplayTimelineEvent]

