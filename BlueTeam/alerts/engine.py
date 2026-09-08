import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from BlueTeam.detection.base_rule import DetectionResult
from BlueTeam.risk.engine import RiskResult


class AlertStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"


class Alert(BaseModel):
    """
    Actionable security alert model generated from RiskResult and DetectionResult inputs.
    """

    alert_id: str = Field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:8]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str
    risk_score: int = Field(..., ge=0, le=100)
    attack_types: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    rule_names: List[str] = Field(default_factory=list)
    detection_count: int = 0
    reasons: List[str] = Field(default_factory=list)
    status: str = AlertStatus.ACTIVE.value


class AlertEngine:
    """
    Blue Team Alert Engine.
    Consumes RiskResult and optional DetectionResult objects to produce explainable Alert objects.
    Does not perform detection or risk scoring.
    """

    def create_alert(
        self,
        risk_result: Optional[RiskResult],
        detections: Optional[List[DetectionResult]] = None,
    ) -> Optional[Alert]:
        """
        Generates an Alert object from a RiskResult and optional DetectionResults.
        Returns None for SAFE risk levels or 0-score results with no attack detections.
        """
        if risk_result is None:
            return None

        # Do not generate security alert for SAFE / 0-score results without attack detections
        if risk_result.risk_level == "SAFE" or (
            risk_result.score == 0 and not risk_result.attack_types
        ):
            return None

        source_ips = list(risk_result.source_ips)
        rule_names = list(risk_result.rule_names)
        detection_count = risk_result.detection_count

        if detections:
            if not source_ips:
                source_ips = list(
                    dict.fromkeys(d.source_ip for d in detections if d.source_ip)
                )
            if not rule_names:
                rule_names = list(
                    dict.fromkeys(d.rule_name for d in detections if d.rule_name)
                )
            if detection_count == 0:
                detection_count = len(detections)

        reasons = list(risk_result.reasons)
        if detections:
            for d in detections:
                for ev in d.evidence:
                    if ev not in reasons:
                        reasons.append(ev)

        return Alert(
            severity=risk_result.risk_level,
            risk_score=risk_result.score,
            attack_types=list(risk_result.attack_types),
            source_ips=source_ips,
            rule_names=rule_names,
            detection_count=detection_count,
            reasons=reasons,
            status=AlertStatus.ACTIVE.value,
        )

    def generate_alert(
        self,
        risk_result: Optional[RiskResult],
        detections: Optional[List[DetectionResult]] = None,
    ) -> Optional[Alert]:
        """Alias for create_alert."""
        return self.create_alert(risk_result, detections)

