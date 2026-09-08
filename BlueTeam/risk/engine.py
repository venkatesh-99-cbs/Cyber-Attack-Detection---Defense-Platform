from typing import List
from pydantic import BaseModel, Field
from BlueTeam.detection.base_rule import DetectionResult
from BlueTeam.risk.classification import classify_score
from BlueTeam.risk.scoring import calculate_risk_score


class RiskResult(BaseModel):
    """
    Explainable result of risk analysis.
    """

    score: int = Field(..., ge=0, le=100)
    risk_level: str
    attack_types: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    rule_names: List[str] = Field(default_factory=list)
    detection_count: int = 0


class RiskEngine:
    """
    Risk Analysis Engine.
    Converts DetectionResult objects into a transparent, explainable project risk score and level.
    """

    def analyze(self, detections: List[DetectionResult]) -> RiskResult:
        """
        Analyze a list of DetectionResult objects and return a RiskResult.
        """
        if not detections:
            return RiskResult(
                score=0,
                risk_level=classify_score(0),
                attack_types=[],
                reasons=["No active attack detections"],
                source_ips=[],
                rule_names=[],
                detection_count=0,
            )

        score, attack_types, reasons = calculate_risk_score(detections)
        risk_level = classify_score(score)

        # Collect metadata for explainability
        source_ips = list(
            dict.fromkeys(d.source_ip for d in detections if d.source_ip)
        )
        rule_names = list(
            dict.fromkeys(d.rule_name for d in detections if d.rule_name)
        )

        return RiskResult(
            score=score,
            risk_level=risk_level,
            attack_types=attack_types,
            reasons=reasons,
            source_ips=source_ips,
            rule_names=rule_names,
            detection_count=len(detections),
        )

    def evaluate(self, detections: List[DetectionResult]) -> RiskResult:
        """Alias for analyze method."""
        return self.analyze(detections)

