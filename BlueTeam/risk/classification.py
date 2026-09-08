from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"


def classify_score(score: int) -> str:
    """
    Classifies a numeric risk score (0-100) into a project risk level string:
    - 0 to 29: SAFE
    - 30 to 69: SUSPICIOUS
    - 70 to 100: HIGH RISK
    """
    if score < 30:
        return RiskLevel.SAFE.value
    elif score < 70:
        return RiskLevel.SUSPICIOUS.value
    else:
        return RiskLevel.HIGH_RISK.value

