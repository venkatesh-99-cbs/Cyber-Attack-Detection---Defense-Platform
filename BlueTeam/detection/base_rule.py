from abc import ABC, abstractmethod
from typing import Any, List
from pydantic import BaseModel, Field
from BlueTeam.api.schemas.event import SecurityEvent


class DetectionResult(BaseModel):
    """Explainable result of a security detection rule evaluation."""

    detected: bool = True
    attack_type: str
    source_ip: str
    rule_name: str
    severity: str = "medium"
    evidence: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)


class BaseRule(ABC):
    """Abstract base class for all Blue Team detection rules."""

    rule_name: str = "BaseRule"
    attack_type: str = "unknown"

    @abstractmethod
    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Evaluate a list of SecurityEvent objects and return detection results.
        """
        pass
