import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field

from BlueTeam.alerts.engine import Alert


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class IncidentStateTransitionError(ValueError):
    """Raised when an invalid status transition is attempted on an incident."""

    pass


class DuplicateIncidentError(ValueError):
    """Raised when attempting to create an incident for an alert that already has one."""

    pass


ALLOWED_TRANSITIONS: Dict[IncidentStatus, set] = {
    IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.RESOLVED},
    IncidentStatus.RESOLVED: set(),
}


class Incident(BaseModel):
    """
    Model representing a security incident generated from an Alert.
    """

    incident_id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:8]}")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id: str
    severity: str
    risk_score: int = Field(..., ge=0, le=100)
    attack_types: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    rule_names: List[str] = Field(default_factory=list)
    detection_count: int = 0
    reasons: List[str] = Field(default_factory=list)
    status: str = IncidentStatus.OPEN.value


class IncidentManager:
    """
    Blue Team Incident Manager.
    Handles incident creation from Alerts, state transitions, and in-memory incident tracking.
    """

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self._alert_to_incident: Dict[str, str] = {}

    def create_incident(self, alert: Optional[Alert]) -> Optional[Incident]:
        """
        Creates a new Incident from an Alert object.
        Returns None for SAFE alerts or invalid inputs.
        Raises DuplicateIncidentError if an incident already exists for the alert.
        """
        if alert is None:
            return None

        if alert.severity == "SAFE" or (
            alert.risk_score == 0 and not alert.attack_types
        ):
            return None

        if alert.alert_id in self._alert_to_incident:
            raise DuplicateIncidentError(
                f"Incident already exists for alert_id '{alert.alert_id}'"
            )

        now = datetime.now(timezone.utc)
        incident = Incident(
            created_at=now,
            updated_at=now,
            alert_id=alert.alert_id,
            severity=alert.severity,
            risk_score=alert.risk_score,
            attack_types=list(alert.attack_types),
            source_ips=list(alert.source_ips),
            rule_names=list(alert.rule_names),
            detection_count=alert.detection_count,
            reasons=list(alert.reasons),
            status=IncidentStatus.OPEN.value,
        )

        self._incidents[incident.incident_id] = incident
        self._alert_to_incident[alert.alert_id] = incident.incident_id
        return incident

    def update_status(
        self, incident_id: str, new_status: Union[str, IncidentStatus]
    ) -> Incident:
        """
        Updates the status of an incident following controlled state transitions.
        Updates updated_at while preserving created_at.
        Raises KeyError if incident_id is not found.
        Raises IncidentStateTransitionError if transition is disallowed.
        """
        if incident_id not in self._incidents:
            raise KeyError(f"Incident '{incident_id}' not found.")

        incident = self._incidents[incident_id]
        current_st = IncidentStatus(incident.status)
        target_st = IncidentStatus(new_status)

        if target_st == current_st:
            return incident

        if target_st not in ALLOWED_TRANSITIONS.get(current_st, set()):
            raise IncidentStateTransitionError(
                f"Invalid status transition from '{current_st.value}' to '{target_st.value}' for incident '{incident_id}'."
            )

        incident.status = target_st.value
        incident.updated_at = datetime.now(timezone.utc)
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve incident by incident_id."""
        return self._incidents.get(incident_id)

    def get_incident_by_alert_id(self, alert_id: str) -> Optional[Incident]:
        """Retrieve incident by originating alert_id."""
        inc_id = self._alert_to_incident.get(alert_id)
        if inc_id:
            return self._incidents.get(inc_id)
        return None

    def list_incidents(self) -> List[Incident]:
        """Returns all managed incidents."""
        return list(self._incidents.values())

