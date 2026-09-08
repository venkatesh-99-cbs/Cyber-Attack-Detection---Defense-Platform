import time
from datetime import datetime
import pytest
from BlueTeam.alerts.engine import Alert, AlertStatus
from BlueTeam.incidents.manager import (
    DuplicateIncidentError,
    Incident,
    IncidentManager,
    IncidentStateTransitionError,
    IncidentStatus,
)


def make_alert(
    severity: str = "HIGH RISK",
    risk_score: int = 100,
    attack_types: list = None,
    source_ips: list = None,
    rule_names: list = None,
    detection_count: int = 2,
    reasons: list = None,
    alert_id: str = None,
) -> Alert:
    if attack_types is None:
        attack_types = ["port_scan", "brute_force"]
    if source_ips is None:
        source_ips = ["192.168.1.50"]
    if rule_names is None:
        rule_names = ["PortScanRule", "BruteForceRule"]
    if reasons is None:
        reasons = [
            "Port scan detection contributed 40 risk points.",
            "Brute-force detection contributed 60 risk points.",
        ]
    kwargs = {
        "severity": severity,
        "risk_score": risk_score,
        "attack_types": attack_types,
        "source_ips": source_ips,
        "rule_names": rule_names,
        "detection_count": detection_count,
        "reasons": reasons,
        "status": AlertStatus.ACTIVE.value,
    }
    if alert_id:
        kwargs["alert_id"] = alert_id
    return Alert(**kwargs)


# =====================================================================
# 20 REQUIRED UNIT TESTS
# =====================================================================

def test_1_create_incident_from_high_risk_alert():
    mgr = IncidentManager()
    alert = make_alert(severity="HIGH RISK", risk_score=100)
    inc = mgr.create_incident(alert)
    assert inc is not None
    assert isinstance(inc, Incident)
    assert inc.severity == "HIGH RISK"


def test_2_create_incident_from_suspicious_alert():
    mgr = IncidentManager()
    alert = make_alert(severity="SUSPICIOUS", risk_score=60)
    inc = mgr.create_incident(alert)
    assert inc is not None
    assert inc.severity == "SUSPICIOUS"


def test_3_incident_receives_unique_incident_id():
    mgr = IncidentManager()
    alert1 = make_alert(alert_id="alert-001")
    alert2 = make_alert(alert_id="alert-002")
    inc1 = mgr.create_incident(alert1)
    inc2 = mgr.create_incident(alert2)
    assert inc1.incident_id is not None
    assert inc2.incident_id is not None
    assert inc1.incident_id != inc2.incident_id
    assert inc1.incident_id.startswith("inc-")


def test_4_incident_references_correct_alert_id():
    mgr = IncidentManager()
    alert = make_alert(alert_id="alert-xyz-999")
    inc = mgr.create_incident(alert)
    assert inc.alert_id == "alert-xyz-999"


def test_5_incident_preserves_risk_score():
    mgr = IncidentManager()
    alert = make_alert(risk_score=70)
    inc = mgr.create_incident(alert)
    assert inc.risk_score == 70


def test_6_incident_preserves_severity_risk_level():
    mgr = IncidentManager()
    alert = make_alert(severity="HIGH RISK")
    inc = mgr.create_incident(alert)
    assert inc.severity == "HIGH RISK"


def test_7_incident_preserves_attack_types():
    mgr = IncidentManager()
    alert = make_alert(attack_types=["sql_injection", "brute_force"])
    inc = mgr.create_incident(alert)
    assert inc.attack_types == ["sql_injection", "brute_force"]


def test_8_incident_preserves_source_ips():
    mgr = IncidentManager()
    alert = make_alert(source_ips=["10.0.0.5", "10.0.0.6"])
    inc = mgr.create_incident(alert)
    assert inc.source_ips == ["10.0.0.5", "10.0.0.6"]


def test_9_incident_preserves_rule_names():
    mgr = IncidentManager()
    alert = make_alert(rule_names=["SQLInjectionRule", "BruteForceRule"])
    inc = mgr.create_incident(alert)
    assert inc.rule_names == ["SQLInjectionRule", "BruteForceRule"]


def test_10_incident_preserves_detection_count():
    mgr = IncidentManager()
    alert = make_alert(detection_count=4)
    inc = mgr.create_incident(alert)
    assert inc.detection_count == 4


def test_11_incident_preserves_alert_reasons_evidence():
    mgr = IncidentManager()
    reasons = ["Port scan probed 5 ports.", "Brute force attempted 5 logins."]
    alert = make_alert(reasons=reasons)
    inc = mgr.create_incident(alert)
    assert inc.reasons == reasons


def test_12_new_incident_status_is_open():
    mgr = IncidentManager()
    alert = make_alert()
    inc = mgr.create_incident(alert)
    assert inc.status == "OPEN"
    assert inc.status == IncidentStatus.OPEN.value


def test_13_open_to_investigating_transition():
    mgr = IncidentManager()
    alert = make_alert()
    inc = mgr.create_incident(alert)
    updated_inc = mgr.update_status(inc.incident_id, IncidentStatus.INVESTIGATING)
    assert updated_inc.status == "INVESTIGATING"


def test_14_investigating_to_resolved_transition():
    mgr = IncidentManager()
    alert = make_alert()
    inc = mgr.create_incident(alert)
    mgr.update_status(inc.incident_id, IncidentStatus.INVESTIGATING)
    resolved_inc = mgr.update_status(inc.incident_id, IncidentStatus.RESOLVED)
    assert resolved_inc.status == "RESOLVED"


def test_15_invalid_transition_from_resolved_is_rejected():
    mgr = IncidentManager()
    alert = make_alert()
    inc = mgr.create_incident(alert)
    mgr.update_status(inc.incident_id, IncidentStatus.RESOLVED)
    with pytest.raises(IncidentStateTransitionError):
        mgr.update_status(inc.incident_id, IncidentStatus.OPEN)
    with pytest.raises(IncidentStateTransitionError):
        mgr.update_status(inc.incident_id, IncidentStatus.INVESTIGATING)
    # Incident status should remain RESOLVED
    assert mgr.get_incident(inc.incident_id).status == "RESOLVED"


def test_16_created_at_remains_unchanged_when_status_changes():
    mgr = IncidentManager()
    alert = make_alert()
    inc = mgr.create_incident(alert)
    initial_created_at = inc.created_at
    time.sleep(0.01)
    updated_inc = mgr.update_status(inc.incident_id, IncidentStatus.INVESTIGATING)
    assert updated_inc.created_at == initial_created_at


def test_17_updated_at_changes_when_status_changes():
    mgr = IncidentManager()
    alert = make_alert()
    inc = mgr.create_incident(alert)
    initial_updated_at = inc.updated_at
    time.sleep(0.01)
    updated_inc = mgr.update_status(inc.incident_id, IncidentStatus.INVESTIGATING)
    assert updated_inc.updated_at > initial_updated_at


def test_18_safe_alert_does_not_create_meaningless_incident():
    mgr = IncidentManager()
    safe_alert = Alert(
        severity="SAFE",
        risk_score=0,
        attack_types=[],
        source_ips=[],
        rule_names=[],
        detection_count=0,
        reasons=["No active attack detections"],
    )
    inc = mgr.create_incident(safe_alert)
    assert inc is None


def test_19_duplicate_alert_handling():
    mgr = IncidentManager()
    alert = make_alert(alert_id="alert-dup-001")
    inc1 = mgr.create_incident(alert)
    assert inc1 is not None
    with pytest.raises(DuplicateIncidentError):
        mgr.create_incident(alert)


def test_20_malformed_invalid_input_handled_safely():
    mgr = IncidentManager()
    assert mgr.create_incident(None) is None
    with pytest.raises(KeyError):
        mgr.update_status("non-existent-inc-id", IncidentStatus.INVESTIGATING)

