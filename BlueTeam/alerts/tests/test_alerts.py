from datetime import datetime
import pytest
from BlueTeam.alerts.engine import AlertEngine, Alert, AlertStatus
from BlueTeam.detection.base_rule import DetectionResult
from BlueTeam.risk.engine import RiskResult


def make_detection(
    attack_type: str,
    source_ip: str = "192.168.1.100",
    rule_name: str = "TestRule",
    evidence: list = None,
    event_ids: list = None,
) -> DetectionResult:
    if evidence is None:
        evidence = [f"Evidence for {attack_type}"]
    if event_ids is None:
        event_ids = ["evt-101"]
    return DetectionResult(
        detected=True,
        attack_type=attack_type,
        source_ip=source_ip,
        rule_name=rule_name,
        severity="high",
        evidence=evidence,
        event_ids=event_ids,
    )


def make_risk_result(
    score: int = 60,
    risk_level: str = "SUSPICIOUS",
    attack_types: list = None,
    reasons: list = None,
    source_ips: list = None,
    rule_names: list = None,
    detection_count: int = 1,
) -> RiskResult:
    if attack_types is None:
        attack_types = ["brute_force"]
    if reasons is None:
        reasons = ["Brute-force detection contributed 60 risk points."]
    if source_ips is None:
        source_ips = ["192.168.1.100"]
    if rule_names is None:
        rule_names = ["BruteForceRule"]
    return RiskResult(
        score=score,
        risk_level=risk_level,
        attack_types=attack_types,
        reasons=reasons,
        source_ips=source_ips,
        rule_names=rule_names,
        detection_count=detection_count,
    )


# =====================================================================
# 15 REQUIRED UNIT TESTS
# =====================================================================

def test_1_safe_result_does_not_create_alert():
    engine = AlertEngine()
    safe_risk = RiskResult(
        score=0,
        risk_level="SAFE",
        attack_types=[],
        reasons=["No active attack detections"],
        source_ips=[],
        rule_names=[],
        detection_count=0,
    )
    alert = engine.create_alert(safe_risk)
    assert alert is None


def test_2_suspicious_risk_creates_alert():
    engine = AlertEngine()
    risk = make_risk_result(score=40, risk_level="SUSPICIOUS")
    alert = engine.create_alert(risk)
    assert alert is not None
    assert isinstance(alert, Alert)
    assert alert.severity == "SUSPICIOUS"


def test_3_high_risk_creates_alert():
    engine = AlertEngine()
    risk = make_risk_result(score=100, risk_level="HIGH RISK")
    alert = engine.create_alert(risk)
    assert alert is not None
    assert alert.severity == "HIGH RISK"


def test_4_alert_preserves_risk_score():
    engine = AlertEngine()
    risk = make_risk_result(score=70, risk_level="HIGH RISK")
    alert = engine.create_alert(risk)
    assert alert.risk_score == 70


def test_5_alert_preserves_risk_level():
    engine = AlertEngine()
    risk = make_risk_result(score=60, risk_level="SUSPICIOUS")
    alert = engine.create_alert(risk)
    assert alert.severity == "SUSPICIOUS"


def test_6_alert_preserves_attack_types():
    engine = AlertEngine()
    risk = make_risk_result(attack_types=["port_scan", "brute_force"])
    alert = engine.create_alert(risk)
    assert alert.attack_types == ["port_scan", "brute_force"]


def test_7_alert_preserves_source_ips():
    engine = AlertEngine()
    risk = make_risk_result(source_ips=["10.0.0.1", "10.0.0.2"])
    alert = engine.create_alert(risk)
    assert alert.source_ips == ["10.0.0.1", "10.0.0.2"]


def test_8_alert_preserves_rule_names():
    engine = AlertEngine()
    risk = make_risk_result(rule_names=["PortScanRule", "BruteForceRule"])
    alert = engine.create_alert(risk)
    assert alert.rule_names == ["PortScanRule", "BruteForceRule"]


def test_9_alert_preserves_detection_count():
    engine = AlertEngine()
    risk = make_risk_result(detection_count=3)
    alert = engine.create_alert(risk)
    assert alert.detection_count == 3


def test_10_alert_preserves_reasons():
    engine = AlertEngine()
    reasons = ["Reason 1: Port scan", "Reason 2: Brute force"]
    risk = make_risk_result(reasons=reasons)
    alert = engine.create_alert(risk)
    assert alert.reasons == reasons


def test_11_newly_generated_alert_has_active_status():
    engine = AlertEngine()
    risk = make_risk_result()
    alert = engine.create_alert(risk)
    assert alert.status == "ACTIVE"
    assert alert.status == AlertStatus.ACTIVE.value


def test_12_alert_id_is_generated():
    engine = AlertEngine()
    risk = make_risk_result()
    alert = engine.create_alert(risk)
    assert alert.alert_id is not None
    assert alert.alert_id.startswith("alert-")


def test_13_alert_timestamp_is_generated():
    engine = AlertEngine()
    risk = make_risk_result()
    alert = engine.create_alert(risk)
    assert alert.timestamp is not None
    assert isinstance(alert.timestamp, datetime)


def test_14_multiple_detections_are_preserved():
    engine = AlertEngine()
    d1 = make_detection("port_scan", source_ip="192.168.1.10", rule_name="PortScanRule")
    d2 = make_detection("brute_force", source_ip="192.168.1.10", rule_name="BruteForceRule")
    risk = RiskResult(
        score=100,
        risk_level="HIGH RISK",
        attack_types=["port_scan", "brute_force"],
        reasons=["Port scan contributed 40 risk points.", "Brute-force contributed 60 risk points."],
        source_ips=["192.168.1.10"],
        rule_names=["PortScanRule", "BruteForceRule"],
        detection_count=2,
    )
    alert = engine.create_alert(risk, detections=[d1, d2])
    assert alert is not None
    assert alert.attack_types == ["port_scan", "brute_force"]
    assert alert.rule_names == ["PortScanRule", "BruteForceRule"]
    assert alert.detection_count == 2
    assert any("Port scan" in r for r in alert.reasons)
    assert any("Brute-force" in r for r in alert.reasons)


def test_15_malformed_empty_detection_input_handled_safely():
    engine = AlertEngine()
    # None risk_result
    assert engine.create_alert(None) is None

    # Empty detections list with valid risk result
    risk = make_risk_result()
    alert = engine.create_alert(risk, detections=[])
    assert alert is not None
    assert alert.risk_score == 60

    # Detections list with None/empty values
    alert2 = engine.create_alert(risk, detections=None)
    assert alert2 is not None
    assert alert2.status == "ACTIVE"

