import pytest
from BlueTeam.detection.base_rule import DetectionResult
from BlueTeam.risk.classification import classify_score, RiskLevel
from BlueTeam.risk.scoring import calculate_risk_score, get_attack_base_score, ATTACK_BASE_SCORES
from BlueTeam.risk.engine import RiskEngine, RiskResult


def make_detection(
    attack_type: str,
    source_ip: str = "192.168.1.100",
    rule_name: str = "TestRule",
    evidence: list = None,
    event_ids: list = None,
) -> DetectionResult:
    if evidence is None:
        evidence = ["Test evidence"]
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


# =====================================================================
# CLASSIFICATION TESTS
# =====================================================================

def test_classification_score_0_safe():
    assert classify_score(0) == "SAFE"


def test_classification_score_29_safe():
    assert classify_score(29) == "SAFE"


def test_classification_score_30_suspicious():
    assert classify_score(30) == "SUSPICIOUS"


def test_classification_score_69_suspicious():
    assert classify_score(69) == "SUSPICIOUS"


def test_classification_score_70_high_risk():
    assert classify_score(70) == "HIGH RISK"


def test_classification_score_100_high_risk():
    assert classify_score(100) == "HIGH RISK"


# =====================================================================
# SCORING TESTS
# =====================================================================

def test_scoring_no_detections():
    score, types, reasons = calculate_risk_score([])
    assert score == 0
    assert types == []
    assert reasons == ["No active attack detections"]


def test_scoring_port_scan():
    d = make_detection("port_scan")
    score, types, reasons = calculate_risk_score([d])
    assert score == 40
    assert types == ["port_scan"]
    assert any("40" in r for r in reasons)


def test_scoring_brute_force():
    d = make_detection("brute_force")
    score, types, reasons = calculate_risk_score([d])
    assert score == 60
    assert types == ["brute_force"]
    assert any("60" in r for r in reasons)


def test_scoring_sql_injection():
    d = make_detection("sql_injection")
    score, types, reasons = calculate_risk_score([d])
    assert score == 70
    assert types == ["sql_injection"]
    assert any("70" in r for r in reasons)


def test_scoring_never_exceeds_100():
    d1 = make_detection("sql_injection")  # 70
    d2 = make_detection("brute_force")     # 60
    score, types, reasons = calculate_risk_score([d1, d2])
    assert score == 100
    assert len(types) == 2


def test_scoring_never_below_0():
    score, types, reasons = calculate_risk_score([])
    assert score >= 0


def test_scoring_unknown_attack_type_does_not_crash():
    d = make_detection("unknown_super_attack")
    score, types, reasons = calculate_risk_score([d])
    assert score == 0
    assert types == ["unknown_super_attack"]
    assert any("Unknown attack type 'unknown_super_attack'" in r for r in reasons)


# =====================================================================
# RISK ENGINE TESTS
# =====================================================================

def test_engine_no_detections():
    engine = RiskEngine()
    result = engine.analyze([])
    assert isinstance(result, RiskResult)
    assert result.score == 0
    assert result.risk_level == "SAFE"
    assert result.reasons == ["No active attack detections"]


def test_engine_port_scan():
    engine = RiskEngine()
    d = make_detection("port_scan")
    result = engine.analyze([d])
    assert result.score == 40
    assert result.risk_level == "SUSPICIOUS"
    assert result.attack_types == ["port_scan"]


def test_engine_brute_force():
    engine = RiskEngine()
    d = make_detection("brute_force")
    result = engine.analyze([d])
    assert result.score == 60
    assert result.risk_level == "SUSPICIOUS"
    assert result.attack_types == ["brute_force"]


def test_engine_sql_injection():
    engine = RiskEngine()
    d = make_detection("sql_injection")
    result = engine.analyze([d])
    assert result.score == 70
    assert result.risk_level == "HIGH RISK"
    assert result.attack_types == ["sql_injection"]


def test_engine_port_scan_plus_brute_force():
    engine = RiskEngine()
    d1 = make_detection("port_scan")    # 40
    d2 = make_detection("brute_force")   # 60
    result = engine.analyze([d1, d2])
    assert result.score == 100
    assert result.risk_level == "HIGH RISK"
    assert "port_scan" in result.attack_types
    assert "brute_force" in result.attack_types


def test_engine_sql_injection_plus_brute_force():
    engine = RiskEngine()
    d1 = make_detection("sql_injection") # 70
    d2 = make_detection("brute_force")    # 60
    result = engine.analyze([d1, d2])
    assert result.score == 100
    assert result.risk_level == "HIGH RISK"
    assert "sql_injection" in result.attack_types
    assert "brute_force" in result.attack_types


def test_engine_multiple_detections_represented_in_reasons():
    engine = RiskEngine()
    d1 = make_detection("port_scan")
    d2 = make_detection("sql_injection")
    result = engine.analyze([d1, d2])
    assert len(result.reasons) == 2
    assert any("Port scan" in r for r in result.reasons)
    assert any("SQL injection" in r for r in result.reasons)


def test_engine_attack_types_preserved():
    engine = RiskEngine()
    d1 = make_detection("port_scan")
    d2 = make_detection("sql_injection")
    result = engine.analyze([d1, d2])
    assert result.attack_types == ["port_scan", "sql_injection"]


def test_engine_unknown_attack_handled_safely():
    engine = RiskEngine()
    d = make_detection("zero_day_unknown")
    result = engine.analyze([d])
    assert result.score == 0
    assert result.risk_level == "SAFE"
    assert any("Unknown attack type 'zero_day_unknown'" in r for r in result.reasons)


def test_engine_result_is_deterministic():
    engine = RiskEngine()
    d1 = make_detection("port_scan")
    d2 = make_detection("brute_force")
    res1 = engine.analyze([d1, d2])
    res2 = engine.analyze([d1, d2])
    assert res1.score == res2.score
    assert res1.risk_level == res2.risk_level
    assert res1.reasons == res2.reasons


# =====================================================================
# EXPLAINABILITY TESTS
# =====================================================================

def test_explainability_structure():
    engine = RiskEngine()
    d = make_detection("sql_injection", source_ip="10.0.0.99", rule_name="SQLInjectionRule")
    result = engine.analyze([d])

    # Must contain score, risk level, attack types, reasons
    assert hasattr(result, "score")
    assert hasattr(result, "risk_level")
    assert hasattr(result, "attack_types")
    assert hasattr(result, "reasons")

    assert result.score == 70
    assert result.risk_level == "HIGH RISK"
    assert result.attack_types == ["sql_injection"]
    assert len(result.reasons) > 0
    assert result.source_ips == ["10.0.0.99"]
    assert result.rule_names == ["SQLInjectionRule"]

