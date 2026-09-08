from datetime import datetime, timezone, timedelta
import pytest
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.detection.base_rule import DetectionResult
from BlueTeam.detection.engine import DetectionEngine
from BlueTeam.detection.rules.brute_force import BruteForceRule
from BlueTeam.detection.rules.port_scan import PortScanRule
from BlueTeam.detection.rules.sqli import SQLInjectionRule


def make_event(
    event_id: str,
    event_type: str,
    source_ip: str = "192.168.1.10",
    target_ip: str = "192.168.1.20",
    timestamp: datetime = None,
    endpoint: str = None,
    method: str = None,
    status_code: int = None,
    message: str = "Test event",
    metadata: dict = None,
) -> SecurityEvent:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    if metadata is None:
        metadata = {}
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        target_ip=target_ip,
        event_type=event_type,
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        message=message,
        metadata=metadata,
    )


# =====================================================================
# BRUTE FORCE RULE TESTS
# =====================================================================

def test_brute_force_1_failed_login():
    rule = BruteForceRule(threshold=5, time_window_seconds=60)
    events = [make_event("evt-1", "login_failure")]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_brute_force_4_failed_logins():
    rule = BruteForceRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    events = [
        make_event(f"evt-{i}", "login_failure", timestamp=base_time + timedelta(seconds=i * 5))
        for i in range(4)
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_brute_force_5_failed_logins_same_ip_within_60s():
    rule = BruteForceRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    events = [
        make_event(f"evt-{i}", "login_failure", source_ip="192.168.1.50", timestamp=base_time + timedelta(seconds=i * 10))
        for i in range(5)
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.detected is True
    assert res.attack_type == "brute_force"
    assert res.source_ip == "192.168.1.50"
    assert res.rule_name == "BruteForceRule"
    assert len(res.event_ids) == 5
    assert any("5 failed login attempts" in ev for ev in res.evidence)
    assert any("192.168.1.50" in ev for ev in res.evidence)


def test_brute_force_5_failed_logins_different_ips():
    rule = BruteForceRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    events = [
        make_event(f"evt-{i}", "login_failure", source_ip=f"10.0.0.{i}", timestamp=base_time + timedelta(seconds=i * 2))
        for i in range(5)
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_brute_force_5_failures_outside_time_window():
    rule = BruteForceRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    # Failures spaced 120 seconds apart
    events = [
        make_event(f"evt-{i}", "login_failure", timestamp=base_time + timedelta(seconds=i * 120))
        for i in range(5)
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_brute_force_evidence_contains_required_fields():
    rule = BruteForceRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    events = [
        make_event(f"evt-{i}", "login_failure", source_ip="192.168.1.99", timestamp=base_time + timedelta(seconds=i * 5))
        for i in range(5)
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.source_ip == "192.168.1.99"
    assert res.event_ids == ["evt-0", "evt-1", "evt-2", "evt-3", "evt-4"]
    assert any("192.168.1.99" in ev for ev in res.evidence)
    assert any("5" in ev for ev in res.evidence)


# =====================================================================
# PORT SCAN RULE TESTS
# =====================================================================

def test_port_scan_1_connection_attempt():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    events = [make_event("evt-1", "connection_attempt", metadata={"port": 80})]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_port_scan_4_distinct_ports():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    ports = [21, 22, 80, 443]
    events = [
        make_event(f"evt-{i}", "connection_attempt", timestamp=base_time + timedelta(seconds=i * 2), metadata={"port": p})
        for i, p in enumerate(ports)
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_port_scan_5_distinct_ports_within_60s():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    ports = [21, 22, 23, 25, 80]
    events = [
        make_event(f"evt-{i}", "connection_attempt", source_ip="192.168.1.77", timestamp=base_time + timedelta(seconds=i * 3), metadata={"port": p})
        for i, p in enumerate(ports)
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.detected is True
    assert res.attack_type == "port_scan"
    assert res.source_ip == "192.168.1.77"
    assert res.rule_name == "PortScanRule"
    assert len(res.event_ids) == 5
    assert any("5 distinct ports" in ev for ev in res.evidence)
    assert any("[21, 22, 23, 25, 80]" in ev for ev in res.evidence)


def test_port_scan_repeated_attempts_same_port():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    events = [
        make_event(f"evt-{i}", "connection_attempt", timestamp=base_time + timedelta(seconds=i * 2), metadata={"port": 80})
        for i in range(10)
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_port_scan_different_source_ips_evaluated_independently():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    # 3 ports from IP A, 3 ports from IP B -> total 6 events, but neither IP reaches 5 distinct ports
    events = [
        make_event("evt-a1", "connection_attempt", source_ip="10.0.0.1", timestamp=base_time, metadata={"port": 21}),
        make_event("evt-a2", "connection_attempt", source_ip="10.0.0.1", timestamp=base_time, metadata={"port": 22}),
        make_event("evt-a3", "connection_attempt", source_ip="10.0.0.1", timestamp=base_time, metadata={"port": 23}),
        make_event("evt-b1", "connection_attempt", source_ip="10.0.0.2", timestamp=base_time, metadata={"port": 80}),
        make_event("evt-b2", "connection_attempt", source_ip="10.0.0.2", timestamp=base_time, metadata={"port": 443}),
        make_event("evt-b3", "connection_attempt", source_ip="10.0.0.2", timestamp=base_time, metadata={"port": 8080}),
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_port_scan_missing_or_invalid_metadata_port_no_crash():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    events = [
        make_event("evt-1", "connection_attempt", metadata={}),
        make_event("evt-2", "connection_attempt", metadata={"port": "invalid_port"}),
        make_event("evt-3", "connection_attempt", metadata={"port": None}),
        make_event("evt-4", "connection_attempt", metadata={"other": 80}),
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_port_scan_evidence_contains_ports_and_event_ids():
    rule = PortScanRule(threshold=5, time_window_seconds=60)
    base_time = datetime.now(timezone.utc)
    ports = [80, 443, 8080, 8443, 9000]
    events = [
        make_event(f"evt-{i}", "connection_attempt", source_ip="172.16.0.5", timestamp=base_time + timedelta(seconds=i), metadata={"port": p})
        for i, p in enumerate(ports)
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.event_ids == ["evt-0", "evt-1", "evt-2", "evt-3", "evt-4"]
    assert any("172.16.0.5" in ev for ev in res.evidence)
    assert any("5 distinct ports" in ev for ev in res.evidence)


# =====================================================================
# SQL INJECTION RULE TESTS
# =====================================================================

def test_sqli_normal_http_request():
    rule = SQLInjectionRule()
    events = [
        make_event("evt-1", "http_request", endpoint="/login", message="User viewing homepage")
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_sqli_suspicious_pattern_in_endpoint():
    rule = SQLInjectionRule()
    events = [
        make_event("evt-1", "http_request", source_ip="192.168.1.100", endpoint="/api/users?id=1' OR 1=1--")
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.detected is True
    assert res.attack_type == "sql_injection"
    assert res.source_ip == "192.168.1.100"
    assert res.rule_name == "SQLInjectionRule"
    assert res.event_ids == ["evt-1"]
    assert any("endpoint" in ev for ev in res.evidence)
    assert any("' OR 1=1" in ev for ev in res.evidence)


def test_sqli_suspicious_pattern_in_message():
    rule = SQLInjectionRule()
    events = [
        make_event("evt-1", "http_request", source_ip="192.168.1.101", message="Payload executed UNION SELECT * FROM users")
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.detected is True
    assert res.source_ip == "192.168.1.101"
    assert res.event_ids == ["evt-1"]
    assert any("message" in ev for ev in res.evidence)
    assert any("UNION SELECT" in ev for ev in res.evidence)


def test_sqli_case_insensitive_matching():
    rule = SQLInjectionRule()
    events = [
        make_event("evt-1", "http_request", endpoint="/search?q=union select 1,2,3"),
        make_event("evt-2", "http_request", message="drop table users"),
    ]
    results = rule.evaluate(events)
    assert len(results) >= 1
    attack_types = [r.attack_type for r in results]
    assert all(at == "sql_injection" for at in attack_types)


def test_sqli_normal_text_containing_sql_alone_no_detection():
    rule = SQLInjectionRule()
    events = [
        make_event("evt-1", "http_request", endpoint="/docs/sql_queries", message="Executing SQL query for user profile"),
        make_event("evt-2", "http_request", metadata={"info": "Database engine is SQL Server"}),
    ]
    results = rule.evaluate(events)
    assert len(results) == 0


def test_sqli_evidence_identifies_matched_indicator_and_event_id():
    rule = SQLInjectionRule()
    events = [
        make_event("evt-sqli-99", "http_request", source_ip="10.10.10.10", endpoint="/admin' OR '1'='1")
    ]
    results = rule.evaluate(events)
    assert len(results) == 1
    res = results[0]
    assert res.event_ids == ["evt-sqli-99"]
    assert any("evt-sqli-99" in ev for ev in res.evidence)
    assert any("' OR '1'='1" in ev for ev in res.evidence)


# =====================================================================
# ENGINE TESTS
# =====================================================================

def test_engine_loads_all_three_rules():
    engine = DetectionEngine()
    assert len(engine.rules) == 3
    rule_names = [r.rule_name for r in engine.rules]
    assert "BruteForceRule" in rule_names
    assert "PortScanRule" in rule_names
    assert "SQLInjectionRule" in rule_names


def test_engine_normal_events_produce_no_detections():
    engine = DetectionEngine()
    events = [
        make_event("evt-1", "login_success", endpoint="/dashboard"),
        make_event("evt-2", "connection_attempt", metadata={"port": 80}),
        make_event("evt-3", "http_request", message="Regular web browsing"),
    ]
    results = engine.analyze(events)
    assert len(results) == 0


def test_engine_brute_force_events_trigger_brute_force_rule():
    engine = DetectionEngine()
    base_time = datetime.now(timezone.utc)
    events = [
        make_event(f"evt-bf-{i}", "login_failure", source_ip="192.168.1.10", timestamp=base_time + timedelta(seconds=i * 2))
        for i in range(5)
    ]
    results = engine.analyze(events)
    assert len(results) == 1
    assert results[0].attack_type == "brute_force"
    assert results[0].rule_name == "BruteForceRule"


def test_engine_port_scan_events_trigger_port_scan_rule():
    engine = DetectionEngine()
    base_time = datetime.now(timezone.utc)
    ports = [21, 22, 23, 25, 80]
    events = [
        make_event(f"evt-ps-{i}", "connection_attempt", source_ip="192.168.1.20", timestamp=base_time + timedelta(seconds=i * 2), metadata={"port": p})
        for i, p in enumerate(ports)
    ]
    results = engine.analyze(events)
    assert len(results) == 1
    assert results[0].attack_type == "port_scan"
    assert results[0].rule_name == "PortScanRule"


def test_engine_sql_injection_event_triggers_sqli_rule():
    engine = DetectionEngine()
    events = [
        make_event("evt-sqli-1", "http_request", source_ip="192.168.1.30", endpoint="/products?category=books' UNION SELECT 1,2,3--")
    ]
    results = engine.analyze(events)
    assert len(results) == 1
    assert results[0].attack_type == "sql_injection"
    assert results[0].rule_name == "SQLInjectionRule"


def test_engine_multiple_attack_types_detected_independently():
    engine = DetectionEngine()
    base_time = datetime.now(timezone.utc)
    events = []

    # Add 5 brute-force events from IP 1.1.1.1
    for i in range(5):
        events.append(make_event(f"evt-bf-{i}", "login_failure", source_ip="1.1.1.1", timestamp=base_time + timedelta(seconds=i)))

    # Add port scan events from IP 2.2.2.2 (5 distinct ports)
    for i, p in enumerate([21, 22, 23, 25, 80]):
        events.append(make_event(f"evt-ps-{i}", "connection_attempt", source_ip="2.2.2.2", timestamp=base_time + timedelta(seconds=i), metadata={"port": p}))

    # Add SQL injection event from IP 3.3.3.3
    events.append(make_event("evt-sqli-1", "http_request", source_ip="3.3.3.3", endpoint="/api' OR 1=1--"))

    results = engine.analyze(events)
    assert len(results) == 3
    attack_types = {r.attack_type for r in results}
    assert attack_types == {"brute_force", "port_scan", "sql_injection"}

