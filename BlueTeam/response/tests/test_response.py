from datetime import datetime
import logging
from unittest.mock import MagicMock, patch
import pytest
from BlueTeam.incidents.manager import Incident, IncidentStatus
from BlueTeam.response.engine import (
    ResponseAction,
    ResponseEngine,
    ResponseMode,
    ResponseResult,
    ResponseStatus,
)
from BlueTeam.response.ip_blocker import IPBlocker, get_rule_name_for_ip, validate_ip_format


def make_incident(
    severity: str = "HIGH RISK",
    risk_score: int = 100,
    source_ips: list = None,
    alert_id: str = "alert-001",
    incident_id: str = "inc-001",
) -> Incident:
    if source_ips is None:
        source_ips = ["192.168.1.100"]
    return Incident(
        incident_id=incident_id,
        alert_id=alert_id,
        severity=severity,
        risk_score=risk_score,
        attack_types=["brute_force"],
        source_ips=source_ips,
        rule_names=["BruteForceRule"],
        detection_count=1,
        reasons=["Brute-force login attempt detected"],
        status=IncidentStatus.OPEN.value,
    )


# =====================================================================
# 24 REQUIRED UNIT TESTS
# =====================================================================

def test_1_safe_incident_skipped():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(severity="SAFE", risk_score=0, source_ips=["192.168.1.10"])
    res = engine.process_incident(inc)
    assert res.status == "SKIPPED"
    assert "SAFE" in res.reason


def test_2_suspicious_incident_skipped_by_default():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(severity="SUSPICIOUS", risk_score=60, source_ips=["192.168.1.10"])
    res = engine.process_incident(inc)
    assert res.status == "SKIPPED"
    assert "SUSPICIOUS" in res.reason


def test_3_high_risk_incident_in_simulation_mode_simulated():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(severity="HIGH RISK", risk_score=100, source_ips=["192.168.1.10"])
    res = engine.process_incident(inc)
    assert res.status == "SIMULATED"
    assert res.action == "BLOCK_IP"
    assert res.source_ip == "192.168.1.10"


def test_4_simulated_result_contains_correct_incident_id():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(incident_id="inc-test-999")
    res = engine.process_incident(inc)
    assert res.incident_id == "inc-test-999"


def test_5_simulated_result_contains_correct_source_ip():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(source_ips=["192.168.1.42"])
    res = engine.process_incident(inc)
    assert res.source_ip == "192.168.1.42"


def test_6_invalid_ip_rejected():
    blocker = IPBlocker()
    res = blocker.block_ip("invalid_ip_str", is_simulation=True)
    assert res.status == "REJECTED"
    assert res.success is False
    assert "Invalid IP" in res.reason

    res2 = blocker.block_ip("192.168.1.300", is_simulation=True)
    assert res2.status == "REJECTED"


def test_7_public_or_non_lab_ip_rejected_in_real_mode():
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    res = blocker.block_ip("8.8.8.8", is_simulation=False)
    assert res.status == "REJECTED"
    assert "not within any allowed lab network" in res.reason


def test_8_missing_lab_allowlist_in_real_mode_rejected():
    blocker = IPBlocker(allowed_networks=[])
    res = blocker.block_ip("192.168.1.10", is_simulation=False)
    assert res.status == "REJECTED"
    assert "No allowed lab networks" in res.reason


def test_9_multiple_source_ips_rejected():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(source_ips=["192.168.1.10", "192.168.1.11"])
    res = engine.process_incident(inc)
    assert res.status == "REJECTED"
    assert "Multiple source IPs" in res.reason


def test_10_no_source_ip_rejected():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident(source_ips=[])
    res = engine.process_incident(inc)
    assert res.status == "REJECTED"
    assert "No source IP" in res.reason


@patch("subprocess.run")
def test_11_real_mode_does_not_use_shell_true(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    blocker.block_ip("192.168.1.10", is_simulation=False)
    assert mock_run.called
    kwargs = mock_run.call_args.kwargs
    assert kwargs.get("shell") is False


@patch("subprocess.run")
def test_12_real_mode_passes_subprocess_arguments_safely_as_list(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    blocker.block_ip("192.168.1.10", is_simulation=False)
    assert mock_run.called
    args = mock_run.call_args.args[0]
    assert isinstance(args, list)
    assert args[0] == "netsh"
    assert "remoteip=192.168.1.10" in args


@patch("subprocess.run")
@patch("sys.platform", "win32")
def test_13_firewall_success(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    res = blocker.block_ip("192.168.1.10", is_simulation=False)
    assert res.status == "SUCCESS"
    assert res.success is True


@patch("subprocess.run")
@patch("sys.platform", "win32")
def test_14_firewall_failure(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Rule creation failed.")
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    res = blocker.block_ip("192.168.1.10", is_simulation=False)
    assert res.status == "FAILED"
    assert res.success is False
    assert "failed" in res.reason.lower()


@patch("subprocess.run")
@patch("sys.platform", "win32")
def test_15_permission_failure(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="The requested operation requires elevation (Run as administrator).")
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    res = blocker.block_ip("192.168.1.10", is_simulation=False)
    assert res.status == "FAILED"
    assert res.success is False
    assert "elevation" in res.error or "failed" in res.reason.lower()


@patch("sys.platform", "linux")
def test_16_unsupported_os_failed_or_rejected():
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    res = blocker.block_ip("192.168.1.10", is_simulation=False)
    assert res.status == "FAILED"
    assert "Unsupported platform" in res.reason


def test_17_deterministic_firewall_rule_name_generated():
    rule1 = get_rule_name_for_ip("192.168.1.10")
    rule2 = get_rule_name_for_ip("192.168.1.10")
    assert rule1 == rule2
    assert rule1 == "CyberAttackDetectionDefense-Block-192.168.1.10"


def test_18_rule_name_contains_only_application_controlled_content():
    rule = get_rule_name_for_ip("10.0.0.5")
    assert rule.startswith("CyberAttackDetectionDefense-Block-")
    assert "CyberAttackDetectionDefense-Block-10.0.0.5" == rule


def test_19_response_result_receives_unique_response_id():
    engine = ResponseEngine(mode="SIMULATION")
    inc1 = make_incident(incident_id="inc-1")
    inc2 = make_incident(incident_id="inc-2")
    res1 = engine.process_incident(inc1)
    res2 = engine.process_incident(inc2)
    assert res1.response_id is not None
    assert res2.response_id is not None
    assert res1.response_id != res2.response_id
    assert res1.response_id.startswith("resp-")


def test_20_response_timestamp_is_generated():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident()
    res = engine.process_incident(inc)
    assert res.timestamp is not None
    assert isinstance(res.timestamp, datetime)


def test_21_response_action_is_block_ip_when_attempted():
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident()
    res = engine.process_incident(inc)
    assert res.action == "BLOCK_IP"
    assert res.action == ResponseAction.BLOCK_IP.value


def test_22_every_response_path_logs_meaningful_result(caplog):
    caplog.set_level(logging.INFO)
    engine = ResponseEngine(mode="SIMULATION")
    inc = make_incident()
    res = engine.process_incident(inc)
    assert res.status == "SIMULATED"
    assert any("Simulated" in record.message or "Response executed" in record.message for record in caplog.records)


@patch("subprocess.run")
@patch("sys.platform", "win32")
def test_23_unblock_only_targets_application_owned_rules(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
    blocker = IPBlocker(allowed_networks=["192.168.1.0/24"])
    res = blocker.unblock_ip("192.168.1.10", is_simulation=False)
    assert res.status == "SUCCESS"
    assert res.rule_name == "CyberAttackDetectionDefense-Block-192.168.1.10"
    args = mock_run.call_args.args[0]
    assert "delete" in args
    assert "name=CyberAttackDetectionDefense-Block-192.168.1.10" in args


def test_24_existing_detection_risk_alert_incident_behavior_unchanged():
    # Verify Incident creation and Response execution work seamlessly together
    from BlueTeam.alerts.engine import Alert
    from BlueTeam.incidents.manager import IncidentManager

    alert = Alert(
        severity="HIGH RISK",
        risk_score=100,
        attack_types=["sqli"],
        source_ips=["192.168.1.88"],
        rule_names=["SQLInjectionRule"],
        detection_count=1,
        reasons=["SQL injection attack detected"],
    )
    inc_mgr = IncidentManager()
    inc = inc_mgr.create_incident(alert)
    assert inc is not None
    assert inc.severity == "HIGH RISK"

    resp_engine = ResponseEngine(mode="SIMULATION")
    resp = resp_engine.process_incident(inc)
    assert resp.status == "SIMULATED"
    assert resp.source_ip == "192.168.1.88"

