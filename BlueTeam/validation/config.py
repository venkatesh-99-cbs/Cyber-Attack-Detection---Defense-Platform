from typing import Optional
from pydantic import BaseModel


class ExpectedResult(BaseModel):
    attack_type: str
    detection: Optional[str] = None
    risk_level: Optional[str] = None
    alert: Optional[bool] = None
    incident: Optional[bool] = None
    response: Optional[str] = None


EXPECTED_SCENARIOS = {
    "brute_force": ExpectedResult(
        attack_type="brute_force",
        detection="BruteForceRule",
        risk_level="SUSPICIOUS", # 60 -> SUSPICIOUS
        alert=True,
        incident=True,
        response="SIMULATED",
    ),
    "port_scan": ExpectedResult(
        attack_type="port_scan",
        detection="PortScanRule",
        risk_level="SUSPICIOUS", # 40 -> SUSPICIOUS
        alert=True,
        incident=True,
        response="SIMULATED",
    ),
    "sqli": ExpectedResult(
        attack_type="sql_injection",
        detection="SQLInjectionRule",
        risk_level="HIGH RISK", # 70 -> HIGH RISK
        alert=True,
        incident=True,
        response="SIMULATED",
    ),
}

def get_expected_for_attack(scenario_name: str) -> ExpectedResult:
    return EXPECTED_SCENARIOS.get(scenario_name)
