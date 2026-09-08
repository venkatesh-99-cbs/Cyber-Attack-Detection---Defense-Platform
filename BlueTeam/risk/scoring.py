from typing import Dict, List, Tuple
from BlueTeam.detection.base_rule import DetectionResult

# Default MVP attack scoring values
ATTACK_BASE_SCORES: Dict[str, int] = {
    "port_scan": 40,
    "brute_force": 60,
    "sql_injection": 70,
}

ATTACK_DISPLAY_NAMES: Dict[str, str] = {
    "port_scan": "Port scan",
    "brute_force": "Brute-force",
    "sql_injection": "SQL injection",
}


def get_attack_base_score(attack_type: str) -> Tuple[int, bool]:
    """
    Returns (score, is_known) for a given attack_type.
    Unknown attack types return (0, False).
    """
    if attack_type in ATTACK_BASE_SCORES:
        return ATTACK_BASE_SCORES[attack_type], True
    return 0, False


def calculate_risk_score(
    detections: List[DetectionResult],
) -> Tuple[int, List[str], List[str]]:
    """
    Calculates total risk score bounded between 0 and 100,
    and builds explainable reasons for each detection.

    Returns: (bounded_score, attack_types, reasons)
    """
    if not detections:
        return 0, [], ["No active attack detections"]

    total_score = 0
    reasons: List[str] = []
    attack_types_seen: List[str] = []

    for detection in detections:
        attack_type = detection.attack_type
        if attack_type not in attack_types_seen:
            attack_types_seen.append(attack_type)

        score, is_known = get_attack_base_score(attack_type)

        if is_known:
            total_score += score
            display_name = ATTACK_DISPLAY_NAMES.get(
                attack_type, attack_type.replace("_", " ").capitalize()
            )
            reasons.append(f"{display_name} detection contributed {score} risk points.")
        else:
            reasons.append(
                f"Unknown attack type '{attack_type}' has no configured risk score (contributed 0 risk points)."
            )

    bounded_score = max(0, min(100, total_score))
    return bounded_score, attack_types_seen, reasons

