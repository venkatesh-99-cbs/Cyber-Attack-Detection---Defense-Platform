from collections import defaultdict
from typing import List, Optional, Tuple
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.detection.base_rule import BaseRule, DetectionResult

DEFAULT_SQLI_PATTERNS = [
    "' OR 1=1",
    "OR 1=1",
    "' OR '1'='1",
    '" OR "1"="1',
    "UNION SELECT",
    "UNION ALL SELECT",
    "DROP TABLE",
    "DROP DATABASE",
    "DELETE FROM",
    "INSERT INTO",
    "--",
]


def _inspect_event(
    event: SecurityEvent, patterns: List[str]
) -> List[Tuple[str, str, str]]:
    """
    Inspects event textual fields for SQL injection patterns.
    Returns list of (field_name, matched_pattern, text_content).
    """
    matches = []
    fields_to_check: List[Tuple[str, str]] = []

    if event.endpoint:
        fields_to_check.append(("endpoint", event.endpoint))
    if event.message:
        fields_to_check.append(("message", event.message))
    if isinstance(event.metadata, dict):
        for k, v in event.metadata.items():
            if isinstance(v, str):
                fields_to_check.append((f"metadata.{k}", v))
            elif isinstance(v, (int, float, bool)):
                pass
            elif v is not None:
                fields_to_check.append((f"metadata.{k}", str(v)))

    for field_name, text in fields_to_check:
        text_lower = text.lower()
        for pat in patterns:
            if pat.lower() in text_lower:
                matches.append((field_name, pat, text))

    return matches


class SQLInjectionRule(BaseRule):
    """
    Detects suspicious SQL injection patterns in HTTP and application event data.
    """

    rule_name: str = "SQLInjectionRule"
    attack_type: str = "sql_injection"

    def __init__(self, patterns: Optional[List[str]] = None):
        self.patterns = patterns if patterns is not None else DEFAULT_SQLI_PATTERNS

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        results: List[DetectionResult] = []

        grouped = defaultdict(list)
        for event in events:
            matches = _inspect_event(event, self.patterns)
            if matches:
                grouped[event.source_ip].append((event, matches))

        for source_ip, match_list in grouped.items():
            event_ids = [e.event_id for e, _ in match_list]
            evidence = []
            for e, matches in match_list:
                for field_name, pat, text in matches:
                    evidence.append(
                        f"Event '{e.event_id}': SQL injection pattern '{pat}' "
                        f"detected in {field_name} ('{text}')"
                    )

            results.append(
                DetectionResult(
                    detected=True,
                    attack_type=self.attack_type,
                    source_ip=source_ip,
                    rule_name=self.rule_name,
                    severity="high",
                    evidence=evidence,
                    event_ids=event_ids,
                )
            )

        return results
