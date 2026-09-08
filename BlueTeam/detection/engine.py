import logging
from typing import List, Optional
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.detection.base_rule import BaseRule, DetectionResult
from BlueTeam.detection.rules.brute_force import BruteForceRule
from BlueTeam.detection.rules.port_scan import PortScanRule
from BlueTeam.detection.rules.sqli import SQLInjectionRule

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Blue Team Detection Engine.
    Executes detection rules independently against ingested security events
    and produces explainable detection results.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        if rules is None:
            self.rules: List[BaseRule] = [
                BruteForceRule(),
                PortScanRule(),
                SQLInjectionRule(),
            ]
        else:
            self.rules = list(rules)

    def add_rule(self, rule: BaseRule) -> None:
        """Add a new detection rule to the engine."""
        self.rules.append(rule)

    def analyze(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze a list of security events against all configured detection rules.
        Returns a list of DetectionResult objects.
        """
        results: List[DetectionResult] = []
        for rule in self.rules:
            try:
                rule_results = rule.evaluate(events)
                results.extend(rule_results)
            except Exception as e:
                logger.error(
                    f"Error executing rule '{getattr(rule, 'rule_name', rule)}': {e}",
                    exc_info=True,
                )
        return results

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """Alias for analyze method for interface consistency."""
        return self.analyze(events)
