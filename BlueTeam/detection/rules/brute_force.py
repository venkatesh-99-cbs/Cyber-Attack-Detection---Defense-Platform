from collections import defaultdict
from datetime import datetime, timezone
from typing import List
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.detection.base_rule import BaseRule, DetectionResult


def _get_timestamp_seconds(dt: datetime) -> float:
    """Helper to convert datetime to epoch seconds safely across tz-aware and tz-naive values."""
    if dt.tzinfo is not None:
        return dt.timestamp()
    return dt.replace(tzinfo=timezone.utc).timestamp()


class BruteForceRule(BaseRule):
    """
    Detects repeated failed login attempts from the same source IP within a defined time window.
    """

    rule_name: str = "BruteForceRule"
    attack_type: str = "brute_force"

    def __init__(self, threshold: int = 5, time_window_seconds: int = 60):
        self.threshold = threshold
        self.time_window_seconds = time_window_seconds

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        results: List[DetectionResult] = []

        # 1. Filter for failed login events
        failed_logins = [e for e in events if e.event_type == "login_failure"]
        if not failed_logins:
            return results

        # 2. Group by source IP
        grouped = defaultdict(list)
        for event in failed_logins:
            grouped[event.source_ip].append(event)

        # 3. Evaluate each source IP independently
        for source_ip, ip_events in grouped.items():
            sorted_events = sorted(
                ip_events, key=lambda e: _get_timestamp_seconds(e.timestamp)
            )
            n = len(sorted_events)
            if n < self.threshold:
                continue

            i = 0
            while i < n:
                t_start = _get_timestamp_seconds(sorted_events[i].timestamp)
                j = i
                while j + 1 < n and (
                    _get_timestamp_seconds(sorted_events[j + 1].timestamp) - t_start
                    <= self.time_window_seconds
                ):
                    j += 1

                count = j - i + 1
                if count >= self.threshold:
                    cluster = sorted_events[i : j + 1]
                    event_ids = [e.event_id for e in cluster]
                    t_end = _get_timestamp_seconds(cluster[-1].timestamp)
                    duration = int(t_end - t_start)
                    evidence = [
                        f"{count} failed login attempts from source IP {source_ip} "
                        f"within {duration} seconds (threshold: {self.threshold} attempts in {self.time_window_seconds}s)"
                    ]
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
                    i = j + 1
                else:
                    i += 1

        return results
