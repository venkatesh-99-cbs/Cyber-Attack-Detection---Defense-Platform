from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Optional
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.detection.base_rule import BaseRule, DetectionResult


def _get_timestamp_seconds(dt: datetime) -> float:
    """Helper to convert datetime to epoch seconds safely across tz-aware and tz-naive values."""
    if dt.tzinfo is not None:
        return dt.timestamp()
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _extract_port(event: SecurityEvent) -> Optional[int]:
    """Safely extract integer port from event metadata."""
    if not isinstance(event.metadata, dict):
        return None
    port_val = event.metadata.get("port")
    if port_val is None:
        return None
    try:
        port_int = int(port_val)
        if 1 <= port_int <= 65535:
            return port_int
    except (ValueError, TypeError):
        return None
    return None


class PortScanRule(BaseRule):
    """
    Detects repeated connection attempts from the same source IP to multiple distinct ports within a short time window.
    """

    rule_name: str = "PortScanRule"
    attack_type: str = "port_scan"

    def __init__(self, threshold: int = 5, time_window_seconds: int = 60):
        self.threshold = threshold
        self.time_window_seconds = time_window_seconds

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        results: List[DetectionResult] = []

        # 1. Filter connection_attempt events with valid ports
        conn_events = []
        for e in events:
            if e.event_type == "connection_attempt":
                port = _extract_port(e)
                if port is not None:
                    conn_events.append((e, port))

        if not conn_events:
            return results

        # 2. Group by source IP
        grouped = defaultdict(list)
        for e, port in conn_events:
            grouped[e.source_ip].append((e, port))

        # 3. Evaluate each source IP independently
        for source_ip, ip_tuples in grouped.items():
            sorted_tuples = sorted(
                ip_tuples, key=lambda pair: _get_timestamp_seconds(pair[0].timestamp)
            )
            n = len(sorted_tuples)

            i = 0
            while i < n:
                t_start = _get_timestamp_seconds(sorted_tuples[i][0].timestamp)
                j = i
                while j + 1 < n and (
                    _get_timestamp_seconds(sorted_tuples[j + 1][0].timestamp) - t_start
                    <= self.time_window_seconds
                ):
                    j += 1

                window_tuples = sorted_tuples[i : j + 1]
                distinct_ports = {port for _, port in window_tuples}

                if len(distinct_ports) >= self.threshold:
                    event_ids = [e.event_id for e, _ in window_tuples]
                    sorted_ports = sorted(list(distinct_ports))
                    evidence = [
                        f"Source IP {source_ip} probed {len(distinct_ports)} distinct ports "
                        f"({sorted_ports}) within {self.time_window_seconds} seconds (threshold: {self.threshold} distinct ports)"
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
