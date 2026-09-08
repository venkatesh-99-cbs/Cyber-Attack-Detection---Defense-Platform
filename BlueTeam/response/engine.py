import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from BlueTeam.incidents.manager import Incident
from BlueTeam.response.ip_blocker import IPBlocker, get_rule_name_for_ip

logger = logging.getLogger(__name__)


class ResponseAction(str, Enum):
    BLOCK_IP = "BLOCK_IP"


class ResponseStatus(str, Enum):
    SIMULATED = "SIMULATED"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"


class ResponseMode(str, Enum):
    SIMULATION = "SIMULATION"
    REAL = "REAL"


class ResponseResult(BaseModel):
    """
    Structured result of a defensive response evaluation or execution.
    """

    response_id: str = Field(
        default_factory=lambda: f"resp-{uuid.uuid4().hex[:8]}"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    incident_id: str
    action: str = ResponseAction.BLOCK_IP.value
    source_ip: Optional[str] = None
    mode: str = ResponseMode.SIMULATION.value
    status: str
    reason: str
    rule_name: Optional[str] = None
    error: Optional[str] = None


class ResponseEngine:
    """
    Blue Team Response Engine.
    Evaluates approved Incidents and executes or simulates controlled IP blocking actions.
    Does not detect attacks or calculate risk scores.
    """

    def __init__(
        self,
        mode: Optional[str] = None,
        ip_blocker: Optional[IPBlocker] = None,
        allowed_networks: Optional[List[str]] = None,
    ):
        if mode is None:
            raw_mode = os.getenv("RESPONSE_MODE", "SIMULATION").strip().upper()
            if raw_mode in (ResponseMode.SIMULATION.value, ResponseMode.REAL.value):
                self.mode = raw_mode
            else:
                self.mode = ResponseMode.SIMULATION.value
        else:
            self.mode = mode.upper()

        if ip_blocker is None:
            self.ip_blocker = IPBlocker(allowed_networks=allowed_networks)
        else:
            self.ip_blocker = ip_blocker

    def process_incident(
        self,
        incident: Optional[Incident],
        override_action: Optional[str] = None,
    ) -> ResponseResult:
        """
        Evaluates an Incident and executes response policy.
        """
        if incident is None:
            err = "No incident provided."
            logger.warning(f"Response evaluation rejected: {err}")
            return ResponseResult(
                incident_id="none",
                mode=self.mode,
                status=ResponseStatus.REJECTED.value,
                reason=err,
                error=err,
            )

        inc_id = incident.incident_id

        # 1. Policy check: SAFE incidents
        if incident.severity == "SAFE":
            msg = "Incident severity is SAFE; no response action required."
            logger.info(f"[{inc_id}] {msg}")
            return ResponseResult(
                incident_id=inc_id,
                mode=self.mode,
                status=ResponseStatus.SKIPPED.value,
                reason=msg,
            )

        # 2. Policy check: SUSPICIOUS incidents without explicit override
        if incident.severity == "SUSPICIOUS" and override_action != ResponseAction.BLOCK_IP.value:
            msg = "Incident severity is SUSPICIOUS; automatic IP blocking disabled by default."
            logger.info(f"[{inc_id}] {msg}")
            return ResponseResult(
                incident_id=inc_id,
                mode=self.mode,
                status=ResponseStatus.SKIPPED.value,
                reason=msg,
            )

        # 3. Source IP checks for HIGH RISK or override
        source_ips = incident.source_ips or []
        if len(source_ips) == 0:
            err = "No source IP present in incident."
            logger.warning(f"[{inc_id}] Response rejected: {err}")
            return ResponseResult(
                incident_id=inc_id,
                mode=self.mode,
                status=ResponseStatus.REJECTED.value,
                reason=err,
                error=err,
            )

        if len(source_ips) > 1:
            err = f"Multiple source IPs present in incident ({source_ips}); automatic blocking requires exactly one source IP."
            logger.warning(f"[{inc_id}] Response rejected: {err}")
            return ResponseResult(
                incident_id=inc_id,
                mode=self.mode,
                status=ResponseStatus.REJECTED.value,
                reason=err,
                error=err,
            )

        target_ip = source_ips[0]
        rule_name = get_rule_name_for_ip(target_ip)

        # 4. Execute block via IPBlocker (SIMULATION or REAL)
        is_simulation = (self.mode == ResponseMode.SIMULATION.value)
        block_result = self.ip_blocker.block_ip(
            target_ip, is_simulation=is_simulation
        )

        logger.info(
            f"[{inc_id}] Response executed for IP {target_ip} (mode={self.mode}, status={block_result.status}): {block_result.reason}"
        )

        return ResponseResult(
            incident_id=inc_id,
            source_ip=target_ip,
            mode=self.mode,
            status=block_result.status,
            reason=block_result.reason,
            rule_name=rule_name,
            error=block_result.error,
        )

    def evaluate_incident(
        self,
        incident: Optional[Incident],
        override_action: Optional[str] = None,
    ) -> ResponseResult:
        """Alias for process_incident."""
        return self.process_incident(incident, override_action)

