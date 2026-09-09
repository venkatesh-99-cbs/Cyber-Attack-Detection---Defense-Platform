import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from BlueTeam.alerts.engine import Alert, AlertEngine
from BlueTeam.incidents.manager import IncidentManager
from BlueTeam.response.engine import ResponseEngine
from BlueTeam.api.routes.websocket import ws_manager
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.database.models.lifecycle import (
    DetectionRecord,
    RiskRecord,
    AlertRecord,
    IncidentRecord,
    ResponseRecord,
)
from BlueTeam.detection.engine import DetectionEngine
from BlueTeam.risk.engine import RiskEngine

logger = logging.getLogger(__name__)


def model_to_schema(model: SecurityEventModel) -> SecurityEvent:
    """Converts a SQLAlchemy SecurityEventModel record into a Pydantic SecurityEvent schema."""
    return SecurityEvent(
        event_id=model.event_id,
        timestamp=model.timestamp,
        source_ip=model.source_ip,
        target_ip=model.target_ip,
        event_type=model.event_type,
        endpoint=model.endpoint,
        method=model.method,
        status_code=model.status_code,
        message=model.message,
        metadata=model.metadata_ or {},
    )


def format_alert_websocket_message(alert: Alert) -> Dict[str, Any]:
    """Formats an Alert object into a JSON-compatible WebSocket broadcast payload."""
    return {
        "type": "security_alert",
        "alert_id": alert.alert_id,
        "risk_level": alert.severity,
        "risk_score": alert.risk_score,
        "attack_types": list(alert.attack_types),
        "source_ips": list(alert.source_ips),
        "rules_triggered": list(alert.rule_names),
        "reasons": list(alert.reasons),
        "timestamp": (
            alert.timestamp.isoformat()
            if hasattr(alert.timestamp, "isoformat")
            else str(alert.timestamp)
        ),
    }


class EventPipelineProcessor:
    """
    Processes ingested security events through Detection -> Risk -> Alert -> Incident -> Response -> WebSocket broadcast pipeline.
    """

    def __init__(
        self,
        detection_engine: Optional[DetectionEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        alert_engine: Optional[AlertEngine] = None,
        incident_manager: Optional[IncidentManager] = None,
        response_engine: Optional[ResponseEngine] = None,
    ):
        self.detection_engine = detection_engine or DetectionEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.alert_engine = alert_engine or AlertEngine()
        self.incident_manager = incident_manager or IncidentManager()
        self.response_engine = response_engine or ResponseEngine()

    def process_event(
        self, current_event: SecurityEvent, db: Session
    ) -> Optional[Alert]:
        """
        Executes pipeline:
        1. Fetch recent events from DB context.
        2. Run DetectionEngine and persist DetectionRecords.
        3. Run RiskEngine and persist RiskRecord.
        4. Run AlertEngine and persist AlertRecord.
        5. Run IncidentManager and persist IncidentRecord.
        6. Run ResponseEngine and persist ResponseRecord.
        Returns generated Alert if any, or None for SAFE results.
        """
        db_events = (
            db.query(SecurityEventModel)
            .order_by(SecurityEventModel.id.desc())
            .limit(100)
            .all()
        )
        events_list = [model_to_schema(e) for e in reversed(db_events)]

        if not any(e.event_id == current_event.event_id for e in events_list):
            events_list.append(current_event)

        # 1. Detection Engine
        detections = self.detection_engine.analyze(events_list)
        for d in detections:
            db.add(DetectionRecord(
                event_id=current_event.event_id,
                detected=d.detected,
                attack_type=d.attack_type,
                source_ip=d.source_ip,
                rule_name=d.rule_name,
                severity=d.severity,
                evidence=list(d.evidence),
                event_ids=list(d.event_ids),
            ))

        # 2. Risk Engine
        risk_result = self.risk_engine.analyze(detections)
        db.add(RiskRecord(
            event_id=current_event.event_id,
            score=risk_result.score,
            risk_level=risk_result.risk_level,
            attack_types=list(risk_result.attack_types),
            reasons=list(risk_result.reasons),
            source_ips=list(risk_result.source_ips),
            rule_names=list(risk_result.rule_names),
            detection_count=risk_result.detection_count,
        ))

        # 3. Alert Engine
        alert = self.alert_engine.create_alert(risk_result, detections)
        if alert:
            db.add(AlertRecord(
                alert_id=alert.alert_id,
                event_id=current_event.event_id,
                timestamp=alert.timestamp,
                severity=alert.severity,
                risk_score=alert.risk_score,
                attack_types=list(alert.attack_types),
                source_ips=list(alert.source_ips),
                rule_names=list(alert.rule_names),
                detection_count=alert.detection_count,
                reasons=list(alert.reasons),
                status=alert.status,
            ))
            
            # 4. Incident Manager
            incident = self.incident_manager.create_incident(alert)
            if incident:
                db.add(IncidentRecord(
                    incident_id=incident.incident_id,
                    alert_id=alert.alert_id,
                    event_id=current_event.event_id,
                    created_at=incident.created_at,
                    updated_at=incident.updated_at,
                    severity=incident.severity,
                    risk_score=incident.risk_score,
                    attack_types=list(incident.attack_types),
                    source_ips=list(incident.source_ips),
                    rule_names=list(incident.rule_names),
                    detection_count=incident.detection_count,
                    reasons=list(incident.reasons),
                    status=incident.status,
                ))

                # 5. Response Engine
                response = self.response_engine.process_incident(incident)
                if response:
                    db.add(ResponseRecord(
                        response_id=response.response_id,
                        incident_id=incident.incident_id,
                        event_id=current_event.event_id,
                        timestamp=response.timestamp,
                        action=response.action,
                        source_ip=response.source_ip,
                        mode=response.mode,
                        status=response.status,
                        reason=response.reason,
                        rule_name=response.rule_name,
                        error=response.error,
                    ))

        return alert

    async def process_and_broadcast(
        self, current_event: SecurityEvent, db: Session
    ) -> Optional[Alert]:
        """
        Runs pipeline and broadcasts generated alert via WebSocket manager safely.
        WebSocket errors are caught and logged so API processing is never disrupted.
        """
        try:
            alert = self.process_event(current_event, db)
            if alert is not None:
                payload = format_alert_websocket_message(alert)
                try:
                    await ws_manager.broadcast(payload)
                except Exception as ws_err:
                    logger.warning(
                        f"WebSocket broadcast delivery failed: {ws_err}. API operation unaffected."
                    )
            return alert
        except Exception as e:
            logger.error(
                f"Error in security event processing pipeline: {e}", exc_info=True
            )
            raise


default_pipeline_processor = EventPipelineProcessor()
