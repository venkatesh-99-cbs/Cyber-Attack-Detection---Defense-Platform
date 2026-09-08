import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from BlueTeam.alerts.engine import Alert, AlertEngine
from BlueTeam.api.routes.websocket import ws_manager
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.database.models.event import SecurityEventModel
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
    Processes ingested security events through Detection -> Risk -> Alert -> WebSocket broadcast pipeline.
    """

    def __init__(
        self,
        detection_engine: Optional[DetectionEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        alert_engine: Optional[AlertEngine] = None,
    ):
        self.detection_engine = detection_engine or DetectionEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.alert_engine = alert_engine or AlertEngine()

    def process_event(
        self, current_event: SecurityEvent, db: Session
    ) -> Optional[Alert]:
        """
        Executes pipeline:
        1. Fetch recent events from DB context.
        2. Run DetectionEngine.
        3. Run RiskEngine.
        4. Run AlertEngine.
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

        # 2. Risk Engine
        risk_result = self.risk_engine.analyze(detections)

        # 3. Alert Engine
        alert = self.alert_engine.create_alert(risk_result, detections)
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
            return None


default_pipeline_processor = EventPipelineProcessor()

