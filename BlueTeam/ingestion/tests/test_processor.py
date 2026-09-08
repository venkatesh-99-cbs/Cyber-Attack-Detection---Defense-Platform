import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from fastapi.testclient import TestClient

from BlueTeam.api.routes.websocket import ws_manager
from BlueTeam.api.schemas.event import SecurityEvent
from BlueTeam.database.database import SessionLocal, init_db
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.ingestion.processor import (
    EventPipelineProcessor,
    format_alert_websocket_message,
)
from BlueTeam.main import app


@pytest.fixture(autouse=True)
def clean_db():
    """Ensure database is initialized and clear event table for isolated pipeline testing."""
    init_db()
    db = SessionLocal()
    try:
        db.query(SecurityEventModel).delete()
        db.commit()
    finally:
        db.close()


def make_event(
    event_id: str = None,
    event_type: str = "login_failure",
    source_ip: str = "192.168.1.100",
    target_ip: str = "192.168.1.200",
    endpoint: str = "/login",
    message: str = "Failed login attempt",
    metadata: dict = None,
) -> SecurityEvent:
    if event_id is None:
        event_id = f"proc-evt-{uuid.uuid4().hex[:6]}"
    if metadata is None:
        metadata = {}
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source_ip=source_ip,
        target_ip=target_ip,
        event_type=event_type,
        endpoint=endpoint,
        method="POST",
        status_code=401,
        message=message,
        metadata=metadata,
    )


# =====================================================================
# STAGE 3 PIPELINE & WEBSOCKET BROADCAST TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_1_safe_event_does_not_generate_alert_broadcast():
    processor = EventPipelineProcessor()
    db = SessionLocal()
    safe_event = make_event(event_type="http_request", message="Normal user request")

    with patch.object(ws_manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
        alert = await processor.process_and_broadcast(safe_event, db)
        assert alert is None
        mock_broadcast.assert_not_called()
    db.close()


@pytest.mark.asyncio
async def test_2_and_3_suspicious_or_high_risk_alert_produces_websocket_message():
    processor = EventPipelineProcessor()
    db = SessionLocal()
    sqli_event = make_event(
        event_type="http_request",
        source_ip="10.0.0.99",
        endpoint="/api/users?id=1' OR 1=1--",
        message="SQL injection payload",
    )

    with patch.object(ws_manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
        alert = await processor.process_and_broadcast(sqli_event, db)
        assert alert is not None
        assert alert.severity in ("SUSPICIOUS", "HIGH RISK")
        mock_broadcast.assert_awaited_once()

        payload = mock_broadcast.call_args[0][0]
        # Test 4: Payload is JSON-compatible
        json_str = json.dumps(payload)
        assert isinstance(json_str, str)

        # Test 5 & 6 & 7 & 8 & 9: Preserves alert ID, risk level, attack types, evidence
        assert payload["type"] == "security_alert"
        assert payload["alert_id"] == alert.alert_id
        assert payload["risk_level"] == alert.severity
        assert payload["risk_score"] == alert.risk_score
        assert "sql_injection" in payload["attack_types"]
        assert "10.0.0.99" in payload["source_ips"]
        assert any("SQLInjectionRule" in r for r in payload["rules_triggered"])
        assert any("SQL injection" in r for r in payload["reasons"])
    db.close()


@pytest.mark.asyncio
async def test_10_websocket_send_failure_does_not_crash_event_processing():
    processor = EventPipelineProcessor()
    db = SessionLocal()
    sqli_event = make_event(
        event_type="http_request",
        endpoint="/admin' OR 1=1--",
    )

    with patch.object(
        ws_manager,
        "broadcast",
        new_callable=AsyncMock,
        side_effect=RuntimeError("WebSocket delivery error"),
    ):
        # Should not raise exception
        alert = await processor.process_and_broadcast(sqli_event, db)
        assert alert is not None
    db.close()


@pytest.mark.asyncio
async def test_11_multiple_connected_clients_receive_broadcast():
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            with client.websocket_connect("/ws") as ws2:
                event_payload = {
                    "event_id": f"api-broadcast-{uuid.uuid4().hex[:6]}",
                    "timestamp": "2026-09-08T15:10:20Z",
                    "source_ip": "192.168.1.77",
                    "target_ip": "192.168.1.88",
                    "event_type": "http_request",
                    "endpoint": "/login?user=admin' OR 1=1--",
                    "method": "POST",
                    "status_code": 401,
                    "message": "SQLi attempt",
                    "metadata": {},
                }
                response = client.post("/events", json=event_payload)
                assert response.status_code == 201

                # Verify both clients received broadcast message
                msg1 = ws1.receive_json()
                msg2 = ws2.receive_json()
                assert msg1["type"] == "security_alert"
                assert msg2["type"] == "security_alert"
                assert msg1["alert_id"] == msg2["alert_id"]
                assert "sql_injection" in msg1["attack_types"]

