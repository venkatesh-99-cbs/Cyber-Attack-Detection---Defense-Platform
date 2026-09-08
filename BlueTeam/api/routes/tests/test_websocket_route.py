import uuid
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from BlueTeam.main import app
from BlueTeam.api.routes.websocket import ws_manager


def test_1_fastapi_app_imports_successfully():
    assert app is not None
    assert isinstance(app, FastAPI)
    assert app.title == "CyberSentinel Blue Team API"


def test_2_health_endpoint_still_works():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_3_events_endpoint_still_works():
    unique_evt_id = f"route-test-evt-{uuid.uuid4().hex[:6]}"
    with TestClient(app) as client:
        event_payload = {
            "event_id": unique_evt_id,
            "timestamp": "2026-09-08T15:10:20Z",
            "source_ip": "192.168.1.50",
            "target_ip": "192.168.1.60",
            "event_type": "login_failure",
            "endpoint": "/login",
            "method": "POST",
            "status_code": 401,
            "message": "Failed password attempt",
            "metadata": {},
        }
        response = client.post("/events", json=event_payload)
        assert response.status_code == 201
        assert response.json()["status"] == "accepted"
        assert response.json()["event_id"] == unique_evt_id


def test_4_websocket_endpoint_exists():
    path = app.url_path_for("websocket_endpoint")
    assert str(path) == "/ws"


def test_5_and_6_websocket_client_connects_and_registers():
    with TestClient(app) as client:
        initial_count = ws_manager.active_count
        with client.websocket_connect("/ws") as websocket:
            # Client connected and registered in ws_manager
            assert ws_manager.active_count == initial_count + 1


def test_7_client_disconnect_removes_connection():
    with TestClient(app) as client:
        initial_count = ws_manager.active_count
        with client.websocket_connect("/ws") as websocket:
            assert ws_manager.active_count == initial_count + 1
        # Context exit disconnects client
        assert ws_manager.active_count == initial_count


def test_8_multiple_clients_can_connect():
    with TestClient(app) as client:
        initial_count = ws_manager.active_count
        with client.websocket_connect("/ws") as ws1:
            with client.websocket_connect("/ws") as ws2:
                assert ws_manager.active_count == initial_count + 2
        assert ws_manager.active_count == initial_count


def test_9_one_client_disconnect_does_not_affect_another():
    with TestClient(app) as client:
        initial_count = ws_manager.active_count
        with client.websocket_connect("/ws") as ws1:
            assert ws_manager.active_count == initial_count + 1
            with client.websocket_connect("/ws") as ws2:
                assert ws_manager.active_count == initial_count + 2
            # ws2 disconnected, ws1 remains connected
            assert ws_manager.active_count == initial_count + 1
        # ws1 disconnected
        assert ws_manager.active_count == initial_count

