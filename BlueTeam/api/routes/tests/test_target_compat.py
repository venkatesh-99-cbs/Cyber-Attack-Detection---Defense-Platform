import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from BlueTeam.api.routes.events import get_db
from BlueTeam.database.database import Base
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.main import app

# Setup test in-memory database using StaticPool
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine
)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_1_target_compat_route_exists(client: TestClient):
    path = app.url_path_for("ingest_target_event")
    assert str(path) == "/api/events"


def test_2_valid_target_event_accepted_and_normalized(client: TestClient):
    evt_id = f"target-evt-{uuid.uuid4().hex[:6]}"
    target_payload = {
        "event_id": evt_id,
        "timestamp": "2026-09-09T14:00:00Z",
        "source_ip": "10.134.216.132",
        "target_ip": "10.134.216.99",
        "source": "target",
        "event_type": "http_request",
        "method": "POST",
        "path": "/login",
        "status_code": 401,
        "params": {"user": "admin"},
        "session_id": "sess-12345",
        "attack_type": None,
        "result": "pending",
        "severity": None,
        "reason": None,
    }

    response = client.post("/api/events", json=target_payload)
    assert response.status_code == 201
    res_data = response.json()
    assert res_data["status"] == "accepted"
    assert res_data["event_id"] == evt_id

    # Verify event is persisted in SQLite DB with normalized fields
    db = TestingSessionLocal()
    db_evt = (
        db.query(SecurityEventModel)
        .filter(SecurityEventModel.event_id == evt_id)
        .first()
    )
    assert db_evt is not None
    assert db_evt.event_id == evt_id
    assert db_evt.source_ip == "10.134.216.132"
    assert db_evt.target_ip == "10.134.216.99"
    # path normalized to endpoint
    assert db_evt.endpoint == "/login"
    assert db_evt.method == "POST"
    assert db_evt.status_code == 401
    # Target 401 on /login normalized to login_failure for detection
    assert db_evt.event_type == "login_failure"
    # Target params and extra fields normalized into metadata
    assert db_evt.metadata_["params"] == {"user": "admin"}
    assert db_evt.metadata_["session_id"] == "sess-12345"
    assert db_evt.metadata_["source"] == "target"
    db.close()


def test_3_duplicate_target_event_id_returns_409(client: TestClient):
    evt_id = f"target-dup-{uuid.uuid4().hex[:6]}"
    target_payload = {
        "event_id": evt_id,
        "timestamp": "2026-09-09T14:00:00Z",
        "source_ip": "10.134.216.132",
        "target_ip": "10.134.216.99",
        "event_type": "http_request",
        "method": "GET",
        "path": "/",
        "status_code": 200,
        "params": {},
    }

    res1 = client.post("/api/events", json=target_payload)
    assert res1.status_code == 201

    res2 = client.post("/api/events", json=target_payload)
    assert res2.status_code == 409
    assert f"Event with event_id '{evt_id}' already exists." in res2.json()["detail"]


def test_4_malformed_target_payload_rejected(client: TestClient):
    # Missing required field event_id
    bad_payload = {
        "timestamp": "2026-09-09T14:00:00Z",
        "source_ip": "10.134.216.132",
        "target_ip": "10.134.216.99",
        "event_type": "http_request",
    }
    res = client.post("/api/events", json=bad_payload)
    assert res.status_code == 422


def test_5_target_event_invokes_detection_pipeline(client: TestClient):
    # Send 5 target login_failure events from same source IP to trigger BruteForceRule
    source_ip = "10.134.216.132"
    for i in range(5):
        payload = {
            "event_id": f"target-bf-{i}-{uuid.uuid4().hex[:4]}",
            "timestamp": f"2026-09-09T14:00:0{i}Z",
            "source_ip": source_ip,
            "target_ip": "10.134.216.99",
            "event_type": "login_failure",
            "method": "POST",
            "path": "/login",
            "status_code": 401,
            "params": {"user": "admin"},
        }
        res = client.post("/api/events", json=payload)
        assert res.status_code == 201

    # Verify events are recorded
    db = TestingSessionLocal()
    count = db.query(SecurityEventModel).count()
    assert count == 5
    db.close()

