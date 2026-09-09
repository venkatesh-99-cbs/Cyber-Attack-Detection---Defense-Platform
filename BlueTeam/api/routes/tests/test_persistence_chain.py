import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from BlueTeam.main import app
from BlueTeam.database.database import Base
from BlueTeam.api.routes.events import get_db
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.database.models.lifecycle import (
    DetectionRecord,
    RiskRecord,
    AlertRecord,
    IncidentRecord,
    ResponseRecord,
)

# Setup test database
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

def test_full_lifecycle_persistence(client: TestClient):
    """
    Verifies that a series of events successfully triggers the pipeline
    and persists Detection, Risk, Alert, Incident, and Response records.
    """
    # Send 5 failed login attempts to trigger brute force rule
    event_ids = []
    for i in range(5):
        event_id = f"evt-brute-{i}"
        event_ids.append(event_id)
        payload = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.99",
            "target_ip": "10.0.0.1",
            "event_type": "login_failure",
            "endpoint": "/api/login",
            "method": "POST",
            "status_code": 401,
            "message": "Failed login attempt",
            "metadata": {"source": "target"}
        }
        res = client.post("/events", json=payload)
        assert res.status_code == 201

    db = TestingSessionLocal()
    
    # 1. Verify Event records
    events = db.query(SecurityEventModel).all()
    assert len(events) == 5

    # 2. Verify Detection records
    # The 5th event should trigger brute force detection
    detections = db.query(DetectionRecord).filter_by(event_id="evt-brute-4").all()
    assert len(detections) > 0
    assert any(d.rule_name == "BruteForceRule" and d.detected for d in detections)

    # 3. Verify Risk records
    risks = db.query(RiskRecord).filter_by(event_id="evt-brute-4").all()
    assert len(risks) == 1
    assert risks[0].risk_level in ("SUSPICIOUS", "HIGH_RISK")

    # 4. Verify Alert records
    alerts = db.query(AlertRecord).filter_by(event_id="evt-brute-4").all()
    assert len(alerts) == 1
    assert alerts[0].status == "ACTIVE"

    # 5. Verify Incident records
    incidents = db.query(IncidentRecord).filter_by(event_id="evt-brute-4").all()
    assert len(incidents) == 1
    assert incidents[0].status == "OPEN"

    # 6. Verify Response records
    responses = db.query(ResponseRecord).filter_by(event_id="evt-brute-4").all()
    assert len(responses) == 1
    # Mode is SIMULATION by default
    assert responses[0].mode == "SIMULATION"
    
    db.close()

def test_safe_event_does_not_create_lifecycle_records(client: TestClient):
    """
    Verifies that a SAFE event does not create fake alerts, incidents, or responses.
    """
    payload = {
        "event_id": "evt-safe-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.0.1",
        "event_type": "http_request",
        "endpoint": "/health",
        "method": "GET",
        "status_code": 200,
        "message": "Health check",
        "metadata": {}
    }
    res = client.post("/events", json=payload)
    assert res.status_code == 201

    db = TestingSessionLocal()
    
    # Detection and risk records are always created to log the analysis
    detections = db.query(DetectionRecord).filter_by(event_id="evt-safe-1").all()
    # Depending on rule config, there might be no detection or a "SAFE" detection.
    # Risk record is always created.
    risks = db.query(RiskRecord).filter_by(event_id="evt-safe-1").all()
    assert len(risks) == 1
    assert risks[0].risk_level == "SAFE"

    # BUT Alerts, Incidents, and Responses should NOT be created for a SAFE event.
    alerts = db.query(AlertRecord).filter_by(event_id="evt-safe-1").all()
    assert len(alerts) == 0

    incidents = db.query(IncidentRecord).filter_by(event_id="evt-safe-1").all()
    assert len(incidents) == 0

    responses = db.query(ResponseRecord).filter_by(event_id="evt-safe-1").all()
    assert len(responses) == 0

    db.close()

