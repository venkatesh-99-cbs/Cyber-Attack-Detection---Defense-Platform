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
    DetectionRecord, RiskRecord, AlertRecord, IncidentRecord, ResponseRecord
)
from BlueTeam.database.models.validation import ValidationRecord

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

def seed_db_for_validation(db):
    from datetime import timedelta
    event_id = "evt-val-1"
    t0 = datetime.now(timezone.utc) - timedelta(seconds=10)
    t1 = t0 + timedelta(seconds=1)
    t2 = t0 + timedelta(seconds=2)
    t3 = t0 + timedelta(seconds=3)
    t4 = t0 + timedelta(seconds=4)
    t5 = t0 + timedelta(seconds=5)

    db.add(SecurityEventModel(
        event_id=event_id, timestamp=t0, source_ip="1.1.1.1", target_ip="10.0.0.1",
        event_type="login_failure", endpoint="/api/login", method="POST",
        status_code=401, message="Failed login", metadata_={}, received_at=t0
    ))
    db.add(DetectionRecord(
        event_id=event_id, detected=True, attack_type="brute_force",
        source_ip="1.1.1.1", rule_name="BruteForceRule", severity="high",
        evidence=[], event_ids=[], created_at=t1
    ))
    db.add(RiskRecord(
        event_id=event_id, score=60, risk_level="SUSPICIOUS",
        attack_types=["brute_force"], reasons=[], source_ips=["1.1.1.1"],
        rule_names=["BruteForceRule"], detection_count=1, created_at=t2
    ))
    db.add(AlertRecord(
        alert_id="alt-1", event_id=event_id, timestamp=t3, severity="SUSPICIOUS",
        risk_score=60, status="ACTIVE", created_at=t3
    ))
    db.add(IncidentRecord(
        incident_id="inc-1", alert_id="alt-1", event_id=event_id,
        created_at=t4, updated_at=t4, severity="SUSPICIOUS", risk_score=60, status="OPEN"
    ))
    db.add(ResponseRecord(
        response_id="res-1", incident_id="inc-1", event_id=event_id,
        timestamp=t5, action="BLOCK_IP", source_ip="1.1.1.1", mode="SIMULATION",
        status="SKIPPED", reason="Test", rule_name="BruteForceRule", error=None, created_at=t5
    ))
    db.commit()
    return event_id

def test_validation_nonexistent_event(client: TestClient):
    res = client.post("/validation", json={"event_id": "nonexistent"})
    assert res.status_code == 404

def test_validation_schema_invalid(client: TestClient):
    res = client.post("/validation", json={"wrong_key": "123"})
    assert res.status_code == 422

def test_validation_overall_pass(client: TestClient):
    db = TestingSessionLocal()
    event_id = seed_db_for_validation(db)
    db.close()

    res = client.post("/validation", json={
        "event_id": event_id,
        "expected": {
            "attack_type": "brute_force",
            "detection": "BruteForceRule",
            "risk_level": "SUSPICIOUS",
            "alert": True,
            "incident": True,
            "response": "SIMULATION"
        }
    })
    assert res.status_code == 201
    data = res.json()
    assert data["overall_result"] == "PASS"
    for k, v in data["checks"].items():
        assert v is True

def test_validation_overall_fail_due_to_risk(client: TestClient):
    db = TestingSessionLocal()
    event_id = seed_db_for_validation(db)
    db.close()

    res = client.post("/validation", json={
        "event_id": event_id,
        "expected": {
            "attack_type": "brute_force",
            "detection": "BruteForceRule",
            "risk_level": "HIGH RISK",  # Database has SUSPICIOUS
            "alert": True,
            "incident": True,
            "response": "SIMULATION"
        }
    })
    assert res.status_code == 201
    data = res.json()
    assert data["overall_result"] == "FAIL"
    assert data["checks"]["risk"] is False
    assert data["checks"]["detection"] is True

def test_validation_missing_optional_stages(client: TestClient):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    event_id = "evt-safe-1"
    db.add(SecurityEventModel(
        event_id=event_id, timestamp=now, source_ip="1.1.1.1", target_ip="10.0.0.1",
        event_type="http_request", message="Health", metadata_={}, received_at=now
    ))
    # Add Risk only, SAFE
    db.add(RiskRecord(
        event_id=event_id, score=0, risk_level="SAFE",
        attack_types=[], reasons=[], source_ips=[],
        rule_names=[], detection_count=0
    ))
    db.commit()
    db.close()

    res = client.post("/validation", json={
        "event_id": event_id,
        "expected": {
            "attack_type": "none",
            "detection": None,
            "risk_level": "SAFE",
            "alert": False,
            "incident": False,
            "response": None
        }
    })
    assert res.status_code == 201
    data = res.json()
    assert data["overall_result"] == "PASS"
    assert data["checks"]["risk"] is True
    assert data["checks"]["alert"] is True
    assert data["checks"]["incident"] is True

def test_validation_persistence_and_retrieval(client: TestClient):
    db = TestingSessionLocal()
    event_id = seed_db_for_validation(db)
    db.close()

    post_res = client.post("/validation", json={"event_id": event_id})
    assert post_res.status_code == 201
    val_id = post_res.json()["validation_id"]

    get_res = client.get(f"/validation/{val_id}")
    assert get_res.status_code == 200
    assert get_res.json()["validation_id"] == val_id

    list_res = client.get("/validation")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

def test_replay_is_readonly_and_ordered(client: TestClient):
    db = TestingSessionLocal()
    event_id = seed_db_for_validation(db)
    db.close()

    # Create validation
    post_res = client.post("/validation", json={"event_id": event_id})
    val_id = post_res.json()["validation_id"]

    replay_res = client.get(f"/validation/{val_id}/replay")
    assert replay_res.status_code == 200
    timeline = replay_res.json()["timeline"]

    # Must contain 7 stages (EVENT, DETECTION, RISK, ALERT, INCIDENT, RESPONSE, VALIDATION)
    assert len(timeline) == 7
    stages = [item["stage"] for item in timeline]
    assert stages == ["EVENT", "DETECTION", "RISK", "ALERT", "INCIDENT", "RESPONSE", "VALIDATION"]

    # Calling replay again should not create duplicate lifecycle records
    replay_res2 = client.get(f"/validation/{val_id}/replay")
    assert len(replay_res2.json()["timeline"]) == 7
