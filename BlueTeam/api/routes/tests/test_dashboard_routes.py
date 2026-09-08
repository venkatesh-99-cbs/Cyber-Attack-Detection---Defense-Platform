from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from BlueTeam.api.routes.events import get_db
from BlueTeam.database.database import Base
from BlueTeam.database.models.event import SecurityEventModel  # noqa: F401
from BlueTeam.main import app

# Setup test shared in-memory database using StaticPool
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


def test_get_events_empty(client: TestClient):
    response = client.get("/events")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["limit"] == 50
    assert data["offset"] == 0
    assert data["events"] == []


def test_get_events_pagination_and_ordering(client: TestClient):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    for i in range(1, 15):
        db.add(
            SecurityEventModel(
                event_id=f"evt-{i:03d}",
                timestamp=now,
                source_ip=f"192.168.1.{i}",
                target_ip="10.0.0.1",
                event_type="login_failure" if i % 2 == 0 else "http_request",
                endpoint="/api/login",
                method="POST",
                status_code=401 if i % 2 == 0 else 200,
                message=f"Test message {i}",
                metadata_={},
                received_at=now,
            )
        )
    db.commit()
    db.close()

    # Default pagination (limit 50, offset 0)
    res = client.get("/events")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 14
    assert len(data["events"]) == 14
    # Check ordering: id desc -> most recent first
    assert data["events"][0]["event_id"] == "evt-014"
    assert data["events"][-1]["event_id"] == "evt-001"

    # Custom limit and offset
    res_page = client.get("/events?limit=5&offset=5")
    assert res_page.status_code == 200
    page_data = res_page.json()
    assert page_data["total"] == 14
    assert page_data["limit"] == 5
    assert page_data["offset"] == 5
    assert len(page_data["events"]) == 5
    assert page_data["events"][0]["event_id"] == "evt-009"


def test_get_dashboard_summary(client: TestClient):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    db.add(
        SecurityEventModel(
            event_id="evt-summary-1",
            timestamp=now,
            source_ip="10.0.0.50",
            target_ip="10.0.0.1",
            event_type="login_failure",
            message="Failed login attempt",
            received_at=now,
        )
    )
    db.commit()
    db.close()

    res = client.get("/dashboard/summary")
    assert res.status_code == 200
    data = res.json()

    assert data["total_events"] == 1
    assert data["data_availability"]["events_persisted"] is True
    assert data["data_availability"]["alerts_persisted"] is False
    assert data["data_availability"]["incidents_persisted"] is False
    assert data["data_availability"]["risk_analysis_persisted"] is False
    assert data["data_availability"]["detection_results_persisted"] is False

    # Honest data representation: non-persisted metrics MUST be null/None
    assert data["active_alerts_count"] is None
    assert data["open_incidents_count"] is None
    assert data["system_status"] is None
    assert "not persisted" in data["system_status_note"].lower()


def test_get_dashboard_statistics_terminology_preservation(client: TestClient):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)

    # Ingest events with exact platform contract event_types
    events = [
        ("login_failure", "192.168.1.10"),
        ("login_failure", "192.168.1.10"),
        ("connection_attempt", "192.168.1.20"),
        ("http_request", "192.168.1.10"),
        ("http_request", "192.168.1.30"),
    ]

    for idx, (evt_type, ip) in enumerate(events, 1):
        db.add(
            SecurityEventModel(
                event_id=f"evt-stat-{idx}",
                timestamp=now,
                source_ip=ip,
                target_ip="10.0.0.1",
                event_type=evt_type,
                message=f"Event {idx}",
                received_at=now,
            )
        )
    db.commit()
    db.close()

    res = client.get("/dashboard/statistics")
    assert res.status_code == 200
    data = res.json()

    assert data["total_events"] == 5
    # Verify exact terminology preservation: 'login_failure', 'connection_attempt', 'http_request'
    assert data["events_by_type"] == {
        "login_failure": 2,
        "connection_attempt": 1,
        "http_request": 2,
    }

    # Top source IPs ranking
    assert len(data["top_source_ips"]) == 3
    assert data["top_source_ips"][0]["source_ip"] == "192.168.1.10"
    assert data["top_source_ips"][0]["count"] == 3

    # Honest data representation for attack count
    assert data["detected_attack_count"] is None
    assert "not persisted" in data["detected_attack_count_note"].lower()


def test_get_alerts_persistence_not_configured(client: TestClient):
    res = client.get("/alerts")
    assert res.status_code == 200
    data = res.json()

    assert data["persisted"] is False
    assert data["status"] == "PERSISTENCE_NOT_CONFIGURED"
    assert data["alerts"] is None
    assert "not persisted in SQLite" in data["message"]


def test_get_incidents_persistence_not_configured(client: TestClient):
    res = client.get("/incidents")
    assert res.status_code == 200
    data = res.json()

    assert data["persisted"] is False
    assert data["status"] == "PERSISTENCE_NOT_CONFIGURED"
    assert data["incidents"] is None
    assert "not persisted in SQLite" in data["message"]

