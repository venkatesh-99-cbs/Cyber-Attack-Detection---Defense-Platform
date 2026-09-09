from datetime import datetime, timezone
from typing import Generator

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from BlueTeam.api.schemas.event import (
    EventListResponse,
    SecurityEvent,
    SecurityEventResponse,
    TargetSecurityEvent,
)
from BlueTeam.database.database import SessionLocal
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.ingestion.processor import default_pipeline_processor

router = APIRouter()


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and ensure it is closed after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def normalize_target_event(target_evt: TargetSecurityEvent) -> SecurityEvent:
    """
    Normalizes a TargetSecurityEvent payload into the internal SecurityEvent domain schema.
    """
    evt_type = target_evt.event_type
    lower_type = evt_type.lower()
    lower_path = (target_evt.path or "").lower()

    if lower_type in ("login_failure", "login_failed", "failed_login"):
        evt_type = "login_failure"
    elif lower_type in ("connection_attempt", "port_scan"):
        evt_type = "connection_attempt"
    elif lower_type == "http_request":
        if target_evt.status_code == 401 and any(
            p in lower_path for p in ["/login", "/signin", "/auth"]
        ):
            evt_type = "login_failure"

    metadata = {
        "source": target_evt.source,
        "params": target_evt.params or {},
        "session_id": target_evt.session_id,
        "target_attack_type": target_evt.attack_type,
        "target_result": target_evt.result,
        "target_severity": target_evt.severity,
        "target_reason": target_evt.reason,
    }

    path_str = target_evt.path or "/"
    method_str = target_evt.method or "REQ"
    if target_evt.status_code is not None:
        message_str = f"Target event: {method_str} {path_str} ({target_evt.status_code})"
    else:
        message_str = f"Target event: {method_str} {path_str}"

    return SecurityEvent(
        event_id=target_evt.event_id,
        timestamp=target_evt.timestamp,
        source_ip=target_evt.source_ip,
        target_ip=target_evt.target_ip,
        event_type=evt_type,
        endpoint=target_evt.path,
        method=target_evt.method,
        status_code=target_evt.status_code,
        message=message_str,
        metadata=metadata,
    )


@router.post("/events", status_code=status.HTTP_201_CREATED)
async def ingest_event(event: SecurityEvent, db: Session = Depends(get_db)):
    """
    Receive a security event from the Target application.

    - Validates the payload using the SecurityEvent Pydantic schema.
    - Persists the event to the SQLite security_events table.
    - Returns 409 Conflict if the event_id already exists.
    - Executes Detection -> Risk -> Alert -> WebSocket broadcast pipeline.
    - Returns 201 Created on success.
    """
    db_event = SecurityEventModel(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        target_ip=event.target_ip,
        event_type=event.event_type,
        endpoint=event.endpoint,
        method=event.method,
        status_code=event.status_code,
        message=event.message,
        metadata_=event.metadata,
        received_at=datetime.now(timezone.utc),
    )
    db.add(db_event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event with event_id '{event.event_id}' already exists.",
        )

    # Execute Detection -> Risk -> Alert -> WebSocket pipeline safely
    await default_pipeline_processor.process_and_broadcast(event, db)
    
    db.commit()
    db.refresh(db_event)

    return {
        "status": "accepted",
        "event_id": db_event.event_id,
        "id": db_event.id,
        "received_at": db_event.received_at.isoformat(),
    }


@router.post("/api/events", status_code=status.HTTP_201_CREATED)
async def ingest_target_event(
    target_event: TargetSecurityEvent, db: Session = Depends(get_db)
):
    """
    Compatibility ingestion endpoint for Target application forwarding to POST /api/events.

    - Validates payload using TargetSecurityEvent schema.
    - Normalizes payload into SecurityEvent domain schema.
    - Reuses existing ingestion pipeline (persists event & runs pipeline).
    - Returns 409 Conflict if event_id already exists.
    - Returns 201 Created on success.
    """
    event = normalize_target_event(target_event)
    return await ingest_event(event, db)



@router.get("/events", response_model=EventListResponse)
def get_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Retrieve paginated security events from SQLite database.

    - Ordered by event ID descending (most recent first).
    """
    total = db.query(func.count(SecurityEventModel.id)).scalar() or 0
    db_events = (
        db.query(SecurityEventModel)
        .order_by(SecurityEventModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    events = [
        SecurityEventResponse(
            id=e.id,
            event_id=e.event_id,
            timestamp=e.timestamp,
            source_ip=e.source_ip,
            target_ip=e.target_ip,
            event_type=e.event_type,
            endpoint=e.endpoint,
            method=e.method,
            status_code=e.status_code,
            message=e.message,
            metadata=e.metadata_ or {},
            received_at=e.received_at,
        )
        for e in db_events
    ]

    return EventListResponse(
        total=total,
        limit=limit,
        offset=offset,
        events=events,
    )
