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
        db.commit()
        db.refresh(db_event)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event with event_id '{event.event_id}' already exists.",
        )

    # Execute Detection -> Risk -> Alert -> WebSocket pipeline safely
    await default_pipeline_processor.process_and_broadcast(event, db)

    return {
        "status": "accepted",
        "event_id": db_event.event_id,
        "id": db_event.id,
        "received_at": db_event.received_at.isoformat(),
    }


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
