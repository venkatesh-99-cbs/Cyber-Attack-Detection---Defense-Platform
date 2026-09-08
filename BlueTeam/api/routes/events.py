from datetime import datetime, timezone
from typing import Generator

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from BlueTeam.api.schemas.event import SecurityEvent
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
