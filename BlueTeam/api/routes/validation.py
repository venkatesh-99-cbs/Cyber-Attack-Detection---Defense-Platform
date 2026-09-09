from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from BlueTeam.api.routes.events import get_db
from BlueTeam.api.schemas.validation import (
    ValidationRequestSchema, ValidationResponseSchema, ReplayResponseSchema
)
from BlueTeam.database.models.validation import ValidationRecord
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.validation.engine import ValidationEngine
from BlueTeam.validation.replay import replay_lifecycle
from BlueTeam.validation.config import ExpectedResult

router = APIRouter()
validation_engine = ValidationEngine()

@router.post("/validation", response_model=ValidationResponseSchema, status_code=status.HTTP_201_CREATED)
def create_validation(request: ValidationRequestSchema, db: Session = Depends(get_db)):
    """
    Creates a validation record evaluating the lifecycle of an event.
    """
    event = db.query(SecurityEventModel).filter(SecurityEventModel.event_id == request.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    expected_config = None
    if request.expected:
        expected_config = ExpectedResult(
            attack_type=request.expected.attack_type,
            detection=request.expected.detection,
            risk_level=request.expected.risk_level,
            alert=request.expected.alert,
            incident=request.expected.incident,
            response=request.expected.response
        )
    
    # If expected_config is None, engine will try to fetch default based on event metadata or we must provide attack_type
    attack_type = expected_config.attack_type if expected_config else event.metadata_.get("target_attack_type", "unknown")
    
    record = validation_engine.validate(db, event_id=request.event_id, attack_type=attack_type, custom_expected=expected_config)
    
    checks = {
        "detection": record.detection_match,
        "risk": record.risk_match,
        "alert": record.alert_match,
        "incident": record.incident_match,
        "response": record.response_match
    }

    return ValidationResponseSchema(
        validation_id=record.validation_id,
        event_id=record.event_id,
        attack_type=record.attack_type,
        checks=checks,
        overall_result=record.overall_result,
        reasons=record.reasons,
        created_at=record.created_at
    )

@router.get("/validation", response_model=List[ValidationResponseSchema])
def list_validations(db: Session = Depends(get_db)):
    """
    List persisted validation records.
    """
    records = db.query(ValidationRecord).order_by(ValidationRecord.id.desc()).all()
    results = []
    for record in records:
        checks = {
            "detection": record.detection_match,
            "risk": record.risk_match,
            "alert": record.alert_match,
            "incident": record.incident_match,
            "response": record.response_match
        }
        results.append(ValidationResponseSchema(
            validation_id=record.validation_id,
            event_id=record.event_id,
            attack_type=record.attack_type,
            checks=checks,
            overall_result=record.overall_result,
            reasons=record.reasons,
            created_at=record.created_at
        ))
    return results

@router.get("/validation/{validation_id}", response_model=ValidationResponseSchema)
def get_validation(validation_id: str, db: Session = Depends(get_db)):
    """
    Get a specific validation record.
    """
    record = db.query(ValidationRecord).filter(ValidationRecord.validation_id == validation_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Validation record not found.")

    checks = {
        "detection": record.detection_match,
        "risk": record.risk_match,
        "alert": record.alert_match,
        "incident": record.incident_match,
        "response": record.response_match
    }
    return ValidationResponseSchema(
        validation_id=record.validation_id,
        event_id=record.event_id,
        attack_type=record.attack_type,
        checks=checks,
        overall_result=record.overall_result,
        reasons=record.reasons,
        created_at=record.created_at
    )

@router.get("/validation/{validation_id}/replay", response_model=ReplayResponseSchema)
def get_validation_replay(validation_id: str, db: Session = Depends(get_db)):
    """
    Return the read-only reconstructed lifecycle timeline.
    """
    record = db.query(ValidationRecord).filter(ValidationRecord.validation_id == validation_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Validation record not found.")

    timeline = replay_lifecycle(db, event_id=record.event_id, validation_id=validation_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Lifecycle data not found for replay.")

    return ReplayResponseSchema(
        validation_id=validation_id,
        event_id=record.event_id,
        timeline=timeline["timeline"]
    )

