from sqlalchemy.orm import Session
from BlueTeam.database.models.event import SecurityEventModel
from BlueTeam.database.models.lifecycle import (
    DetectionRecord, RiskRecord, AlertRecord, IncidentRecord, ResponseRecord
)
from BlueTeam.database.models.validation import ValidationRecord

def replay_lifecycle(db: Session, event_id: str, validation_id: str = None):
    """
    Reconstructs the chronological lifecycle sequence for a given event.
    Replay is completely READ-ONLY.
    """
    event = db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).first()
    if not event:
        return None

    timeline = []
    
    # 1. EVENT
    timeline.append({
        "stage": "EVENT",
        "timestamp": event.timestamp.isoformat(),
        "status": "RECORDED",
        "detail": event.event_type
    })
    
    # 2. DETECTION
    detections = db.query(DetectionRecord).filter(DetectionRecord.event_id == event_id).all()
    for d in detections:
        timeline.append({
            "stage": "DETECTION",
            "timestamp": d.created_at.isoformat(),
            "status": "DETECTED" if d.detected else "EVALUATED",
            "rule": d.rule_name
        })
        
    # 3. RISK
    risks = db.query(RiskRecord).filter(RiskRecord.event_id == event_id).all()
    for r in risks:
        timeline.append({
            "stage": "RISK",
            "timestamp": r.created_at.isoformat(),
            "status": r.risk_level,
            "score": r.score
        })
        
    # 4. ALERT
    alerts = db.query(AlertRecord).filter(AlertRecord.event_id == event_id).all()
    for a in alerts:
        timeline.append({
            "stage": "ALERT",
            "timestamp": a.created_at.isoformat(),
            "status": a.status
        })
        
    # 5. INCIDENT
    incidents = db.query(IncidentRecord).filter(IncidentRecord.event_id == event_id).all()
    for i in incidents:
        timeline.append({
            "stage": "INCIDENT",
            "timestamp": i.created_at.isoformat(),
            "status": i.status
        })
        
    # 6. RESPONSE
    responses = db.query(ResponseRecord).filter(ResponseRecord.event_id == event_id).all()
    for res in responses:
        timeline.append({
            "stage": "RESPONSE",
            "timestamp": res.created_at.isoformat(),
            "status": res.status,
            "mode": res.mode
        })
        
    # 7. VALIDATION
    query = db.query(ValidationRecord).filter(ValidationRecord.event_id == event_id)
    if validation_id:
        query = query.filter(ValidationRecord.validation_id == validation_id)
    validations = query.all()
    
    for v in validations:
        timeline.append({
            "stage": "VALIDATION",
            "timestamp": v.created_at.isoformat(),
            "status": v.overall_result,
            "validation_id": v.validation_id
        })
        
    # Sort chronologically
    timeline.sort(key=lambda x: x["timestamp"])
    
    return {
        "event_id": event_id,
        "timeline": timeline
    }

