from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from BlueTeam.api.routes.events import get_db
from BlueTeam.api.schemas.incident import IncidentListResponse, IncidentResponse
from BlueTeam.database.models.lifecycle import IncidentRecord

router = APIRouter()


@router.get("/incidents", response_model=IncidentListResponse)
def get_incidents(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Retrieve paginated security incidents from the database.
    """
    db_incidents = (
        db.query(IncidentRecord)
        .order_by(IncidentRecord.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    incidents = [
        IncidentResponse(
            incident_id=inc.incident_id,
            alert_id=inc.alert_id,
            event_id=inc.event_id,
            created_at=inc.created_at_dt,
            updated_at=inc.updated_at,
            severity=inc.severity,
            risk_score=inc.risk_score,
            attack_types=inc.attack_types or [],
            source_ips=inc.source_ips or [],
            rule_names=inc.rule_names or [],
            detection_count=inc.detection_count,
            reasons=inc.reasons or [],
            status=inc.status,
        )
        for inc in db_incidents
    ]

    return IncidentListResponse(incidents=incidents)

