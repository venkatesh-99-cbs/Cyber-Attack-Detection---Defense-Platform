from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from BlueTeam.api.routes.events import get_db
from BlueTeam.api.schemas.alert import AlertListResponse, AlertResponse
from BlueTeam.database.models.lifecycle import AlertRecord

router = APIRouter()


@router.get("/alerts", response_model=AlertListResponse)
def get_alerts(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Retrieve paginated security alerts from the database.
    """
    db_alerts = (
        db.query(AlertRecord)
        .order_by(AlertRecord.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    alerts = [
        AlertResponse(
            alert_id=a.alert_id,
            event_id=a.event_id,
            timestamp=a.timestamp,
            severity=a.severity,
            risk_score=a.risk_score,
            attack_types=a.attack_types or [],
            source_ips=a.source_ips or [],
            rule_names=a.rule_names or [],
            detection_count=a.detection_count,
            reasons=a.reasons or [],
            status=a.status,
            created_at=a.created_at,
        )
        for a in db_alerts
    ]

    return AlertListResponse(alerts=alerts)

