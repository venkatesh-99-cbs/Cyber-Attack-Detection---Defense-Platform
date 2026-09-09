from typing import Generator

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from BlueTeam.api.routes.events import get_db
from BlueTeam.api.schemas.dashboard import (
    DataAvailabilityStatus,
    DashboardStatsResponse,
    DashboardSummaryResponse,
    TopSourceIP,
)
from BlueTeam.database.models.event import SecurityEventModel

from BlueTeam.database.models.lifecycle import AlertRecord, IncidentRecord, DetectionRecord, RiskRecord

router = APIRouter()


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    Retrieve security summary data for the dashboard.
    """
    total_events = db.query(func.count(SecurityEventModel.id)).scalar() or 0
    active_alerts = db.query(func.count(AlertRecord.id)).filter(AlertRecord.status == "ACTIVE").scalar() or 0
    open_incidents = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.status == "OPEN").scalar() or 0
    
    latest_risk = db.query(RiskRecord).order_by(RiskRecord.id.desc()).first()
    system_status = latest_risk.risk_level if latest_risk else "SAFE"

    return DashboardSummaryResponse(
        total_events=total_events,
        data_availability=DataAvailabilityStatus(),
        active_alerts_count=active_alerts,
        open_incidents_count=open_incidents,
        system_status=system_status,
        system_status_note="Data is now fully persisted.",
    )


@router.get("/dashboard/statistics", response_model=DashboardStatsResponse)
def get_dashboard_statistics(db: Session = Depends(get_db)):
    """
    Retrieve statistical analytics on persisted security events.
    """
    total_events = db.query(func.count(SecurityEventModel.id)).scalar() or 0

    type_counts = (
        db.query(SecurityEventModel.event_type, func.count(SecurityEventModel.id))
        .group_by(SecurityEventModel.event_type)
        .all()
    )
    events_by_type = {evt_type: count for evt_type, count in type_counts}

    ip_counts = (
        db.query(SecurityEventModel.source_ip, func.count(SecurityEventModel.id))
        .group_by(SecurityEventModel.source_ip)
        .order_by(func.count(SecurityEventModel.id).desc())
        .limit(10)
        .all()
    )
    top_source_ips = [
        TopSourceIP(source_ip=ip, count=count) for ip, count in ip_counts
    ]

    detected_attacks = db.query(func.count(DetectionRecord.id)).filter(DetectionRecord.detected == True).scalar() or 0

    return DashboardStatsResponse(
        total_events=total_events,
        events_by_type=events_by_type,
        top_source_ips=top_source_ips,
        detected_attack_count=detected_attacks,
        detected_attack_count_note="Data is now fully persisted.",
        data_availability=DataAvailabilityStatus(),
    )

