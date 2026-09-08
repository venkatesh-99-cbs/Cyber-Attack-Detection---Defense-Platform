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

router = APIRouter()


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    Retrieve security summary data for the dashboard.

    - Returns persisted total event count.
    - Explicitly reports non-persisted status for alerts, incidents, and risk scoring.
    """
    total_events = db.query(func.count(SecurityEventModel.id)).scalar() or 0

    return DashboardSummaryResponse(
        total_events=total_events,
        data_availability=DataAvailabilityStatus(),
        active_alerts_count=None,
        open_incidents_count=None,
        system_status=None,
    )


@router.get("/dashboard/statistics", response_model=DashboardStatsResponse)
def get_dashboard_statistics(db: Session = Depends(get_db)):
    """
    Retrieve statistical analytics on persisted security events.

    - Preserves exact event_type terminology from stored SecurityEvent records.
    - Explicitly reports non-persisted status for detection rule matches.
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

    return DashboardStatsResponse(
        total_events=total_events,
        events_by_type=events_by_type,
        top_source_ips=top_source_ips,
        detected_attack_count=None,
        data_availability=DataAvailabilityStatus(),
    )

