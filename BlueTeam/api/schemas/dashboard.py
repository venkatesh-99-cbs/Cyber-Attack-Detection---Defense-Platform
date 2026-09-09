from typing import Any
from pydantic import BaseModel, Field


class DataAvailabilityStatus(BaseModel):
    """
    Explicit data-availability representation indicating backend persistence scope.
    """

    events_persisted: bool = True
    alerts_persisted: bool = True
    incidents_persisted: bool = True
    risk_analysis_persisted: bool = True
    detection_results_persisted: bool = True


class DashboardSummaryResponse(BaseModel):
    """
    Summary metrics response for GET /dashboard/summary.
    """

    total_events: int
    data_availability: DataAvailabilityStatus = Field(
        default_factory=DataAvailabilityStatus
    )
    active_alerts_count: int | None = None
    open_incidents_count: int | None = None
    system_status: str | None = None
    system_status_note: str = (
        "Alert, incident, and risk analysis data are not persisted in SQLite."
    )


class TopSourceIP(BaseModel):
    """
    Source IP address event count aggregation item.
    """

    source_ip: str
    count: int


class DashboardStatsResponse(BaseModel):
    """
    Statistical breakdown response for GET /dashboard/statistics.
    """

    total_events: int
    events_by_type: dict[str, int]
    top_source_ips: list[TopSourceIP]
    detected_attack_count: int | None = None
    detected_attack_count_note: str = (
        "Detection engine results are evaluated dynamically and not persisted in database."
    )
    data_availability: DataAvailabilityStatus = Field(
        default_factory=DataAvailabilityStatus
    )

