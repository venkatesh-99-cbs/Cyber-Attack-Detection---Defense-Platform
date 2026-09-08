from fastapi import APIRouter

from BlueTeam.api.schemas.alert import AlertListResponse

router = APIRouter()


@router.get("/alerts", response_model=AlertListResponse)
def get_alerts():
    """
    Retrieve alerts status for the dashboard.

    - Alerts are generated dynamically in memory and broadcast over WebSocket (/ws).
    - Historical alert persistence is not configured in SQLite.
    """
    return AlertListResponse(
        persisted=False,
        status="PERSISTENCE_NOT_CONFIGURED",
        message=(
            "Alerts are generated dynamically in memory and broadcast over WebSocket (/ws), "
            "but historical alerts are not persisted in SQLite."
        ),
        alerts=None,
    )

