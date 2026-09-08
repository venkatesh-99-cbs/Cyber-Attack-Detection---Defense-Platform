from fastapi import APIRouter

from BlueTeam.api.schemas.incident import IncidentListResponse

router = APIRouter()


@router.get("/incidents", response_model=IncidentListResponse)
def get_incidents():
    """
    Retrieve incidents status for the dashboard.

    - Incidents are managed in memory only during runtime.
    - Historical incident persistence is not configured in SQLite.
    """
    return IncidentListResponse(
        persisted=False,
        status="PERSISTENCE_NOT_CONFIGURED",
        message=(
            "Incidents are managed in memory only and historical incidents are not persisted in SQLite."
        ),
        incidents=None,
    )

