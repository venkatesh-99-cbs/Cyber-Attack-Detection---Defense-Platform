from typing import Any
from pydantic import BaseModel, Field


class IncidentListResponse(BaseModel):
    """
    Response model for GET /incidents reporting non-persisted incident state transparently.
    """

    persisted: bool = False
    status: str = "PERSISTENCE_NOT_CONFIGURED"
    message: str = (
        "Incidents are managed in memory only and historical incidents are not persisted in SQLite."
    )
    incidents: list[dict[str, Any]] | None = None

