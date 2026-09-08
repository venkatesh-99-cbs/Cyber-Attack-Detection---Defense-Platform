from typing import Any
from pydantic import BaseModel, Field


class AlertListResponse(BaseModel):
    """
    Response model for GET /alerts reporting non-persisted alert state transparently.
    """

    persisted: bool = False
    status: str = "PERSISTENCE_NOT_CONFIGURED"
    message: str = (
        "Alerts are generated dynamically in memory and broadcast over WebSocket (/ws), "
        "but historical alerts are not persisted in SQLite."
    )
    alerts: list[dict[str, Any]] | None = None

