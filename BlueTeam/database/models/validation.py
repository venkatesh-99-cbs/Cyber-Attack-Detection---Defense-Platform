import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, JSON, String, ForeignKey, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from BlueTeam.database.database import Base

class ValidationRecord(Base):
    """Database model for validation tracking."""
    __tablename__ = "validations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    validation_id: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False, default=lambda: f"val-{uuid.uuid4().hex[:8]}"
    )
    event_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("security_events.event_id"), index=True, nullable=False
    )
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    
    expected_detection: Mapped[str | None] = mapped_column(String(100), nullable=True)
    expected_risk_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    expected_alert: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    expected_incident: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    expected_response: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    actual_detection: Mapped[str | None] = mapped_column(String(100), nullable=True)
    actual_risk_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    actual_alert: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    actual_incident: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    actual_response: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    detection_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    risk_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    alert_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    incident_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    response_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    
    overall_result: Mapped[str] = mapped_column(String(20), nullable=False)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
