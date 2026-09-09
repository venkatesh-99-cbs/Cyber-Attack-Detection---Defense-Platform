from datetime import datetime
from sqlalchemy import DateTime, Integer, JSON, String, ForeignKey, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from BlueTeam.database.database import Base


class DetectionRecord(Base):
    """Database model for detection results associated with a security event."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("security_events.event_id"), index=True, nullable=False
    )
    detected: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )


class RiskRecord(Base):
    """Database model for risk results associated with a security event."""

    __tablename__ = "risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("security_events.event_id"), index=True, nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    attack_types: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    rule_names: Mapped[list] = mapped_column(JSON, default=list)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )


class AlertRecord(Base):
    """Database model for alerts associated with a security event."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )
    event_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("security_events.event_id"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_types: Mapped[list] = mapped_column(JSON, default=list)
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    rule_names: Mapped[list] = mapped_column(JSON, default=list)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )


class IncidentRecord(Base):
    """Database model for incidents associated with a security event."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )
    alert_id: Mapped[str] = mapped_column(
        String(100), index=True, nullable=False
    )
    event_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("security_events.event_id"), index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_types: Mapped[list] = mapped_column(JSON, default=list)
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    rule_names: Mapped[list] = mapped_column(JSON, default=list)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False)


class ResponseRecord(Base):
    """Database model for automated responses associated with a security event."""

    __tablename__ = "responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    response_id: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )
    incident_id: Mapped[str] = mapped_column(
        String(100), index=True, nullable=False
    ) 
    event_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("security_events.event_id"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
