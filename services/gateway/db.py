"""Async engine/session factory and ORM models (ARCHITECTURE.md §4.8 schema)."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    BigInteger,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from services.gateway.config import settings


class Base(DeclarativeBase):
    pass


class AuditLog(Base):
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    prev_hash: Mapped[str] = mapped_column(CHAR(64))
    curr_hash: Mapped[str] = mapped_column(CHAR(64))
    # Nullable until ECDSA signing lands (Phase 2, item 11); pre-signing rows stay unsigned.
    signature: Mapped[bytes | None] = mapped_column(LargeBinary)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    identity_id: Mapped[str] = mapped_column(Text)
    server_id: Mapped[str | None] = mapped_column(Text)
    tool_name: Mapped[str | None] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    latency_ms: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        Index("idx_audit_identity", "identity_id", "timestamp"),
        Index("idx_audit_event", "event_type", "timestamp"),
        Index("idx_audit_policy_version", "policy_version"),
    )


class ToolBaseline(Base):
    """Accepted schema baseline per (server, tool) — the Drift Detector's trust anchor.
    observed_* holds the latest drifted schema (what re-approval promotes) and dedups
    drift events across polls."""

    __tablename__ = "tool_baselines"

    server_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tool_name: Mapped[str] = mapped_column(Text, primary_key=True)
    approved_schema: Mapped[dict[str, Any]] = mapped_column(JSONB)
    approved_hash: Mapped[str] = mapped_column(CHAR(64))
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    blocked: Mapped[bool] = mapped_column(default=False)
    observed_schema: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    observed_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    content_hash: Mapped[str] = mapped_column(CHAR(64))
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    activated_by: Mapped[str] = mapped_column(Text)


engine = create_async_engine(settings.database_url)
async_session = async_sessionmaker(engine, expire_on_commit=False)
