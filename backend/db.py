"""SQLAlchemy engine, session factory, and ORM models for Secure-VibeCode.

DATABASE_URL is read from the environment (see README for hosted Postgres
setup). Falls back to a local SQLite file so the API is runnable with zero
external setup during development/demo.
"""
import os
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./secure_vibecode.db")

# Normalize legacy Heroku/Render postgres:// scheme to postgresql+psycopg2://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

# SQLite needs this connect_arg for use with FastAPI's threaded TestClient;
# Postgres ignores it entirely so it's safe to always pass.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String, nullable=False)
    platform: Mapped[str] = mapped_column(String, nullable=False, default="generic")
    status: Mapped[str] = mapped_column(String, nullable=False, default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # Opaque per-session ownership token (not a user account) -- whoever holds
    # this value is treated as the scan's owner. Set explicitly at creation
    # time in backend/main.py, never exposed in ScanResponse.
    owner_token: Mapped[str] = mapped_column(String, nullable=False)
    # Set when a scan or rescan job fails; cleared when a new job starts.
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Commit the last completed scan saw (repo targets only); lets a rescan of
    # an unchanged commit skip the scanners and LLM calls entirely.
    commit_sha: Mapped[str | None] = mapped_column(String, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)

    category: Mapped[str] = mapped_column(String, nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False)
    file: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    what_it_means: Mapped[str] = mapped_column(Text, nullable=False)
    why_it_matters: Mapped[str] = mapped_column(Text, nullable=False)
    fix_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    # Stable cross-scan identity (see agents.verify_agent.fingerprint); null on
    # rows saved before this column existed.
    fingerprint: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")


class ScanRun(Base):
    """One row per scan or rescan job started -- the source of truth for the
    daily spend cap (and, later, per-account usage metering)."""

    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)  # "scan" | "rescan"
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )


def init_db() -> None:
    """Bring the database to the latest Alembic revision.

    A database created earlier by create_all() has tables but no
    alembic_version table; it is stamped at head instead of re-created.
    Schema changes go in a new file under alembic/versions/, never by
    editing an applied migration."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))

    tables = inspect(engine).get_table_names()
    if "scans" in tables and "alembic_version" not in tables:
        command.stamp(cfg, "head")
    else:
        command.upgrade(cfg, "head")


def get_db():
    """FastAPI dependency — yields a session and guarantees it closes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
