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

    scan: Mapped["Scan"] = relationship(back_populates="findings")


def init_db() -> None:
    """Create all tables if they don't already exist. Fast-path for a demo;
    swap for Alembic migrations once the schema needs to evolve post-hackathon."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency — yields a session and guarantees it closes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
