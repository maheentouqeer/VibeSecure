"""SQLAlchemy engine, session factory, and ORM models for Secure-VibeCode.

DATABASE_URL is read from the environment (see README for hosted Postgres
setup). Falls back to a local SQLite file so the API is runnable with zero
external setup during development/demo.
"""
import os
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey, Index, UniqueConstraint, text
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


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    clerk_user_id: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GithubConnection(Base):
    """A user's connected GitHub account, used to clone that user's private
    repositories. The access token is stored encrypted (backend/github_oauth.py)."""

    __tablename__ = "github_connections"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, unique=True)
    github_login: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_token: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),
        # At most one owner per organization, whatever the application code does.
        Index(
            "uq_membership_one_owner", "org_id", unique=True,
            sqlite_where=text("role = 'owner'"), postgresql_where=text("role = 'owner'"),
        ),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String, nullable=False, default="member")  # owner | admin | member

    organization: Mapped["Organization"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship()


class Subscription(Base):
    """A paid plan held by a user or (for the team plan) an organization."""

    __tablename__ = "subscriptions"
    __table_args__ = (
        UniqueConstraint("provider", "provider_subscription_id", name="uq_subscription_provider_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    provider_customer_id: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_subscription_id: Mapped[str] = mapped_column(String, nullable=False)
    plan: Mapped[str] = mapped_column(String, nullable=False)  # pro | team
    status: Mapped[str] = mapped_column(String, nullable=False)  # active | trialing | past_due | canceled | expired
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    # When the provider says the last applied event happened. Providers retry
    # for days and can deliver out of order; older events must not overwrite newer ones.
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    # Set once the scan belongs to a signed-in account (created while signed in,
    # or claimed from an anonymous owner_token). Anonymous scans leave it null.
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    # Set when the scan was created on behalf of an organization.
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)

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


class ScanJob(Base):
    """A unit of background work (run a scan, or re-scan). The database is the
    queue: it survives restarts and any number of API or worker processes can
    pull from it safely (see backend/jobs.py)."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)  # scan | rescan | webhook
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_by: Mapped[str | None] = mapped_column(String, nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanRun(Base):
    """One row per scan, rescan, or webhook re-scan started -- the source of
    truth for plan metering and the daily spend cap.

    It carries its own owner columns instead of leaning on scans, so deleting
    a scan (or an account) neither erases usage (which would let a free user
    reset their monthly limit by deleting scans) nor keeps personal data:
    scan_id is nulled on scan deletion and the owner columns on account deletion."""

    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)  # "scan" | "rescan" | "webhook"
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    owner_token: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )


class AdminAction(Base):
    """Audit trail of everything done through the admin API. Records what was
    done to which object -- never scan contents, findings, or target URLs."""

    __tablename__ = "admin_actions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String, nullable=True)


class RateEvent(Base):
    """One hit against a rate limit (see backend/limits.py). Kept in the
    database so limits are exact across instances and survive restarts."""

    __tablename__ = "rate_events"
    __table_args__ = (Index("ix_rate_events_lookup", "bucket", "key", "ts"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    bucket: Mapped[str] = mapped_column(String, nullable=False)
    key: Mapped[str] = mapped_column(String, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


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
