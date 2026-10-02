"""enable row level security on every application table (Postgres / Supabase only)

Why: on Supabase the `public` schema is reachable through the auto-generated REST
API with the public anon key. Without row level security anyone holding that key
(it ships in the frontend) could read or write these tables directly, including
`github_connections.encrypted_token` and every user's scans.

With RLS enabled and no policies, the anon and authenticated roles can see nothing.
The backend is unaffected: it connects with the database owner role, which bypasses
RLS, and enforces ownership in the application layer.

No-op on SQLite (local development and the default test run). Safe to re-run.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-02
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

TABLES = (
    "scans",
    "findings",
    "scan_runs",
    "users",
    "organizations",
    "memberships",
    "subscriptions",
    "scan_jobs",
    "github_connections",
    "rate_events",
    "admin_actions",
    "org_invites",
    "alembic_version",
)


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if not _is_postgres():
        return
    for table in TABLES:
        op.execute(f'ALTER TABLE IF EXISTS public."{table}" ENABLE ROW LEVEL SECURITY')


def downgrade() -> None:
    if not _is_postgres():
        return
    for table in TABLES:
        op.execute(f'ALTER TABLE IF EXISTS public."{table}" DISABLE ROW LEVEL SECURITY')
