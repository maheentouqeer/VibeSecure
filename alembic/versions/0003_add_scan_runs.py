"""add scan_runs for spend cap and usage metering

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_runs_started_at", "scan_runs", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_runs_started_at", table_name="scan_runs")
    op.drop_table("scan_runs")
