"""rate_events: database-backed rate limiting

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("bucket", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_rate_events_lookup", "rate_events", ["bucket", "key", "ts"])


def downgrade() -> None:
    op.drop_index("ix_rate_events_lookup", table_name="rate_events")
    op.drop_table("rate_events")
