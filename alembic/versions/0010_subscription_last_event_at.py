"""subscriptions.last_event_at: ignore out-of-order provider events

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("subscriptions", sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("subscriptions") as batch:
        batch.drop_column("last_event_at")
