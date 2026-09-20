"""admin_actions: audit log for the admin API

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_actions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip", sa.String(), nullable=True),
    )
    op.create_index("ix_admin_actions_at", "admin_actions", ["at"])


def downgrade() -> None:
    op.drop_index("ix_admin_actions_at", table_name="admin_actions")
    op.drop_table("admin_actions")
