"""github_connections: per-user GitHub OAuth tokens (encrypted)

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_connections",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False, unique=True),
        sa.Column("github_login", sa.String(), nullable=False),
        sa.Column("encrypted_token", sa.Text(), nullable=False),
        sa.Column("scope", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("github_connections")
