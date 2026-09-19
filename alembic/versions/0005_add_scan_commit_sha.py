"""add scans.commit_sha for unchanged-commit rescan skipping

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("commit_sha", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "commit_sha")
