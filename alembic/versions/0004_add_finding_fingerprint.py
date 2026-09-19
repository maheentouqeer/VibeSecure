"""add findings.fingerprint for stable rescan matching

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("fingerprint", sa.String(), nullable=True))
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_column("findings", "fingerprint")
