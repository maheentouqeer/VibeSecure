"""initial schema: scans and findings

Revision ID: 0001
Revises:
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("platform", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("owner_token", sa.String(), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("file", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("what_it_means", sa.Text(), nullable=False),
        sa.Column("why_it_matters", sa.Text(), nullable=False),
        sa.Column("fix_prompt", sa.Text(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("scans")
