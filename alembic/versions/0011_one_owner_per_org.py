"""at most one owner per organization

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_membership_one_owner", "memberships", ["org_id"], unique=True,
        sqlite_where=sa.text("role = 'owner'"), postgresql_where=sa.text("role = 'owner'"),
    )


def downgrade() -> None:
    op.drop_index("uq_membership_one_owner", table_name="memberships")
