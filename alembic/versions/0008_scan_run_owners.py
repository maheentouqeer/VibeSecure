"""scan_runs carry their own owner, and survive scan deletion

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_runs") as batch:
        batch.add_column(sa.Column("owner_user_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("owner_token", sa.String(), nullable=True))
        batch.alter_column("scan_id", existing_type=sa.String(), nullable=True)
        batch.create_foreign_key("fk_scan_runs_owner_user_id", "users", ["owner_user_id"], ["id"])
        batch.create_index("ix_scan_runs_owner_user_id", ["owner_user_id"])
        batch.create_index("ix_scan_runs_owner_token", ["owner_token"])

    op.execute(
        "UPDATE scan_runs SET "
        "owner_user_id = (SELECT owner_user_id FROM scans WHERE scans.id = scan_runs.scan_id), "
        "owner_token = (SELECT owner_token FROM scans WHERE scans.id = scan_runs.scan_id)"
    )


def downgrade() -> None:
    op.execute("DELETE FROM scan_runs WHERE scan_id IS NULL")
    with op.batch_alter_table("scan_runs") as batch:
        batch.drop_index("ix_scan_runs_owner_token")
        batch.drop_index("ix_scan_runs_owner_user_id")
        batch.drop_constraint("fk_scan_runs_owner_user_id", type_="foreignkey")
        batch.alter_column("scan_id", existing_type=sa.String(), nullable=False)
        batch.drop_column("owner_token")
        batch.drop_column("owner_user_id")
