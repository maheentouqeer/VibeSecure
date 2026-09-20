"""accounts: users, organizations, memberships, subscriptions, scan owners

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("clerk_user_id", sa.String(), nullable=False, unique=True),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "organizations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("owner_user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "memberships",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_org_id", "memberships", ["org_id"])

    op.create_table(
        "subscriptions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("provider_customer_id", sa.String(), nullable=True),
        sa.Column("provider_subscription_id", sa.String(), nullable=False),
        sa.Column("plan", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider", "provider_subscription_id", name="uq_subscription_provider_id"),
    )
    op.create_index("ix_subscriptions_user_id", "subscriptions", ["user_id"])
    op.create_index("ix_subscriptions_org_id", "subscriptions", ["org_id"])

    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("owner_user_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("org_id", sa.String(), nullable=True))
        batch.create_foreign_key("fk_scans_owner_user_id", "users", ["owner_user_id"], ["id"])
        batch.create_foreign_key("fk_scans_org_id", "organizations", ["org_id"], ["id"])
        batch.create_index("ix_scans_owner_user_id", ["owner_user_id"])
        batch.create_index("ix_scans_org_id", ["org_id"])


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_index("ix_scans_org_id")
        batch.drop_index("ix_scans_owner_user_id")
        batch.drop_constraint("fk_scans_org_id", type_="foreignkey")
        batch.drop_constraint("fk_scans_owner_user_id", type_="foreignkey")
        batch.drop_column("org_id")
        batch.drop_column("owner_user_id")
    op.drop_table("subscriptions")
    op.drop_table("memberships")
    op.drop_table("organizations")
    op.drop_table("users")
