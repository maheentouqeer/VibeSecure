"""API keys for remote MCP and CLI integrations."""
from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

def _is_postgres() -> bool:
    return op.get_bind().dialect.name == 'postgresql'

def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    if _is_postgres():
        op.execute('ALTER TABLE IF EXISTS public."api_keys" ENABLE ROW LEVEL SECURITY')

def downgrade() -> None:
    if _is_postgres():
        op.execute('ALTER TABLE IF EXISTS public."api_keys" DISABLE ROW LEVEL SECURITY')
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")
