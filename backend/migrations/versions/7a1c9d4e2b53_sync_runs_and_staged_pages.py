"""sync runs, staged pages, cancellation"""

import sqlalchemy as sa
from alembic import op

revision = "7a1c9d4e2b53"
down_revision = "e86bccc424dd"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("sync_state") as batch:
        batch.add_column(
            sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    op.create_table(
        "sync_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("start", sa.DateTime(), nullable=False),
        sa.Column("end", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("pages_fetched", sa.Integer(), nullable=False),
        sa.Column("pages_total", sa.Integer(), nullable=True),
        sa.Column("cursor_index", sa.Integer(), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("last_page_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("status IN ('running','completed','failed','cancelled')"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "sync_staged_cves",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("page_index", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("staged_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["sync_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "cve_id"),
    )
    op.create_index("ix_sync_staged_run_page", "sync_staged_cves", ["run_id", "page_index"], unique=False)


def downgrade():
    op.drop_index("ix_sync_staged_run_page", table_name="sync_staged_cves")
    op.drop_table("sync_staged_cves")
    op.drop_table("sync_runs")
    with op.batch_alter_table("sync_state") as batch:
        batch.drop_column("cancel_requested")
