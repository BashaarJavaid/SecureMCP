"""tool_baselines for the Drift Detector (ARCHITECTURE.md §4.8, ROADMAP item 9).

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-07

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_baselines",
        sa.Column("server_id", sa.Text(), primary_key=True),
        sa.Column("tool_name", sa.Text(), primary_key=True),
        sa.Column("approved_schema", JSONB, nullable=False),
        sa.Column("approved_hash", sa.CHAR(64), nullable=False),
        sa.Column(
            "approved_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("observed_schema", JSONB, nullable=True),
        sa.Column("observed_hash", sa.CHAR(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("tool_baselines")
