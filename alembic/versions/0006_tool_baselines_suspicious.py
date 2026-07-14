"""suspicious flag for baseline-time description scanning (ROADMAP item 36b).

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-13

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing baselines were never scanned; they stay unflagged rather than being
    # retroactively judged by heuristics that didn't exist when they were approved.
    op.add_column(
        "tool_baselines",
        sa.Column("suspicious", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("tool_baselines", "suspicious")
