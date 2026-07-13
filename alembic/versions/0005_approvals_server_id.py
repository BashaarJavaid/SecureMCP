"""per-server approvals for the server registry (ROADMAP item 35).

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-13

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Pre-registry rows all belong to the single hardcoded upstream, "default".
    op.add_column(
        "approvals",
        sa.Column("server_id", sa.Text(), nullable=False, server_default="default"),
    )


def downgrade() -> None:
    op.drop_column("approvals", "server_id")
