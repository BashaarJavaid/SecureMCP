"""ECDSA signing + verifier checkpoint (ARCHITECTURE.md §4.8, ROADMAP item 11).

signature becomes NOT NULL — pre-signing rows cannot be signed retroactively, so this
migration fails (by design) on a chain that already has unsigned rows; dev/demo chains
are disposable and should be truncated first. audit_verifier_checkpoint holds the
daemon's single last_verified_seq row (Postgres, not Redis, so a restart never forces
an O(n) rescan — see ADR-003's scoping of Redis to loss-tolerable state).

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-07

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("audit_log", "signature", existing_type=sa.LargeBinary(), nullable=False)
    op.create_table(
        "audit_verifier_checkpoint",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("last_verified_seq", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("audit_verifier_checkpoint")
    op.alter_column("audit_log", "signature", existing_type=sa.LargeBinary(), nullable=True)
