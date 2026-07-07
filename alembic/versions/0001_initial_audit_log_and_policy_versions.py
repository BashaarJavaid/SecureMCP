"""Initial audit_log and policy_versions tables (ARCHITECTURE.md §4.8).

Revision ID: 0001
Revises:
Create Date: 2026-07-06

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), autoincrement=True, primary_key=True),
        sa.Column("prev_hash", sa.CHAR(64), nullable=False),
        sa.Column("curr_hash", sa.CHAR(64), nullable=False),
        # Nullable until ECDSA signing lands (Phase 2, item 11).
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("identity_id", sa.Text(), nullable=False),
        sa.Column("server_id", sa.Text(), nullable=True),
        sa.Column("tool_name", sa.Text(), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=True),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
    )
    op.create_index("idx_audit_identity", "audit_log", ["identity_id", "timestamp"])
    op.create_index("idx_audit_event", "audit_log", ["event_type", "timestamp"])
    op.create_index("idx_audit_policy_version", "audit_log", ["policy_version"])

    op.create_table(
        "policy_versions",
        sa.Column("version", sa.Integer(), autoincrement=False, primary_key=True),
        sa.Column("content_hash", sa.CHAR(64), nullable=False),
        sa.Column(
            "activated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("activated_by", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("policy_versions")
    op.drop_index("idx_audit_policy_version", table_name="audit_log")
    op.drop_index("idx_audit_event", table_name="audit_log")
    op.drop_index("idx_audit_identity", table_name="audit_log")
    op.drop_table("audit_log")
