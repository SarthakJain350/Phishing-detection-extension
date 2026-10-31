"""Initial migration: create scans table.

Revision ID: 001_initial_scans
Revises:
Create Date: 2026-11-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_initial_scans"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Universal JSON and UUID types for cross-dialect migrations
    json_type = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
    uuid_type = postgresql.UUID(as_uuid=True).with_variant(sa.String(36), "sqlite")

    op.create_table(
        "scans",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target_reference", sa.String(length=255), nullable=False),
        sa.Column("classification", sa.String(length=32), nullable=True),
        sa.Column("risk_score", sa.SmallInteger(), nullable=True),
        sa.Column("evidence", json_type, nullable=False),
        sa.Column("tool_statuses", json_type, nullable=False),
        sa.Column("analysis_status", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "(risk_score IS NULL) OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_scans_risk_score_range",
        ),
        sa.CheckConstraint(
            "target_type IN ('website', 'email')",
            name="ck_scans_target_type",
        ),
        sa.CheckConstraint(
            "analysis_status IN ('complete', 'partial', 'unavailable')",
            name="ck_scans_analysis_status",
        ),
    )

    op.create_index(
        "ix_scans_created_at",
        "scans",
        [sa.text("created_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_scans_target_created_at",
        "scans",
        ["target_reference", sa.text("created_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_scans_classification_created_at",
        "scans",
        ["classification", sa.text("created_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_classification_created_at", table_name="scans")
    op.drop_index("ix_scans_target_created_at", table_name="scans")
    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_table("scans")
