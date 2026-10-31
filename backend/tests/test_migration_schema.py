"""Tests for Alembic migration definitions and schema consistency.

Runs locally without requiring Docker or a running PostgreSQL instance.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_migration_module():
    migration_file = (
        Path(__file__).resolve().parent.parent / "alembic" / "versions" / "001_initial_scans.py"
    )
    assert migration_file.exists(), f"Migration file not found at: {migration_file}"

    spec = importlib.util.spec_from_file_location("initial_scans_migration", migration_file)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMigrationSchemaConsistency:
    """Verify that the initial Alembic migration is structurally sound and complete."""

    def test_migration_metadata(self):
        mod = load_migration_module()
        assert mod.revision == "001_initial_scans"
        assert mod.down_revision is None
        assert hasattr(mod, "upgrade")
        assert hasattr(mod, "downgrade")

    def test_migration_source_contains_required_definitions(self):
        migration_file = (
            Path(__file__).resolve().parent.parent / "alembic" / "versions" / "001_initial_scans.py"
        )
        content = migration_file.read_text(encoding="utf-8")

        # Verify table creation
        assert 'op.create_table(\n        "scans"' in content or 'op.create_table("scans"' in content or 'op.create_table(\n        \'scans\'' in content

        # Verify critical columns
        required_columns = [
            '"id"',
            '"target_type"',
            '"target_reference"',
            '"classification"',
            '"risk_score"',
            '"evidence"',
            '"tool_statuses"',
            '"analysis_status"',
            '"source"',
            '"created_at"',
        ]
        for col in required_columns:
            assert col in content, f"Column {col} missing from initial migration DDL"

        # Verify check constraints
        assert "ck_scans_risk_score_range" in content
        assert "ck_scans_target_type" in content
        assert "ck_scans_analysis_status" in content

        # Verify indexes
        assert "ix_scans_created_at" in content
        assert "ix_scans_target_created_at" in content
        assert "ix_scans_classification_created_at" in content
