#!/usr/bin/env python3
"""Unit tests for check_secrets.py guardrail script."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

# Add scripts directory to sys.path so check_secrets can be imported
scripts_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(scripts_dir))

from check_secrets import (  # noqa: E402
    check_forbidden_filename,
    scan_content,
    scan_file,
)


def test_clean_content_passes():
    content = """
    # Safe python code
    import os
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/db")
    API_KEY = os.getenv("GEMINI_API_KEY", "")
    print("System initialized.")
    """
    findings = scan_content(content, "safe_file.py")
    assert len(findings) == 0, f"Expected 0 findings, got: {findings}"


def test_google_api_key_detected():
    # 39-character string starting with AIza
    mock_key = "AIzaSy" + "A" * 33
    content = f'GEMINI_API_KEY = "{mock_key}"'
    findings = scan_content(content, "config.py")
    assert len(findings) == 1
    assert findings[0].rule_name == "google_api_key"
    assert "AIza" in findings[0].redacted_preview


def test_private_key_block_detected():
    # Assembled dynamically to avoid triggering the scanner on the test file itself
    header = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
    footer = "-----" + "END RSA PRIVATE KEY" + "-----"
    content = f"""
    {header}
    MIIEowIBAAKCAQEA0Y1234567890abcdefgh...
    {footer}
    """
    findings = scan_content(content, "server.key")
    assert len(findings) >= 1
    assert any(f.rule_name == "private_key_block" for f in findings)


def test_database_credentials_detected():
    # Assembled dynamically to avoid triggering the scanner on the test file itself
    uri_prefix = "postgresql://" + "admin"
    content = f'DATABASE_URL = "{uri_prefix}:super_secret_password_123@prod-db.internal:5432/phishing"'
    findings = scan_content(content, "settings.py")
    assert len(findings) == 1
    assert findings[0].rule_name == "database_credential_uri"


def test_forbidden_filenames():
    # Forbidden filenames
    assert check_forbidden_filename(".env") is not None
    assert check_forbidden_filename(".env.production") is not None
    assert check_forbidden_filename(".env.local") is not None
    assert check_forbidden_filename("server.pem") is not None
    assert check_forbidden_filename("id_rsa") is not None

    # Permitted filenames
    assert check_forbidden_filename(".env.example") is None
    assert check_forbidden_filename("config.py") is None
    assert check_forbidden_filename("README.md") is None


def test_scan_file_live():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. Clean file
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("print('Clean hello')", encoding="utf-8")
        assert len(scan_file(clean_file)) == 0

        # 2. Forbidden .env file
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=12345", encoding="utf-8")
        env_findings = scan_file(env_file)
        assert any(f.rule_name == "forbidden_filename" for f in env_findings)

        # 3. Permitted .env.example with placeholder
        example_file = tmp_path / ".env.example"
        example_file.write_text("DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/db", encoding="utf-8")
        assert len(scan_file(example_file)) == 0


def test_cli_exit_code():
    script_path = scripts_dir / "check_secrets.py"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Clean file execution -> exit code 0
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("print('Hello')", encoding="utf-8")
        res_clean = subprocess.run([sys.executable, str(script_path), str(clean_file)], capture_output=True, text=True)
        assert res_clean.returncode == 0, f"Expected 0, got {res_clean.returncode}: {res_clean.stdout}"

        # Dirty file execution -> exit code 1
        dirty_file = tmp_path / "dirty.py"
        dirty_file.write_text("KEY = 'AIzaSy" + "B" * 33 + "'", encoding="utf-8")
        res_dirty = subprocess.run([sys.executable, str(script_path), str(dirty_file)], capture_output=True, text=True)
        assert res_dirty.returncode == 1, f"Expected 1, got {res_dirty.returncode}: {res_dirty.stdout}"


if __name__ == "__main__":
    print("[test_check_secrets] Running test suite...")
    test_clean_content_passes()
    test_google_api_key_detected()
    test_private_key_block_detected()
    test_database_credentials_detected()
    test_forbidden_filenames()
    test_scan_file_live()
    test_cli_exit_code()
    print("[test_check_secrets] ALL 7 TEST SUITES PASSED SUCCESSFULLY!")
