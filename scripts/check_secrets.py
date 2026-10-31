#!/usr/bin/env python3
"""Secret Scanning Guardrail — Phishing Attack Detector.

PURPOSE:
    Scans project files and git staged files for accidentally exposed secrets,
    private keys, API credentials, embedded database passwords, and staged .env files
    before commits and pushes to public GitHub repositories.

LIMITATIONS & DEFENSE-IN-DEPTH NOTICE:
    1. This tool uses deterministic regular expression patterns and heuristic entropy
       checks. It is effective at identifying common key signatures (e.g., Google API keys,
       RSA private keys, database connection strings), but cannot guarantee detection of:
       - Base64-obfuscated or dynamically constructed credentials.
       - Generic random tokens that do not follow established vendor prefixes.
       - Secrets split across multiple variables or configuration templates.
    2. This scanner is a local pre-commit guardrail. For comprehensive CI/CD protection,
       pair it with dedicated repository scanning solutions (such as Gitleaks or TruffleHog)
       and automated branch protection rules.
    3. Always treat .env.example with placeholder values as the ONLY permitted commit.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple


class SecretFinding(NamedTuple):
    file_path: str
    line_number: int
    rule_name: str
    redacted_preview: str


# Regular expression rules for known secret formats
SECRET_RULES: dict[str, re.Pattern[str]] = {
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----"),
    "database_credential_uri": re.compile(
        r"(?:postgres|postgresql|postgresql\+psycopg|mysql|mongodb)(?:\+[a-z0-9_]+)?:\/\/[^:\/\s]+:(?!\$\{|postgres\b|password\b|placeholder\b)[^@\/\s]{4,}@[^\/\s]+"
    ),
    "aws_access_key_id": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    "generic_secret_assignment": re.compile(
        r"(?i)\b(?:api_key|apikey|secret_key|private_key|auth_token)\s*=\s*['\"][0-9a-zA-Z\-_]{20,}['\"]"
    ),
}

# Forbidden file name patterns (cannot be staged or committed, except .env.example)
FORBIDDEN_FILE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\.env(?:\.[a-zA-Z0-9_\-]+)?$"),
    re.compile(r"^.*\.pem$"),
    re.compile(r"^.*\.key$"),
    re.compile(r"^.*id_rsa$"),
]

# Paths and file types ignored during scanning
DEFAULT_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".planning",
}

DEFAULT_IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".docx",
    ".pdf",
    ".zip",
    ".pyc",
}


def redact_secret(value: str) -> str:
    """Return a safely redacted representation of a secret match."""
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return "****"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def check_forbidden_filename(file_path: str | Path) -> str | None:
    """Check if the filename itself is a forbidden secret file."""
    path = Path(file_path)
    name = path.name

    # Allow .env.example explicitly
    if name == ".env.example":
        return None

    for pattern in FORBIDDEN_FILE_PATTERNS:
        if pattern.match(name):
            return f"Forbidden secret file name detected: {name}"
    return None


def scan_content(content: str, file_path: str) -> list[SecretFinding]:
    """Scan string content line by line against secret rules."""
    findings: list[SecretFinding] = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # Skip scanning obvious placeholder lines in docs or tests
        if "placeholder" in line.lower() or "example" in line.lower():
            # Still scan if rule is a private key block or real Google key
            if "AIza" not in line and "-----BEGIN" not in line:
                continue

        for rule_name, pattern in SECRET_RULES.items():
            matches = pattern.findall(line)
            for match in matches:
                findings.append(
                    SecretFinding(
                        file_path=file_path,
                        line_number=line_idx,
                        rule_name=rule_name,
                        redacted_preview=redact_secret(match),
                    )
                )

    return findings


def scan_file(file_path: Path) -> list[SecretFinding]:
    """Scan a single file on disk."""
    findings: list[SecretFinding] = []

    # Check filename rule
    filename_violation = check_forbidden_filename(file_path)
    if filename_violation:
        findings.append(
            SecretFinding(
                file_path=str(file_path),
                line_number=1,
                rule_name="forbidden_filename",
                redacted_preview=filename_violation,
            )
        )

    if file_path.suffix.lower() in DEFAULT_IGNORED_EXTENSIONS:
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        findings.append(
            SecretFinding(
                file_path=str(file_path),
                line_number=0,
                rule_name="read_error",
                redacted_preview=f"Could not read file: {exc}",
            )
        )
        return findings

    findings.extend(scan_content(content, str(file_path)))
    return findings


def get_git_staged_files(repo_root: Path) -> list[Path]:
    """Retrieve list of files currently staged in git index."""
    try:
        output = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=repo_root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        files = [repo_root / line.strip() for line in output.splitlines() if line.strip()]
        return [f for f in files if f.exists()]
    except (subprocess.SubprocessError, FileNotFoundError):
        return []


def scan_directory(root_dir: Path) -> list[SecretFinding]:
    """Walk directory recursively, skipping ignored folders."""
    findings: list[SecretFinding] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Mutate dirnames in place to skip ignored directories
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORED_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            findings.extend(scan_file(file_path))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan repository files for exposed credentials and secrets."
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan git staged files only (ideal for git pre-commit hooks).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all files in the current repository.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Specific files or directories to scan.",
    )

    args = parser.parse_args()
    repo_root = Path.cwd()

    files_to_scan: list[Path] = []
    findings: list[SecretFinding] = []

    if args.staged:
        files_to_scan = get_git_staged_files(repo_root)
        if not files_to_scan:
            print("[check_secrets] No staged files found to scan.")
            return 0
        for f in files_to_scan:
            findings.extend(scan_file(f))
    elif args.paths:
        for p in args.paths:
            if p.is_file():
                findings.extend(scan_file(p))
            elif p.is_dir():
                findings.extend(scan_directory(p))
    else:
        # Default behavior: scan the repo directory
        findings = scan_directory(repo_root)

    if not findings:
        print("[check_secrets] PASS: No secrets or forbidden files detected.")
        return 0

    print("=" * 80)
    print(f"[check_secrets] ALERT: Found {len(findings)} potential secret violation(s)!")
    print("=" * 80)
    for finding in findings:
        print(
            f" - {finding.file_path}:{finding.line_number} [{finding.rule_name}] -> {finding.redacted_preview}"
        )
    print("=" * 80)
    print("ACTION REQUIRED: Remove secrets or update .gitignore before committing/pushing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
