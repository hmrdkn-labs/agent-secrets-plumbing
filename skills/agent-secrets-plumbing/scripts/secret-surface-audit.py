#!/usr/bin/env python3
"""Read-only repository audit for risky secret plumbing surfaces."""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}

SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b("
    r"BAO_TOKEN|VAULT_TOKEN|OP_SERVICE_ACCOUNT_TOKEN|AWS_SECRET_ACCESS_KEY|"
    r"GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|CLIENT_SECRET|"
    r"SECRET_ID|CLIENT_TOKEN|PRIVATE_KEY|DATABASE_URL|API_KEY"
    r")\b\s*[:=]\s*['\"]?([^'\"\s#]+)"
)

PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
HIGH_ENTROPY = re.compile(r"\b[A-Za-z0-9_/\-+=]{48,}\b")
K8S_KIND_SECRET = re.compile(r"(?im)^\s*kind:\s*Secret\s*$")
K8S_STRING_DATA = re.compile(r"(?im)^\s*stringData:\s*$")
K8S_DATA = re.compile(r"(?im)^\s*data:\s*$")

UNSAFE_COMMANDS = [
    ("shell-tracing", re.compile(r"(?m)^\s*set\s+-x\b")),
    ("print-environment", re.compile(r"(?m)^\s*(printenv|env)\s*(?:$|[|>])")),
    ("kubectl-secret-dump", re.compile(r"kubectl\s+get\s+secret\b.*\s-o\s+yaml\b")),
    ("sops-decrypt-to-file", re.compile(r"sops\s+-d\b.*>")),
    ("op-write-plaintext", re.compile(r"op\s+(?:read|inject)\b.*--out-file\b")),
    ("op-no-masking", re.compile(r"op\s+run\b.*--no-masking\b")),
]

PLACEHOLDER_WORDS = {
    "",
    "...",
    "redacted",
    "placeholder",
    "example",
    "sample",
    "dummy",
    "changeme",
    "change-me",
    "replace-me",
    "todo",
    "false",
    "true",
}


@dataclass
class Finding:
    severity: str
    path: str
    line: int
    rule: str
    detail: str


def is_placeholder(value: str) -> bool:
    clean = value.strip().strip("'\"`.,;:").lower()
    if clean in PLACEHOLDER_WORDS:
        return True
    if clean.startswith("<") and clean.endswith(">"):
        return True
    if clean.startswith("${") or clean.startswith("$"):
        return True
    if "placeholder" in clean or "redacted" in clean:
        return True
    return False


def iter_files(root: Path):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        current_path = Path(current)
        for filename in files:
            path = current_path / filename
            if path.is_symlink() or path.stat().st_size > 2_000_000:
                continue
            yield path


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def audit_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    name = path.name
    rel_path = rel(path, root)
    lower_name = name.lower()
    if lower_name.startswith(".env") and not any(x in lower_name for x in ("example", "sample", "template")):
        findings.append(Finding("high", rel_path, 1, "committed-env-file", "committed environment file"))

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        findings.append(Finding("medium", rel_path, 1, "unreadable", str(exc)))
        return findings

    match = PRIVATE_KEY.search(text)
    if match:
        findings.append(Finding("critical", rel_path, line_number(text, match.start()), "private-key", "private key block"))

    for match in SENSITIVE_ASSIGNMENT.finditer(text):
        key, value = match.group(1), match.group(2)
        line = text.splitlines()[line_number(text, match.start()) - 1]
        if "re.compile" in line or line.strip().startswith('r"') or line.strip().startswith("r'"):
            continue
        if not is_placeholder(value):
            findings.append(
                Finding("high", rel_path, line_number(text, match.start()), "sensitive-assignment", f"{key} assigned a non-placeholder value")
            )

    if K8S_KIND_SECRET.search(text):
        if K8S_STRING_DATA.search(text):
            findings.append(Finding("high", rel_path, 1, "kubernetes-stringdata", "Kubernetes Secret uses stringData"))
        elif K8S_DATA.search(text) and not re.search(r"(?i)sops|encrypted_regex|ENC\[", text):
            findings.append(Finding("medium", rel_path, 1, "kubernetes-secret-data", "Kubernetes Secret data may be plaintext/base64"))

    if ".github/workflows/" in rel_path.replace("\\", "/"):
        if re.search(r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS", text):
            findings.append(Finding("high", rel_path, 1, "static-ci-credential", "workflow references static cloud credential"))
        if re.search(r"pull_request_target", text) and re.search(r"id-token:\s*write|secrets\.", text):
            findings.append(Finding("high", rel_path, 1, "privileged-pr-target", "pull_request_target appears near privileged access"))

    for rule, pattern in UNSAFE_COMMANDS:
        for match in pattern.finditer(text):
            findings.append(Finding("medium", rel_path, line_number(text, match.start()), rule, "unsafe command pattern"))

    for match in HIGH_ENTROPY.finditer(text):
        value = match.group(0)
        if "/" in value or "\\" in value:
            continue
        if not is_placeholder(value) and len(set(value)) > 12:
            findings.append(Finding("medium", rel_path, line_number(text, match.start()), "high-entropy", "long high-entropy-looking token"))
            break

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="Repository or directory to audit")
    args = parser.parse_args()
    root = Path(args.repo).resolve()
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(audit_file(path, root))

    if not findings:
        print("OK: no risky secret surfaces found")
        return 0

    for item in findings:
        print(f"{item.severity.upper()} {item.path}:{item.line} {item.rule}: {item.detail}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
