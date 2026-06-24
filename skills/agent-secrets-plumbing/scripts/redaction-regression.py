#!/usr/bin/env python3
"""Fail if canaries or common secret patterns appear in files or stdin."""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
TOKEN_PATTERNS = [
    ("github-token", re.compile(r"\bgh[opsu]_[A-Za-z0-9_]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("vault-token", re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b")),
    ("onepassword-service-token", re.compile(r"\bops_[A-Za-z0-9_=-]{20,}\b")),
]
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|DATABASE_URL|API_KEY)\b\s*[:=]\s*['\"]?([^'\"\s#]+)"
)
PLACEHOLDER = re.compile(
    r"(?i)^(<[^>]+>|\$\{[^}]+\}|\.\.\.|redacted|placeholder|example|sample|dummy|change-?me|true|false|read|write)$"
)


@dataclass
class Hit:
    path: str
    line: int
    rule: str


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_text(text: str, label: str, canary: str | None) -> list[Hit]:
    hits: list[Hit] = []
    if canary:
        index = text.find(canary)
        if index >= 0:
            hits.append(Hit(label, line_number(text, index), "canary"))
    match = PRIVATE_KEY.search(text)
    if match:
        hits.append(Hit(label, line_number(text, match.start()), "private-key"))
    for rule, pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            hits.append(Hit(label, line_number(text, match.start()), rule))
    for match in SENSITIVE_ASSIGNMENT.finditer(text):
        line = text.splitlines()[line_number(text, match.start()) - 1]
        stripped = line.strip()
        if "re.compile" in line or "re.search(" in line or stripped.startswith('r"') or stripped.startswith("r'"):
            continue
        if "fixture-only" in line or "findings.append(" in line:
            continue
        if "os.getenv(" in line or "getenv(" in line or "process.env." in line:
            continue
        value = match.group(2).strip().strip("'\"`.,;:")
        if not PLACEHOLDER.match(value):
            hits.append(Hit(label, line_number(text, match.start()), "sensitive-assignment"))
    return hits


def iter_paths(paths: list[str]):
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for current, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", ".cache", "node_modules"}]
                for filename in files:
                    candidate = Path(current) / filename
                    if candidate.stat().st_size <= 2_000_000:
                        yield candidate
        else:
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Files or directories to scan. Use no paths or '-' for stdin.")
    parser.add_argument("--canary", help="Synthetic canary value that must not appear")
    args = parser.parse_args()

    hits: list[Hit] = []
    if not args.paths or args.paths == ["-"]:
        hits.extend(scan_text(sys.stdin.read(), "<stdin>", args.canary))
    else:
        for path in iter_paths(args.paths):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"WARN {path}: {exc}", file=sys.stderr)
                continue
            hits.extend(scan_text(text, str(path), args.canary))

    if not hits:
        print("OK: no canary or common secret pattern found")
        return 0
    for hit in hits:
        print(f"LEAK {hit.path}:{hit.line} {hit.rule}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
