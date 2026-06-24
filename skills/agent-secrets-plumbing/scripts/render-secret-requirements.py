#!/usr/bin/env python3
"""Infer logical secret requirements and render placeholder-only injection plans."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


SKIP_DIRS = {".git", "node_modules", ".cache", "__pycache__", "dist", "build"}
ENV_PATTERNS = [
    re.compile(r"os\.Getenv\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']\s*\)"),
    re.compile(r"getenv\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']\s*\)"),
    re.compile(r"process\.env\.([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"import\.meta\.env\.([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"env:\s*\n(?:\s+-\s+name:\s*([A-Z][A-Z0-9_]{2,})\s*\n)+", re.MULTILINE),
]
SECRET_HINTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE",
    "API_KEY",
    "ACCESS_KEY",
    "DATABASE_URL",
    "DSN",
    "WEBHOOK",
    "CLIENT_SECRET",
)
IGNORE = {
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "PWD",
    "CI",
    "PORT",
    "HOST",
    "NODE_ENV",
    "PYTHONPATH",
    "GOCACHE",
}


def iter_files(root: Path):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(current) / filename
            if path.is_symlink() or path.stat().st_size > 1_000_000:
                continue
            yield path


def collect(root: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for pattern in ENV_PATTERNS:
            for match in pattern.finditer(text):
                for value in match.groups():
                    if not value or value in IGNORE:
                        continue
                    if any(hint in value for hint in SECRET_HINTS):
                        found.setdefault(value, set()).add(rel)
    return found


def render_json(root: Path, found: dict[str, set[str]]) -> str:
    names = sorted(found)
    payload = {
        "backend": "openbao-vault-kv-v2",
        "path_template": "projects/<project>/<environment>/<service>",
        "required_secret_names": [
            {"name": name, "sources": sorted(found[name])} for name in names
        ],
        "injection_plan": {
            "wrapper_argv_template": ["secrets", "run", "--", "<command>", "<args>"],
            "sdk_interface": "Provider.Get(ctx, path, key) / Provider.GetMap(ctx, path)",
            "verification": "presence booleans, status classes, policy capabilities, and denied-access checks only",
        },
        "repo": str(root),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_md(root: Path, found: dict[str, set[str]]) -> str:
    lines = [
        "# Secret Requirements",
        "",
        f"Repo: `{root}`",
        "",
        "Backend: OpenBao/Vault KV v2 or repo-approved equivalent.",
        "Path template: `projects/<project>/<environment>/<service>`.",
        "",
        "## Required Names",
    ]
    if not found:
        lines.append("")
        lines.append("No obvious secret-like environment requirements were found.")
    else:
        for name in sorted(found):
            sources = ", ".join(f"`{item}`" for item in sorted(found[name]))
            lines.append(f"- `{name}` from {sources}")
    lines.extend(
        [
            "",
            "## Injection Plan",
            "",
            "- Existing app wrapper: `secrets run -- <command> <args>`.",
            "- New app SDK: `Provider.Get(ctx, path, key)` or `Provider.GetMap(ctx, path)` behind a repo-owned adapter.",
            "- Verify with presence booleans, status classes, policy capabilities, and expected denials only.",
            "- Do not print or materialize values.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="Repository or directory to inspect")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    args = parser.parse_args()
    root = Path(args.repo).resolve()
    found = collect(root)
    if args.format == "json":
        print(render_json(root, found))
    else:
        print(render_md(root, found), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

