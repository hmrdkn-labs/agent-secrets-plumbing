#!/usr/bin/env python3
"""Lint OpenBao/Vault HCL policies for safe KV v2 runtime scope."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


PATH_BLOCK = re.compile(r'path\s+"([^"]+)"\s*\{(?P<body>.*?)\}', re.DOTALL)
CAPS = re.compile(r"capabilities\s*=\s*\[([^\]]*)\]", re.DOTALL)
SAFE_KV = re.compile(r"^[A-Za-z0-9_-]+/(data|metadata)/projects/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$")
APPROLE_SECRET_ID = re.compile(r"^auth/approle/role/[A-Za-z0-9_-]+/secret-id$")


@dataclass
class Finding:
    severity: str
    rule: str
    detail: str


def parse_caps(body: str) -> set[str]:
    match = CAPS.search(body)
    if not match:
        return set()
    return {part.strip().strip('"').strip("'") for part in match.group(1).split(",") if part.strip()}


def lint(text: str) -> list[Finding]:
    findings: list[Finding] = []
    data_paths: set[str] = set()
    metadata_paths: set[str] = set()
    blocks = list(PATH_BLOCK.finditer(text))
    if not blocks:
        return [Finding("high", "no-path-blocks", "policy contains no path blocks")]

    for match in blocks:
        path = match.group(1)
        caps = parse_caps(match.group("body"))
        if not caps:
            findings.append(Finding("medium", "missing-capabilities", f"{path} has no capabilities list"))

        if "root" in caps or "sudo" in caps:
            findings.append(Finding("critical", "privileged-capability", f"{path} grants root/sudo-like access"))

        if "*" in path:
            findings.append(Finding("high", "wildcard-path", f"{path} contains a wildcard"))

        if path in {"*", "kv/*", "secret/*"} or re.match(r"^[A-Za-z0-9_-]+/(data|metadata)/?\*$", path):
            findings.append(Finding("critical", "broad-runtime-path", f"{path} is too broad for runtime access"))

        if "/data/" in path or "/metadata/" in path:
            if not SAFE_KV.match(path) and "*" not in path:
                findings.append(Finding("medium", "noncanonical-kv-path", f"{path} does not match mount/(data|metadata)/projects/project/env/service"))

        if "/data/" in path:
            data_paths.add(path.replace("/data/", "/"))
            bad = caps & {"create", "update", "patch", "delete", "destroy"}
            if bad:
                findings.append(Finding("high", "runtime-data-mutation", f"{path} grants {sorted(bad)}"))

        if "/metadata/" in path:
            metadata_paths.add(path.replace("/metadata/", "/"))
            if "list" in caps:
                findings.append(Finding("medium", "metadata-list", f"{path} grants list; list leaks key names"))
            bad = caps & {"create", "update", "patch", "delete", "destroy"}
            if bad:
                findings.append(Finding("high", "runtime-metadata-mutation", f"{path} grants {sorted(bad)}"))

        if APPROLE_SECRET_ID.match(path):
            if not (caps & {"create", "update"}):
                findings.append(Finding("medium", "approle-secretid-capability", f"{path} should use create/update for wrapped bootstrap"))
            if "max_wrapping_ttl" not in match.group("body"):
                findings.append(Finding("medium", "missing-wrap-ttl", f"{path} lacks max_wrapping_ttl"))

    for data_path in sorted(data_paths):
        if data_path not in metadata_paths:
            findings.append(Finding("low", "missing-metadata-read", f"{data_path} has data read without matching metadata read"))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy_file", help="OpenBao/Vault HCL policy file")
    args = parser.parse_args()
    path = Path(args.policy_file)
    text = path.read_text(encoding="utf-8")
    findings = lint(text)
    if not findings:
        print("OK: policy scope looks safe for KV v2 runtime read")
        return 0
    for item in findings:
        print(f"{item.severity.upper()} {item.rule}: {item.detail}")
    return 1 if any(item.severity in {"critical", "high"} for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

