#!/usr/bin/env python3
"""Agent-safe OpenBao helper CLI.

This tool is designed for AI-agent plumbing: it can plan scopes, check server
health, query token capabilities, write KV v2 data from local input, and verify
required key presence without printing secret values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
SAFE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
DEFAULT_ADDR = "https://127.0.0.1:8200"


class CliError(Exception):
    """Expected CLI failure without secret-bearing details."""


@dataclass(frozen=True)
class Scope:
    project: str
    environment: str
    service: str
    mount: str = "kv"

    def validate(self) -> None:
        for label, value in (
            ("project", self.project),
            ("environment", self.environment),
            ("service", self.service),
            ("mount", self.mount),
        ):
            if not SAFE_SEGMENT.match(value):
                raise CliError(f"{label} must use only letters, numbers, '_' and '-'")

    @property
    def logical_path(self) -> str:
        return f"projects/{self.project}/{self.environment}/{self.service}"

    @property
    def data_path(self) -> str:
        return f"{self.mount}/data/{self.logical_path}"

    @property
    def metadata_path(self) -> str:
        return f"{self.mount}/metadata/{self.logical_path}"

    @property
    def role_name(self) -> str:
        return f"app-{self.project}-{self.environment}-{self.service}"

    @property
    def policy_name(self) -> str:
        return f"{self.role_name}-read"

    @property
    def policy_hcl(self) -> str:
        return (
            f'path "{self.data_path}" {{\n'
            '  capabilities = ["read"]\n'
            "}\n\n"
            f'path "{self.metadata_path}" {{\n'
            '  capabilities = ["read"]\n'
            "}\n"
        )


def token_from_env() -> str:
    token = os.environ.get("BAO_TOKEN") or os.environ.get("VAULT_TOKEN")
    if not token:
        raise CliError("BAO_TOKEN or VAULT_TOKEN must be set in the local environment")
    return token


def bool_env(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}


def json_print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def api_request(
    args: argparse.Namespace,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    token_required: bool = True,
    allowed_status: set[int] | None = None,
) -> tuple[int, dict[str, Any]]:
    allowed_status = allowed_status or {200}
    base = (args.addr or os.environ.get("BAO_ADDR") or os.environ.get("VAULT_ADDR") or DEFAULT_ADDR).rstrip("/")
    url = f"{base}/v1/{path.lstrip('/')}"
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token_required:
        headers["X-Vault-Token"] = token_from_env()

    context = None
    if args.tls_skip_verify or bool_env("BAO_SKIP_VERIFY") or bool_env("VAULT_SKIP_VERIFY"):
        context = ssl._create_unverified_context()

    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=args.timeout, context=context) as response:
            status = response.getcode()
            data = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        data = exc.read()
    except urllib.error.URLError as exc:
        raise CliError(f"OpenBao request failed for {method} /v1/{path}: {exc.reason}") from exc

    if status not in allowed_status:
        raise CliError(f"OpenBao returned HTTP {status} for {method} /v1/{path}")

    if not data:
        return status, {}
    try:
        parsed = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        return status, {}
    if not isinstance(parsed, dict):
        return status, {}
    return status, parsed


def build_scope(args: argparse.Namespace) -> Scope:
    scope = Scope(args.project, args.environment, args.service, args.mount)
    scope.validate()
    return scope


def validate_key_names(keys: list[str]) -> None:
    for key in keys:
        if not SAFE_KEY.match(key):
            raise CliError(f"key name {key!r} must be uppercase snake case")


def scope_payload(scope: Scope, keys: list[str]) -> dict[str, Any]:
    validate_key_names(keys)
    return {
        "mount": scope.mount,
        "logical_path": scope.logical_path,
        "data_path": scope.data_path,
        "metadata_path": scope.metadata_path,
        "role_name": scope.role_name,
        "policy_name": scope.policy_name,
        "required_keys": keys,
        "policy_hcl": scope.policy_hcl,
        "safe_verification": [
            f"capabilities-self {scope.data_path}",
            f"capabilities-self {scope.metadata_path}",
            "presence check returns present/missing only",
        ],
        "runtime_contract": {
            "wrapper": ["secrets", "run", "--", "<command>", "<args>"],
            "sdk": "Provider.Get(ctx, path, key) / Provider.GetMap(ctx, path)",
        },
    }


def cmd_scope_plan(args: argparse.Namespace) -> int:
    scope = build_scope(args)
    payload = scope_payload(scope, args.key or [])
    if args.format == "json":
        json_print(payload)
    else:
        print(f"Mount: `{payload['mount']}`")
        print(f"Logical path: `{payload['logical_path']}`")
        print(f"Data path: `{payload['data_path']}`")
        print(f"Metadata path: `{payload['metadata_path']}`")
        print(f"Role: `{payload['role_name']}`")
        if payload["required_keys"]:
            print("Required keys: " + ", ".join(f"`{key}`" for key in payload["required_keys"]))
        print("\nPolicy:\n")
        print("```hcl")
        print(payload["policy_hcl"], end="")
        print("```")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    status, data = api_request(args, "GET", "sys/health?standbyok=true", token_required=False, allowed_status={200, 429, 501, 503})
    json_print(
        {
            "http_status": status,
            "initialized": data.get("initialized"),
            "sealed": data.get("sealed"),
            "standby": data.get("standby"),
            "performance_standby": data.get("performance_standby"),
            "version": data.get("version"),
        }
    )
    return 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    paths = list(args.path or [])
    if args.project:
        scope = build_scope(args)
        paths.extend([scope.data_path, scope.metadata_path])
    if not paths:
        raise CliError("provide --path or --project/--environment/--service")
    _, data = api_request(args, "POST", "sys/capabilities-self", {"paths": paths}, token_required=True)
    capabilities = {path: data.get(path, data.get("capabilities", [])) for path in paths}
    json_print({"paths": capabilities})
    return 0


def read_secret_file(path: str) -> dict[str, Any]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        candidate = Path(path)
        if is_git_tracked(candidate):
            raise CliError(f"refusing to read tracked secret input file: {candidate}")
        raw = candidate.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError(f"secret input must be a JSON object: {exc}") from exc
    if not isinstance(data, dict):
        raise CliError("secret input must be a JSON object")
    keys = sorted(str(key) for key in data)
    validate_key_names(keys)
    return data


def is_git_tracked(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(path.parent), "ls-files", "--error-unmatch", "--", path.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def cmd_write_kv(args: argparse.Namespace) -> int:
    scope = build_scope(args)
    secret_data = read_secret_file(args.secret_file)
    keys = sorted(secret_data)
    payload = {
        "mount": scope.mount,
        "logical_path": scope.logical_path,
        "data_path": scope.data_path,
        "keys": keys,
        "mode": "dry-run" if not args.apply else "applied",
    }
    if not args.apply:
        json_print(payload)
        return 0
    api_request(args, "POST", f"{scope.mount}/data/{scope.logical_path}", {"data": secret_data}, token_required=True)
    json_print(payload)
    return 0


def cmd_presence(args: argparse.Namespace) -> int:
    scope = build_scope(args)
    if not args.key:
        raise CliError("presence verification requires at least one --key")
    validate_key_names(args.key)
    _, data = api_request(args, "GET", f"{scope.mount}/data/{scope.logical_path}", token_required=True)
    values = data.get("data", {}).get("data", {})
    if not isinstance(values, dict):
        values = {}
    json_print(
        {
            "mount": scope.mount,
            "logical_path": scope.logical_path,
            "keys": {key: "present" if key in values else "missing" for key in args.key},
        }
    )
    return 0


def add_scope_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", required=True)
    parser.add_argument("--environment", "--env", dest="environment", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--mount", default="kv")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addr", help="OpenBao address. Defaults to BAO_ADDR, VAULT_ADDR, or https://127.0.0.1:8200")
    parser.add_argument("--tls-skip-verify", action="store_true", help="Disable TLS verification for local disposable testing only")
    parser.add_argument("--timeout", type=float, default=10.0)
    sub = parser.add_subparsers(dest="command", required=True)

    scope_plan = sub.add_parser("scope-plan", help="Render a non-secret scope and policy plan")
    add_scope_args(scope_plan)
    scope_plan.add_argument("--key", action="append", default=[], help="Required logical key name, repeatable")
    scope_plan.add_argument("--format", choices=("json", "md"), default="json")
    scope_plan.set_defaults(func=cmd_scope_plan)

    health = sub.add_parser("health", help="Check OpenBao health without a token")
    health.set_defaults(func=cmd_health)

    capabilities = sub.add_parser("capabilities", help="Query self capabilities without reading values")
    capabilities.add_argument("--path", action="append", default=[], help="OpenBao API path, repeatable")
    capabilities.add_argument("--project")
    capabilities.add_argument("--environment", "--env", dest="environment")
    capabilities.add_argument("--service")
    capabilities.add_argument("--mount", default="kv")
    capabilities.set_defaults(func=cmd_capabilities)

    write_kv = sub.add_parser("write-kv", help="Write KV v2 values from a local JSON object without printing values")
    add_scope_args(write_kv)
    write_kv.add_argument("--secret-file", required=True, help="JSON object file, or '-' for stdin")
    write_kv.add_argument("--apply", action="store_true", help="Actually write. Without this, output is a dry run.")
    write_kv.set_defaults(func=cmd_write_kv)

    presence = sub.add_parser("presence", help="Verify required KV v2 keys as present/missing only")
    add_scope_args(presence)
    presence.add_argument("--key", action="append", required=True, help="Required logical key name, repeatable")
    presence.set_defaults(func=cmd_presence)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

