#!/usr/bin/env python3
"""Agent-safe OpenBao helper CLI.

This CLI is a thin wrapper around openbao_agent_sdk.py. The SDK consumes
BAO_TOKEN or VAULT_TOKEN locally when live authenticated calls are requested,
but CLI output remains metadata-only.
"""

from __future__ import annotations

import argparse
import json
import sys

from openbao_agent_sdk import (
    OpenBaoAgentError,
    OpenBaoClient,
    Scope,
    dry_run_write_payload,
    read_secret_file,
    scope_payload,
    validate_key_names,
)


def json_print(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def build_scope(args: argparse.Namespace) -> Scope:
    scope = Scope(args.project, args.environment, args.service, args.mount)
    scope.validate()
    return scope


def client_from_args(args: argparse.Namespace, *, token_required: bool = True) -> OpenBaoClient:
    return OpenBaoClient.from_env(
        addr=args.addr,
        token_required=token_required,
        tls_skip_verify=args.tls_skip_verify,
        timeout=args.timeout,
    )


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
    json_print(client_from_args(args, token_required=False).health())
    return 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    paths = list(args.path or [])
    if args.project:
        scope = build_scope(args)
        paths.extend([scope.data_path, scope.metadata_path])
    if not paths:
        raise OpenBaoAgentError("provide --path or --project/--environment/--service")
    json_print(client_from_args(args).capabilities(paths))
    return 0


def cmd_write_kv(args: argparse.Namespace) -> int:
    scope = build_scope(args)
    secret_data = read_secret_file(args.secret_file)
    if not args.apply:
        json_print(dry_run_write_payload(scope, secret_data))
        return 0
    json_print(client_from_args(args).kv2_write(scope, secret_data))
    return 0


def cmd_presence(args: argparse.Namespace) -> int:
    scope = build_scope(args)
    validate_key_names(args.key)
    json_print(client_from_args(args).kv2_presence(scope, args.key))
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
    except OpenBaoAgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
