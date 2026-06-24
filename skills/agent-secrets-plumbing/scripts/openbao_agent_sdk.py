"""Small SDK for agent-safe OpenBao operations.

The SDK may use BAO_TOKEN or VAULT_TOKEN from the local process environment,
but it must not return tokens or secret values to callers. Methods return safe
metadata such as status, paths, key names, capabilities, or present/missing.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
SAFE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
DEFAULT_ADDR = "https://127.0.0.1:8200"


class OpenBaoAgentError(Exception):
    """Expected failure without secret-bearing details."""


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
                raise OpenBaoAgentError(f"{label} must use only letters, numbers, '_' and '-'")

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


@dataclass(frozen=True)
class OpenBaoConfig:
    addr: str = DEFAULT_ADDR
    token: str | None = None
    tls_skip_verify: bool = False
    timeout: float = 10.0

    @classmethod
    def from_env(
        cls,
        *,
        addr: str | None = None,
        token_required: bool = True,
        tls_skip_verify: bool = False,
        timeout: float = 10.0,
    ) -> "OpenBaoConfig":
        token = os.environ.get("BAO_TOKEN") or os.environ.get("VAULT_TOKEN")
        if token_required and not token:
            raise OpenBaoAgentError("BAO_TOKEN or VAULT_TOKEN must be set in the local environment")
        effective_addr = addr or os.environ.get("BAO_ADDR") or os.environ.get("VAULT_ADDR") or DEFAULT_ADDR
        return cls(
            addr=effective_addr,
            token=token,
            tls_skip_verify=tls_skip_verify or bool_env("BAO_SKIP_VERIFY") or bool_env("VAULT_SKIP_VERIFY"),
            timeout=timeout,
        )


def bool_env(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}


def validate_key_names(keys: list[str]) -> None:
    for key in keys:
        if not SAFE_KEY.match(key):
            raise OpenBaoAgentError(f"key name {key!r} must be uppercase snake case")


def scope_payload(scope: Scope, keys: list[str]) -> dict[str, Any]:
    scope.validate()
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
            "sdk": "OpenBaoClient.from_env().kv2_presence(scope, keys)",
        },
    }


class OpenBaoClient:
    def __init__(self, config: OpenBaoConfig):
        self._config = config

    @classmethod
    def from_env(
        cls,
        *,
        addr: str | None = None,
        token_required: bool = True,
        tls_skip_verify: bool = False,
        timeout: float = 10.0,
    ) -> "OpenBaoClient":
        return cls(
            OpenBaoConfig.from_env(
                addr=addr,
                token_required=token_required,
                tls_skip_verify=tls_skip_verify,
                timeout=timeout,
            )
        )

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token_required: bool = True,
        allowed_status: set[int] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        allowed_status = allowed_status or {200}
        base = self._config.addr.rstrip("/")
        url = f"{base}/v1/{path.lstrip('/')}"
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token_required:
            if not self._config.token:
                raise OpenBaoAgentError("BAO_TOKEN or VAULT_TOKEN must be set in the local environment")
            headers["X-Vault-Token"] = self._config.token

        context = None
        if self._config.tls_skip_verify:
            context = ssl._create_unverified_context()

        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._config.timeout, context=context) as response:
                status = response.getcode()
                data = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            data = exc.read()
        except urllib.error.URLError as exc:
            raise OpenBaoAgentError(f"OpenBao request failed for {method} /v1/{path}: {exc.reason}") from exc

        if status not in allowed_status:
            raise OpenBaoAgentError(f"OpenBao returned HTTP {status} for {method} /v1/{path}")

        if not data:
            return status, {}
        try:
            parsed = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            return status, {}
        if not isinstance(parsed, dict):
            return status, {}
        return status, parsed

    def health(self) -> dict[str, Any]:
        status, data = self.request(
            "GET",
            "sys/health?standbyok=true",
            token_required=False,
            allowed_status={200, 429, 501, 503},
        )
        return {
            "http_status": status,
            "initialized": data.get("initialized"),
            "sealed": data.get("sealed"),
            "standby": data.get("standby"),
            "performance_standby": data.get("performance_standby"),
            "version": data.get("version"),
        }

    def capabilities(self, paths: list[str]) -> dict[str, Any]:
        _, data = self.request("POST", "sys/capabilities-self", {"paths": paths}, token_required=True)
        return {"paths": {path: data.get(path, data.get("capabilities", [])) for path in paths}}

    def kv2_write(self, scope: Scope, values: dict[str, Any]) -> dict[str, Any]:
        scope.validate()
        keys = sorted(str(key) for key in values)
        validate_key_names(keys)
        self.request("POST", f"{scope.mount}/data/{scope.logical_path}", {"data": values}, token_required=True)
        return {
            "mount": scope.mount,
            "logical_path": scope.logical_path,
            "data_path": scope.data_path,
            "keys": keys,
            "mode": "applied",
        }

    def kv2_presence(self, scope: Scope, keys: list[str]) -> dict[str, Any]:
        scope.validate()
        validate_key_names(keys)
        _, data = self.request("GET", f"{scope.mount}/data/{scope.logical_path}", token_required=True)
        values = data.get("data", {}).get("data", {})
        if not isinstance(values, dict):
            values = {}
        return {
            "mount": scope.mount,
            "logical_path": scope.logical_path,
            "keys": {key: "present" if key in values else "missing" for key in keys},
        }


def read_secret_file(path: str) -> dict[str, Any]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        candidate = Path(path)
        if is_git_tracked(candidate):
            raise OpenBaoAgentError(f"refusing to read tracked secret input file: {candidate}")
        raw = candidate.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OpenBaoAgentError(f"secret input must be a JSON object: {exc}") from exc
    if not isinstance(data, dict):
        raise OpenBaoAgentError("secret input must be a JSON object")
    validate_key_names(sorted(str(key) for key in data))
    return data


def dry_run_write_payload(scope: Scope, values: dict[str, Any]) -> dict[str, Any]:
    scope.validate()
    keys = sorted(str(key) for key in values)
    validate_key_names(keys)
    return {
        "mount": scope.mount,
        "logical_path": scope.logical_path,
        "data_path": scope.data_path,
        "keys": keys,
        "mode": "dry-run",
    }


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
