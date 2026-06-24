#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SKILL="$ROOT/skills/agent-secrets-plumbing"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== skill validation =="
if [ -f "/Users/hamardikan-mac/.codex/skills/.system/skill-creator/scripts/quick_validate.py" ]; then
  python3 /Users/hamardikan-mac/.codex/skills/.system/skill-creator/scripts/quick_validate.py "$SKILL"
else
  test -f "$SKILL/SKILL.md"
  grep -q '^name: agent-secrets-plumbing$' "$SKILL/SKILL.md"
  grep -q '^description: ' "$SKILL/SKILL.md"
fi

echo "== syntax =="
python3 -m py_compile "$SKILL"/scripts/*.py
bash -n "$SKILL/scripts/validate-package.sh"
python3 -m json.tool "$ROOT/.codex-plugin/plugin.json" >/dev/null
python3 -m json.tool "$ROOT/.claude-plugin/plugin.json" >/dev/null

echo "== fixture: secret-surface-audit catches leaks =="
mkdir -p "$TMP/bad/.github/workflows"
printf 'APP_MODE=dev\n' > "$TMP/bad/.env"
{
  printf '%s\n' '-----BEGIN PRIVATE'
  printf '%s\n' 'KEY-----'
  printf '%s\n' 'fixture'
  printf '%s\n' '-----END PRIVATE'
  printf '%s\n' 'KEY-----'
} > "$TMP/bad/key.pem"
printf 'VAULT_%s=%s\n' 'TOKEN' 'dev-fixture-value' > "$TMP/bad/config.txt"
cat > "$TMP/bad/.github/workflows/deploy.yml" <<'YAML'
name: deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: printenv
YAML
if "$SKILL/scripts/secret-surface-audit.py" "$TMP/bad" >/dev/null; then
  echo "expected secret-surface-audit to fail on bad fixture" >&2
  exit 1
fi

echo "== fixture: policy lint =="
cat > "$TMP/safe.hcl" <<'HCL'
path "kv/data/projects/app/dev/api" {
  capabilities = ["read"]
}

path "kv/metadata/projects/app/dev/api" {
  capabilities = ["read"]
}
HCL
"$SKILL/scripts/openbao-policy-lint.py" "$TMP/safe.hcl" >/dev/null
cat > "$TMP/bad.hcl" <<'HCL'
path "kv/data/projects/*" {
  capabilities = ["read", "update", "delete"]
}
HCL
if "$SKILL/scripts/openbao-policy-lint.py" "$TMP/bad.hcl" >/dev/null; then
  echo "expected openbao-policy-lint to fail on broad policy" >&2
  exit 1
fi

echo "== fixture: redaction regression =="
CANARY="agent_skill_canary_1234567890"
printf 'safe output\n' > "$TMP/safe-output.txt"
"$SKILL/scripts/redaction-regression.py" --canary "$CANARY" "$TMP/safe-output.txt" >/dev/null
printf 'contains %s\n' "$CANARY" > "$TMP/leaky-output.txt"
if "$SKILL/scripts/redaction-regression.py" --canary "$CANARY" "$TMP/leaky-output.txt" >/dev/null; then
  echo "expected redaction-regression to fail on canary" >&2
  exit 1
fi

echo "== fixture: requirements renderer =="
mkdir -p "$TMP/app"
cat > "$TMP/app/main.py" <<'PY'
# fixture-only: logical names, no values
import os
dsn = os.getenv("DATABASE_URL")
token = os.getenv("API_TOKEN")
PY
"$SKILL/scripts/render-secret-requirements.py" "$TMP/app" --format json > "$TMP/requirements.json"
grep -q '"DATABASE_URL"' "$TMP/requirements.json"
grep -q '"API_TOKEN"' "$TMP/requirements.json"

echo "== fixture: openbao agent cli =="
"$SKILL/scripts/openbao-agent.py" scope-plan \
  --project billing \
  --environment staging \
  --service api \
  --key DATABASE_URL \
  --format json > "$TMP/scope.json"
grep -q '"logical_path": "projects/billing/staging/api"' "$TMP/scope.json"
grep -q '"data_path": "kv/data/projects/billing/staging/api"' "$TMP/scope.json"
cat > "$TMP/local-secrets.json" <<'JSON'
{
  "DATABASE_URL": "agent_skill_canary_database_value",
  "API_TOKEN": "agent_skill_canary_token_value"
}
JSON
"$SKILL/scripts/openbao-agent.py" write-kv \
  --project billing \
  --environment staging \
  --service api \
  --secret-file "$TMP/local-secrets.json" > "$TMP/write-dry-run.json"
grep -q '"mode": "dry-run"' "$TMP/write-dry-run.json"
grep -q '"DATABASE_URL"' "$TMP/write-dry-run.json"
if grep -q 'agent_skill_canary_' "$TMP/write-dry-run.json"; then
  echo "openbao-agent.py dry-run leaked a canary value" >&2
  exit 1
fi

echo "== repo redaction =="
"$SKILL/scripts/redaction-regression.py" "$ROOT/README.md" "$ROOT/SECURITY.md" "$SKILL/SKILL.md" "$SKILL/references" >/dev/null

echo "OK: package validation passed"
