# OpenBao Agent CLI

Use this reference when a local self-hosted OpenBao needs an agent-safe command
surface.

## Command

```sh
skills/agent-secrets-plumbing/scripts/openbao-agent.py <command>
```

Configuration:

- `BAO_ADDR` or `VAULT_ADDR`: OpenBao/Vault URL.
- `BAO_TOKEN` or `VAULT_TOKEN`: local token for authenticated actions.
- `--tls-skip-verify`: local disposable testing only.

Do not pass tokens as command-line flags. Command arguments can end up in shell
history and process listings.

## SDK Boundary

Use `openbao_agent_sdk.py` when another agent tool or script needs the same
OpenBao behavior without copying token-handling code. The SDK reads
`BAO_TOKEN` or `VAULT_TOKEN` from the local process environment for live
authenticated operations, sends it to OpenBao as the request token, and returns
only safe metadata.

Minimal pattern:

```python
from openbao_agent_sdk import OpenBaoClient, Scope

scope = Scope("billing", "staging", "api")
client = OpenBaoClient.from_env()
status = client.kv2_presence(scope, ["DATABASE_URL", "API_TOKEN"])
print(status)
```

Allowed SDK return data: health status, paths, key names, capabilities, and
`present` / `missing`. Do not add SDK methods that return raw secret values to
the caller by default.

## Safe Commands

Render a scope and policy without contacting OpenBao:

```sh
openbao-agent.py scope-plan \
  --project billing \
  --environment staging \
  --service api \
  --key DATABASE_URL \
  --key API_TOKEN \
  --format md
```

Check health without a token:

```sh
openbao-agent.py --addr "$BAO_ADDR" health
```

Check capabilities without reading values:

```sh
openbao-agent.py --addr "$BAO_ADDR" capabilities \
  --project billing \
  --environment staging \
  --service api
```

Dry-run a KV v2 write from a local JSON object:

```sh
openbao-agent.py write-kv \
  --project billing \
  --environment staging \
  --service api \
  --secret-file /path/to/local-secrets.json
```

Apply the write only after the local operator has reviewed the file path and
token scope:

```sh
openbao-agent.py write-kv \
  --project billing \
  --environment staging \
  --service api \
  --secret-file /path/to/local-secrets.json \
  --apply
```

Verify required keys without printing values:

```sh
openbao-agent.py presence \
  --project billing \
  --environment staging \
  --service api \
  --key DATABASE_URL \
  --key API_TOKEN
```

## Output Contract

The CLI may print:

- mount and logical path
- policy HCL
- key names
- `present` / `missing`
- capability lists
- health fields such as initialized/sealed/standby/version

The CLI must not print values, tokens, SecretIDs, unseal material, private keys,
or full KV payloads.

## Sources

- https://openbao.org/api-docs/
- https://openbao.org/api-docs/system/health/
- https://openbao.org/api-docs/system/seal-status/
- https://openbao.org/api-docs/system/capabilities-self/
- https://openbao.org/docs/secrets/kv/kv-v2/
