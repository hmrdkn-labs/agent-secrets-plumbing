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

