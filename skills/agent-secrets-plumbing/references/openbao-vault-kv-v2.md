# OpenBao/Vault KV v2

Use this reference when designing or reviewing OpenBao/Vault-compatible static
app secret plumbing.

## Path Model

Default mount: `kv`

Default logical path:

```text
projects/<project>/<environment>/<service>
```

Runtime read policy must account for KV v2 API paths:

```hcl
path "kv/data/projects/<project>/<environment>/<service>" {
  capabilities = ["read"]
}

path "kv/metadata/projects/<project>/<environment>/<service>" {
  capabilities = ["read"]
}
```

Do not add `list` unless discovery is truly needed; listing can reveal key
names. Do not grant broad wildcards such as project-wide or environment-wide
runtime reads.

## Identity

- Prefer workload-native auth where possible, such as Kubernetes/JWT/OIDC.
- Use AppRole for machine identity when no better platform identity exists.
- Use one runtime identity per `<project>/<environment>/<service>`.
- Treat RoleID as identifier-like and SecretID as password-like.
- Use bounded TTLs and low use counts for bootstrap credentials.

## Response Wrapping

Use response wrapping for bootstrap handoff. The receiver should look up
wrapping metadata, validate the creation path and TTL, unwrap once, and alert on
missing, expired, already-used, or wrong-path wrapping tokens. Never unwrap into
chat or saved logs.

## Rotation

KV v2 static secrets are versioned values, not leased dynamic credentials.
Rotation must update the upstream system and the KV value together, shift
consumers, verify without printing the value, then revoke or disable the old
credential at its source.

## Safe Verification

- Check `bao status` and sealed/initialized state without printing tokens.
- Use capability checks for expected allow/deny paths.
- Use metadata/subkey shape when available instead of reading values.
- Confirm denied access across sibling project/env/service paths.
- Confirm app health endpoints return booleans or status classes only.

Sources:

- https://openbao.org/docs/secrets/kv/kv-v2/
- https://openbao.org/api-docs/secret/kv/kv-v2/
- https://openbao.org/docs/auth/approle/
- https://openbao.org/api-docs/auth/approle/
- https://openbao.org/docs/concepts/policies/
- https://openbao.org/docs/concepts/response-wrapping/
- https://openbao.org/docs/concepts/lease/
- https://openbao.org/docs/audit/

