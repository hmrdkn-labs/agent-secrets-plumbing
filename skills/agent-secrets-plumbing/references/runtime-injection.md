# Runtime Injection

Use this reference when converting code from plaintext local config to safer
runtime secret delivery.

## Existing Apps

Prefer a child-process wrapper when the app already reads environment
variables:

```text
secrets run -- <command-argv>
```

Keep mount and logical path separate. For OpenBao/Vault KV v2, a common mount is
`kv`, while the logical secret path remains
`projects/<project>/<environment>/<service>`. Policy/API paths combine them as
`kv/data/projects/<project>/<environment>/<service>` and
`kv/metadata/projects/<project>/<environment>/<service>`.

The wrapper should fetch values inside the process boundary, inject them into
the child process environment, fail before launching the child on auth/backend
errors, and avoid writing materialized `.env` files.

## New Apps

Use a small provider interface and keep backend client details inside one
adapter. Example shape:

```go
type Provider interface {
    Get(ctx context.Context, path string, key string) (string, error)
    GetMap(ctx context.Context, path string) (map[string]string, error)
}
```

App code should depend on the interface, not on raw OpenBao/Vault API routes.

## 1Password Local Development

Use `op://` references and `op run` for runtime substitution. Treat references
as pointers, not values. Avoid `op read` or `op inject` flows that write
plaintext into tracked files or agent-visible output.

## Sidecars And Mounted Files

Sidecars and file mounts can reduce environment-variable exposure, but require
clear reload behavior. Confirm whether apps reload files, need restarts, or can
receive signals after rotation.

## Safe Output Contract

Plans may show:

- required key names
- backend choice
- placeholder path templates
- command argument arrays with placeholders
- SDK interface shapes
- verification by booleans/status

Plans must not show values.

Sources:

- https://openbao.org/docs/agent-and-proxy/
- https://www.1password.dev/cli/secret-references
- https://www.1password.dev/cli/best-practices
