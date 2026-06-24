# End-To-End Recipe

Use this reference when the task spans local development, CI/CD, GitOps, and
Kubernetes runtime for one service.

## Target Shape

| Layer | Default | Purpose |
| --- | --- | --- |
| Canonical store | OpenBao/Vault KV v2 | Source of truth for shared app secrets |
| Local dev | 1Password `op://` references with `op run` | Human-local process injection |
| CI/CD | GitHub Actions OIDC | Short-lived deploy identity |
| GitOps | SOPS/age only for confidential material that must live in Git | Encrypted declarative config |
| Kubernetes runtime | External Secrets Operator, or Secrets Store CSI for mounted-file apps | Delivery into pods |

## Service Contract

- Required names are logical names such as `DATABASE_URL` and `API_TOKEN`.
- OpenBao/Vault mount is a backend setting such as `kv`.
- Logical path is `projects/<project>/<environment>/<service>`.
- Runtime policy/API paths combine mount and logical path with KV v2 `data` and
  `metadata`.

## Safe Implementation Sequence

1. Infer required secret names from code and manifests.
2. Choose the canonical backend and path template.
3. Design least-privilege runtime policy for one service.
4. Pick injection mode:
   - local developer command: `op run -- <command>`
   - existing app runtime: `secrets run -- <command>`
   - new app runtime: SDK/provider interface
   - Kubernetes env/secretKeyRef: ESO
   - Kubernetes mounted file: CSI
5. Write GitOps manifests with references and placeholders only.
6. Verify without values.

## Safe Verification Cookbook

Use these command shapes only after replacing placeholders locally. Do not paste
resulting secret-bearing output into chat.

```sh
gh workflow view <workflow>
gh run view <run-id> --json conclusion,status
```

```sh
bao status
bao token capabilities kv/data/projects/<project>/<environment>/<service>
bao token capabilities kv/data/projects/<project>/<environment>/<other-service>
```

```sh
sops --decrypt --output /dev/null <encrypted-file>
```

```sh
kubectl get externalsecret -n <namespace>
kubectl get secretstore -n <namespace>
kubectl describe pod -n <namespace> <pod>
```

Acceptable evidence: status, allowed/denied classes, resource readiness, and
presence booleans. Unacceptable evidence: raw secret values, hashes, prefixes,
lengths, token JSON, or decoded Kubernetes Secret data.

Sources:

- https://docs.github.com/en/actions/concepts/security/openid-connect
- https://external-secrets.io/latest/provider/openbao/
- https://secrets-store-csi-driver.sigs.k8s.io/
- https://getsops.io/docs/
- https://www.1password.dev/cli/secret-references

