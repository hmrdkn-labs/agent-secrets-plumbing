# Backend Matrix

Use this reference to choose the simplest safe secret delivery pattern for a
repo or workflow.

## Defaults

| Situation | Preferred pattern | Avoid |
| --- | --- | --- |
| Static app secrets | OpenBao/Vault KV v2 with path-scoped runtime identity | Shared root/admin token |
| CI to cloud or Vault | GitHub Actions OIDC with constrained trust claims | Long-lived cloud keys in GitHub secrets |
| GitOps config | SOPS with age or cloud KMS | Plaintext YAML or decrypted artifacts |
| Local developer runtime | 1Password secret references with `op run` | `op read` into chat or tracked files |
| Kubernetes native Secret needed | External Secrets Operator with namespace/RBAC boundaries | Cluster-wide store without policy controls |
| Kubernetes mounted files enough | Secrets Store CSI Driver | Syncing to Kubernetes Secrets by default |

## Selection Notes

- Prefer platform identity over manually distributed credentials when the
  platform can prove workload identity.
- Prefer child-process injection for existing applications that already consume
  environment variables.
- Prefer a small SDK/provider interface for new services so backend details do
  not spread through application code.
- Prefer metadata and capability checks over value reads for verification.
- Consider restart and rotation behavior before choosing environment variables,
  mounted files, sidecars, or synced Kubernetes Secrets.

Sources:

- https://openbao.org/docs/secrets/kv/kv-v2/
- https://docs.github.com/en/actions/concepts/security/openid-connect
- https://getsops.io/docs/
- https://www.1password.dev/cli/secret-references
- https://external-secrets.io/latest/guides/security-best-practices/
- https://secrets-store-csi-driver.sigs.k8s.io/

