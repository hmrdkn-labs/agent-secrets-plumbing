# Kubernetes Secrets

Use this reference when reviewing Kubernetes secret delivery.

## External Secrets Operator

Use ESO when workloads need native Kubernetes Secret objects. Keep the external
secret manager as the source of truth and scope Kubernetes access carefully.

Review:

- Prefer namespaced `SecretStore` over cluster-wide stores when possible.
- Restrict RBAC on `ExternalSecret`, `SecretStore`, `ClusterSecretStore`, and
  native `Secret` resources.
- Avoid cross-namespace references unless there is a clear platform boundary.
- Confirm etcd encryption and audit logging for clusters that store Secrets.
- Confirm rotation and workload restart behavior.

## Secrets Store CSI Driver

Use CSI when workloads can consume mounted files and you want to avoid syncing
values into Kubernetes Secret objects.

Review:

- Avoid syncing to Kubernetes Secrets unless required.
- Avoid `subPath` for secret mounts because rotation behavior can break.
- Confirm provider identity and namespace boundaries.
- Ensure applications can reload or restart when mounted values rotate.

## Unsafe Patterns

- Treating base64 Kubernetes Secret data as encryption.
- Committing plaintext Secret manifests.
- Granting broad `get/list/watch` access to Secrets.
- Using cluster-scoped secret stores in multi-tenant clusters without policy
  controls.

Sources:

- https://kubernetes.io/docs/concepts/security/secrets-good-practices/
- https://external-secrets.io/latest/
- https://external-secrets.io/latest/guides/security-best-practices/
- https://secrets-store-csi-driver.sigs.k8s.io/
- https://secrets-store-csi-driver.sigs.k8s.io/topics/best-practices

