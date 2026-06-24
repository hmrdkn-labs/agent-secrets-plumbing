# SOPS And Age

Use this reference when a repo needs encrypted declarative configuration in Git.

## Default Pattern

- Store encrypted YAML/JSON/ENV/INI files with SOPS.
- Use age or cloud KMS recipients according to team and platform needs.
- Use `.sops.yaml` creation rules by path and environment.
- Keep age private identities and cloud decrypt rights outside the repository
  and outside agent-visible context.
- Decrypt only inside a local human session, CI step, or controller runtime
  that is allowed to see the plaintext.

## Agent Rules

- Do not ask the user to paste decrypted output.
- Do not run decrypt commands that print plaintext into chat.
- Do not write decrypted plaintext to tracked paths.
- Prefer redacted diffs, metadata checks, and rule validation.

## Review Checklist

- `.sops.yaml` exists and maps environment paths to intended recipients.
- Encrypted files are not mixed with plaintext copies.
- Decrypt commands write to runtime-only sinks, never tracked files.
- GitOps controllers have only the decrypt rights they need.
- Private age identities are not present in the repo, CI logs, or artifacts.

Sources:

- https://getsops.io/docs/
- https://github.com/getsops/sops
- https://fluxcd.io/flux/guides/mozilla-sops/

