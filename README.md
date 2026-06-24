# Agent Secrets Plumbing

Agent Secrets Plumbing is a skill-first package for helping AI coding agents
design, review, and verify secrets plumbing without exposing secret values.

V1 deliberately ships no secret-reading MCP server. The safe default is an
Agent Skills-compatible workflow package with references and deterministic
checks for non-leaking reviews, injection plans, OpenBao/Vault policy scope,
GitHub Actions OIDC, SOPS/age, 1Password CLI, and Kubernetes secret delivery.

## What It Provides

- A portable skill at `skills/agent-secrets-plumbing/SKILL.md`.
- One-hop references for OpenBao/Vault KV v2, CI OIDC, SOPS/age, Kubernetes
  ESO/CSI, runtime injection, backend selection, and threat modeling.
- Stdlib-only scripts that scan for risky surfaces, lint OpenBao/Vault policy,
  render required secret names without values, and test redaction behavior.
- Thin Codex and Claude plugin manifests for distribution.

## Safety Boundary

This repository is for metadata, policy, review, and safe verification. It must
not fetch, print, export, write, rotate, decrypt, or materialize secret values.
Generated outputs use placeholders, key names, capability checks, status
classes, and boolean presence checks.

## Quick Checks

```sh
skills/agent-secrets-plumbing/scripts/validate-package.sh
```

Run individual tools:

```sh
skills/agent-secrets-plumbing/scripts/secret-surface-audit.py <repo>
skills/agent-secrets-plumbing/scripts/openbao-policy-lint.py <policy-file>
skills/agent-secrets-plumbing/scripts/redaction-regression.py --canary <value> <path...>
skills/agent-secrets-plumbing/scripts/render-secret-requirements.py <repo> --format md
```

## Source Basis

This package distills current public guidance from OpenBao, OWASP, GitHub
Actions OIDC, SOPS, 1Password, Kubernetes External Secrets Operator, Secrets
Store CSI Driver, Agent Skills, and MCP security documentation. Source URLs are
kept in the reference files; no full public documentation mirrors are stored.

