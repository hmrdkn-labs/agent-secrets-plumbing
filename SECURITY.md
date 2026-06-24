# Security Policy

## Reporting

Report suspected vulnerabilities or unsafe examples privately through GitHub
security advisories for this repository. Do not open public issues containing
secret values, tokens, private keys, unseal/recovery material, database dumps,
or decrypted configuration.

## Scope

In scope:

- Examples that can cause agents to print, export, hash, prefix, encode, or
  otherwise disclose secret values.
- Scripts that miss obvious leaked values or create plaintext secret artifacts.
- Guidance that grants overbroad access, normalizes runtime root/admin tokens,
  or suggests unsafe MCP tools.

Out of scope:

- Requests to add secret-reading or secret-writing MCP tools to v1.
- Reports that require sharing real credentials. Use synthetic canaries and
  redacted reproductions instead.

## Project Rule

This repository must not contain real secret values. Verification should use
synthetic canaries and assert absence from stdout, stderr, files, logs, and
artifacts.

