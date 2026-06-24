# CI OIDC

Use this reference when reviewing CI/CD secret access, especially GitHub
Actions.

## Preferred Pattern

Use OpenID Connect to exchange a job-scoped identity token for short-lived cloud
or secret-manager credentials. Configure the receiving provider to trust only
the intended repository, branch/tag, workflow, environment, and audience.

## Review Checklist

- Job permissions are minimal. `id-token: write` appears only on jobs that need
  federation.
- `contents: read` is explicit unless the workflow needs broader repository
  permissions.
- Trust policy constrains `aud` and `sub` claims.
- Deployment environments have protection rules when production is involved.
- Pull request workflows do not expose privileged secrets to untrusted code.
- Static cloud access keys are absent when OIDC is available.
- Workflow logs do not run shell tracing, print environment variables, or dump
  provider token responses.

## Unsafe Patterns

- Long-lived cloud access keys in repository or organization secrets.
- Wildcard trust for all repositories or all branches in an organization.
- `pull_request_target` workflows that execute untrusted code with privileged
  tokens.
- Debugging steps that print full environment, credentials, or token JSON.

Sources:

- https://docs.github.com/en/actions/concepts/security/openid-connect
- https://docs.github.com/en/actions/reference/security/oidc
- https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers
- https://docs.github.com/en/actions/reference/security/secure-use

