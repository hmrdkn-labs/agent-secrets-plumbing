# Incident And Rotation

Use this reference when a credential may be exposed, stale, over-privileged, or
due for planned rotation.

## Incident Rule

Do not ask the user to paste the suspect value. Work from metadata: affected
service, backend, path, key name, deployment surface, approximate exposure
window, and consumer inventory.

## Rotation Playbook

1. Identify consumers and deployment paths for the logical key name.
2. Create a replacement credential in the upstream system.
3. Store the replacement in the secret backend without printing it.
4. Deploy consumers to use the replacement.
5. Verify with presence booleans, health checks, capability checks, and denied
   use of old identity where possible.
6. Revoke or disable the old credential at the upstream source.
7. Review logs/artifacts for disclosure and rotate any dependent credentials.
8. Record metadata-only evidence: affected key name, systems touched, time
   range, verification status, and follow-up actions.

## What Not To Automate In The Base Skill

- No raw secret generation in chat.
- No default `rotate_secret` MCP tool.
- No blind overwrite of production values.
- No rotation without consumer inventory and rollback plan.

## Static Secret Note

KV v2 versioning is not the same as revocation. Replacing a KV value does not
invalidate a database password, API token, or cloud credential at its source.

Sources:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- https://openbao.org/docs/secrets/kv/kv-v2/
- https://openbao.org/docs/concepts/lease/

