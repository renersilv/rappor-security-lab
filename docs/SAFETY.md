# Laboratory safety

## Isolation

Laboratory deployments use dedicated accounts, projects, domains and databases. They have no peering, shared credentials, shared data, callback trust or administrative path to production or Rappor Security infrastructure.

## Synthetic secrets

- Use the Rappor-owned non-functional marker family for deterministic public fixtures.
- A provider-shaped fixture must be explicitly synthetic or revoked, isolated from any account and documented in the ground-truth manifest.
- Never create a functioning elevated credential merely to test its detection.
- Never copy a real leaked credential from an incident report, repository or customer environment.

## Public targets

- Owned targets contain only dummy data and no user registration or persistent user-supplied content.
- Vulnerable states expose only synthetic material and remain isolated from privileged services.
- Third-party targets must be listed by exact URL with evidence that the operator intended them for security testing.
- Third-party execution is limited to the passive behavior already implemented by the Rappor Security public scan.

## Connected Supabase validation

- Use a disposable laboratory organization and project.
- Store only generated dummy rows.
- Public applications use only publishable credentials.
- Administrative access is supplied outside Git and never sent to the browser.
- Authorization checks target declared laboratory tables and avoid retrieving unnecessary row contents.
- Delete or reset the disposable project when its benchmark lifecycle ends.

## Incident response

Stop the affected target immediately if a real credential, real person, unexpected external system or non-dummy record appears. Revoke the credential through the provider, preserve only sanitized metadata and notify the owner through a private channel.

