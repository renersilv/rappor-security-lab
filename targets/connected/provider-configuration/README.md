# Controlled provider configuration target

This target establishes independent ground truth for the connected Supabase and
Vercel configuration rules currently in scope. It does not call Rappor Security
and does not retain provider responses.

## Supabase

The lifecycle uses the existing disposable laboratory project and protected
PostgreSQL service. Seven Security Advisor families are pinned to the immutable
`supabase/splinter` `2026.08.0` revision. Each condition is represented by an
empty synthetic object and proven by bounded PostgreSQL catalog predicates. The
existing authorization checks also run in every state with the disposable dummy
user; no row body or user identifier is retained.

The schema migration starts from the safe configuration. The vulnerable,
partially fixed, fixed and reintroduced migrations change only declared
laboratory objects. The Storage fixture creates an empty synthetic bucket and
never uploads an object. Cleanup runs in `finally`, drops every fixture and
verifies the authorization relation, configuration objects, bucket and policy are
all absent.

Runtime configuration stays outside Git and uses the same protected
`SUPABASE_LAB_*`, `PGSERVICEFILE` and `PGPASSFILE` values documented by the
authorization target. Run only against the owner-authorized disposable project:

```sh
npm run provider:supabase -- \
  --source-commit <full-laboratory-commit> \
  --json /tmp/supabase-provider-configuration.json \
  --markdown /tmp/supabase-provider-configuration.md
```

## Vercel

The lifecycle uses only the four existing `rappor-lab-*` controlled projects in
the isolated `rappor-security-tests` scope. It reads and updates only
`gitForkProtection` through the official project API using the pinned Vercel CLI.
The runner first establishes a safe baseline, verifies vulnerable, negative and
reintroduced states independently, and restores `gitForkProtection=true` on all
four projects in `finally`.

The CLI's saved authentication remains outside Git. The runner discards account
and project identifiers, environment variables and every unused API field in
memory:

```sh
npm run provider:vercel -- \
  --source-commit <full-laboratory-commit> \
  --json /tmp/vercel-provider-configuration.json \
  --markdown /tmp/vercel-provider-configuration.md
```

Always verify temporary reports before admitting a dated observation:

```sh
node src/verify-provider-configuration-report.mjs /tmp/report.json /tmp/report.md
```

Do not add provider management tokens, project identifiers, raw responses,
visitor data, source code, logs, users, rows or credentials to the repository.
