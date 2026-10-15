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

## HML connected-analysis gate

The provider mutations above are independent ground truth. The HML comparison is
performed by `src/run-connected-service-lifecycle.mjs`, which selects resources
from `GET /api/integrations/connected-services/`, creates missing configurations
through `POST /api/products/:id/connected-service-analyses`, starts assessments
through the published analysis-definition execution contract and polls them with
a fixed bound. Provider response bodies and HML identifiers remain transient or
in a protected external checkpoint. The checkpoint binds each provider to one
visible HML version and one full laboratory commit. Retesting a new deployment
baseline therefore uses a new checkpoint path and preserves the earlier file as
historical private evidence.

Vercel expects the four exact controlled projects declared in `lib/states.mjs`.
Supabase expects exactly one disposable project and applies all four states to
that resource. Both adapters restore the safe provider state in `finally` and
verify the post-condition. A connection that is not `Active`, a resource that is
not `Authorized`, partial coverage, a terminal scanner failure, timeout or cleanup
failure produces a non-clean outcome.

The Supabase comparator maps the seven independent manifest advisor cases to the
four canonical families published by the connected-analysis contract. Three
manifest cases have no comparable published coverage check; they stay explicit
and make manifest coverage `Inconclusive` instead of being inferred from another
family. Findings are grouped by canonical family and logical synthetic object.
Multiple objects in one family are distinct affected items; only another finding
for the same family and object, or a repeated transient fingerprint, is counted as
a true duplicate. Raw fingerprints, issue and occurrence identifiers, locations
and evidence are excluded from the report.

Across vulnerable, partially fixed, fixed and reintroduced states, the report
validates measured finding transitions, score progression, resolution,
reintroduction and history independently. Any measured mismatch is non-clean;
an unmeasured published capability remains `Inconclusive`.
