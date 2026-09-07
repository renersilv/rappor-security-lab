# Disposable Supabase authorization target

This target reproduces four authorization states on one laboratory-only relation:

| State | RLS | `anon` read | `anon` write | `authenticated` read | `authenticated` write |
| --- | --- | --- | --- | --- | --- |
| `vulnerable` | disabled | allow | allow | allow | allow |
| `partially-fixed` | enabled | allow | deny | allow | allow |
| `fixed` | enabled | deny | deny | allow | allow |
| `reintroduced` | disabled | allow | allow | allow | allow |

Every lifecycle pass recreates `public.rappor_lab_documents`, inserts one fixed
dummy seed row, applies one state migration and tests all four actor/operation
pairs. Read checks use `HEAD` plus `Prefer: count=exact`; write checks use
`Prefer: return=minimal`. No row body, inserted identifier, credential, project
reference or user identifier is retained in the run report.

## Isolation and prerequisites

Project creation is an owner action. Create a disposable project inside the
laboratory-only Supabase organization with bounded spend and no network, identity,
credential or callback shared with production or Rappor Security. Keep only the
single relation created here and one manually confirmed dummy Auth user. Disable
public sign-up after creating that user.

Use a current publishable key (`sb_publishable_...`) for every Data API and Auth
request. Do not create or supply a secret or `service_role` key to this target.
Administrative SQL uses `psql` and a PostgreSQL service definition stored outside
the repository, for example in a mode-`0600` `PGSERVICEFILE`:

```ini
[rappor-security-lab-supabase]
host=db.<disposable-project-ref>.supabase.co
port=5432
dbname=postgres
user=postgres
password=<database-password-from-the-secure-channel>
sslmode=require
```

Supply runtime values only through the secure execution environment:

```sh
export SUPABASE_LAB_URL='https://<disposable-project-ref>.supabase.co'
export SUPABASE_LAB_PUBLISHABLE_KEY='sb_publishable_<value>'
export SUPABASE_LAB_AUTH_EMAIL='<dummy-lab-user>'
export SUPABASE_LAB_AUTH_PASSWORD='<dummy-lab-password>'
export SUPABASE_LAB_PGSERVICE='rappor-security-lab-supabase'
export PGSERVICEFILE='<absolute-path-outside-the-repository>'
```

Never place those exports, the service file, an administrative connection string,
or generated reports in this directory. The browser-facing helper accepts only the
project URL and publishable key; database and elevated credentials have no browser
configuration field.

## Lifecycle validation

Install `psql` through the operator's reviewed workstation setup, then execute the
complete lifecycle. The runner applies the four revisions in the declared order and
emits only the comparison input fields:

```sh
npm run supabase:lifecycle -- --output /tmp/supabase-authorization-run.json
node src/compare.mjs \
  manifests/supabase-authorization.json \
  /tmp/supabase-authorization-run.json
```

The lifecycle runner resets and verifies removal of the relation in a `finally`
step, including after a failed assertion. A completed matching run has five true
positives, eleven true negatives, no false result and no inconclusive case. Any
migration, authentication, network or protocol
failure exits non-zero; when an output path was supplied it is replaced with a
sanitized failed run, which cannot produce a clean comparison.

For bounded diagnosis after manually applying one state, run:

```sh
node src/run-supabase-authorization.mjs --state fixed
```

That four-observation output is intentionally incomplete for the full manifest and
is not release evidence.

## Reset and disposal

The lifecycle already removes the benchmark relation. After an interrupted process,
or as an idempotent independent check, remove it and verify that it no longer exists:

```sh
npm run supabase:reset
```

Then delete the disposable project from **Settings > General > Delete project** or
with the Supabase CLI from the owner-controlled environment:

```sh
supabase projects delete <disposable-project-ref>
supabase projects list
```

Confirm that the exact project reference is absent from the laboratory organization
and that its project URL is no longer reachable after provider cleanup. Project
deletion is deliberately not automated by repository code because it is irreversible
and requires owner authorization. Remove the external PostgreSQL service entry and
all five `SUPABASE_LAB_*` values after deletion. Preserve only the sanitized run and
comparison reports.
