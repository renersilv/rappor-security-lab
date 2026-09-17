# Controlled vibe-coding public target

This is a non-production static fixture for passive public scanning. It exposes
deterministic Next.js, Vercel, Lovable and Supabase client signals together with
controlled HTTP and DOM conditions. Vercel is the real hosting provider; the
other technology signals are explicit synthetic markers. The generated page has
one public JavaScript resource under a deterministic `_next` path and must never
exceed the six-resource scanner budget.

Generate exactly one lifecycle state with `node build.mjs --state <state>
--output <directory>`, where `<state>` is `vulnerable`, `partially-fixed`,
`fixed` or `reintroduced`. Each generated directory contains one bounded Vercel
Function for GET/HEAD responses and one public JavaScript fixture. The benchmark
manifest pins the digest of the complete generator source plus that selection.

The Supabase URL, publishable key and anon key are explicit non-functional
laboratory values. No Supabase client library or network operation is present.
Elevated-looking values use only the documented Rappor synthetic marker family.
The form has no named or enabled control, and the generated function rejects
every method other than GET and HEAD without reading a body.

Do not deploy this source until the owner supplies an authorized disposable
Vercel account and isolated laboratory domain. A deployment must remain
`noindex`, must not add registration, write routes, analytics, visitor storage or
external integrations, and must never share an account, project, domain or
credential with production or Rappor Security infrastructure.
