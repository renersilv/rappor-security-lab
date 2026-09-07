# Controlled vibe-coding public target

This is a non-production Next.js fixture for passive public scanning. It exposes
deterministic Next.js, Vercel, Lovable and Supabase client signals together with
controlled HTTP and DOM conditions. The default state is `fixed`.

Select exactly one lifecycle state at build and runtime with
`RAPPOR_LAB_STATE`: `vulnerable`, `partially-fixed`, `fixed` or `reintroduced`.
The benchmark manifest pins the digest of the complete target source plus that
selection. A deployment revision must preserve the same value at build and
runtime.

The Supabase URL, publishable key and anon key are explicit non-functional
laboratory values. The client blocks all network operations and disables auth
persistence. Elevated-looking values use only the documented Rappor synthetic
marker family. The form has no named or enabled control, and the proxy rejects
every method other than GET and HEAD without reading a body.

Do not deploy this source until the owner supplies an authorized disposable
Vercel account and isolated laboratory domain. A deployment must remain
`noindex`, must not add registration, write routes, analytics, visitor storage or
external integrations, and must never share an account, project, domain or
credential with production or Rappor Security infrastructure.
