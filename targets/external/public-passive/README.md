# External public passive observations

This directory documents the bounded target set for dated, exploratory observations
through the Rappor Security public browser form. External results are informational:
they never define controlled ground truth, block a benchmark verdict, or change a
controlled target expectation.

## Approved target set

Only these exact URLs are in scope:

| Scenario | Exact URL | Operator evidence |
| --- | --- | --- |
| Mixed content | `https://public-firing-range.appspot.com/mixedcontent/index.html` | [Google Firing Range at pinned revision](https://github.com/google/firing-range/blob/4f991a6418b07a66cd63006f4a2bec27c84b72f4/README.md) |
| Missing HSTS | `https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing` | [Google Firing Range at pinned revision](https://github.com/google/firing-range/blob/4f991a6418b07a66cd63006f4a2bec27c84b72f4/README.md) |
| Insecure cookie | `https://public-firing-range.appspot.com/leakedcookie/leakedcookie` | [Google Firing Range at pinned revision](https://github.com/google/firing-range/blob/4f991a6418b07a66cd63006f4a2bec27c84b72f4/README.md) |
| Expired certificate | `https://expired.badssl.com/` | [badssl.com at pinned revision](https://github.com/chromium/badssl.com/blob/bfc80f7c2bf0873e2fdc9ba79f38a5afd93570fb/README.md) |

Google describes Firing Range as a public test bed for web application security
scanners. The badssl.com project describes its subdomains as client tests for bad
TLS configurations and explicitly lists the expired-certificate endpoint. The
evidence revisions document test intent; they do not make the live pages immutable.

## Capture procedure

1. Open only `/` on the owner-selected staging base URL and confirm its visible
   version before submitting a target.
2. Submit one exact URL at a time with the public form's passive-use confirmation.
   Do not authenticate, enumerate routes, vary inputs, or attempt exploitation.
3. Record the URL, UTC observation time, visible application version, completion
   status, summary, finding titles, severity, confidence, and category.
4. Exclude raw evidence, response bodies, cookies, scan identifiers, correlation
   identifiers, and credentials. A partial or failed scan remains partial or failed.
5. Set `externalState` to `changed` or `unavailable` when the page differs from its
   described purpose or cannot be reached, and describe only the sanitized condition.

Records live under `observations/public-external` and conform to
`schemas/public-external-baseline.schema.json`. Local verification checks structure,
sanitization, the four-URL ceiling, and informational-only disposition without
contacting the staging service or any third party.
