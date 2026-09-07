# Benchmark contract

## Purpose

The laboratory provides independent ground truth for Rappor Security. A scanner output is evidence to compare with the manifest, never the source of the expected result.

## Validation layers

1. Controlled code corpus with vulnerable, partially fixed, fixed and reintroduced revisions.
2. Controlled public web targets for TLS, headers, cookies, forms, mixed content, public resources, technology signals and synthetic secret exposure.
3. Disposable connected services, beginning with Supabase, for authorized access-control validation.
4. Realistic public training repositories pinned by commit for exploratory and load validation.

## Required states

Every controlled scenario uses immutable revisions for:

- `vulnerable`;
- `partially-fixed` when the scenario supports independent controls;
- `fixed`;
- `reintroduced` for lifecycle validation.

## Ground-truth record

Every case must declare at least:

- stable case identifier;
- target and immutable target revision;
- covered capability and expected rule family;
- expected presence or absence;
- expected severity and grouping key when applicable;
- safe evidence description without a recoverable secret;
- corresponding fixed case;
- functional assertion that must continue to pass;
- benchmark manifest version.

## Comparison rules

- Exact counts are release gates only for controlled targets.
- Third-party projects and pages are exploratory unless their revision and required inputs are immutable.
- Results from different scanner profiles, rule checksums or vulnerability database digests are not directly comparable as code remediation.
- A finding is resolved only when comparable coverage completes and the expected condition is absent.
- A partial or failed run cannot establish a clean baseline.

## Product feedback

A reproducible mismatch report contains only:

- Rappor Security visible deployment version;
- scanner profile and safe version metadata;
- laboratory manifest version and case identifier;
- expected versus observed behavior;
- bounded reproduction steps;
- sanitized evidence.

The report never contains a credential, customer data or unrestricted external target.

