# Rappor Security Lab

Laboratório independente e controlado para validar a Rappor Security como uma caixa-preta.

O repositório manterá aplicações e estados deliberadamente vulneráveis, suas versões corrigidas, alvos públicos isolados e um manifesto de resultados esperados. O objetivo é medir detecção, falsos positivos, falsos negativos, normalização, agrupamento, score, ciclo de correção e comportamento visível da interface.

Este repositório não contém código do produto, dados de clientes ou credenciais reais. Nenhum alvo do laboratório deve ser usado em produção.

Antes de contribuir, leia:

1. `AGENTS.md`;
2. `docs/STATUS.md`;
3. `docs/BENCHMARK-CONTRACT.md`;
4. `docs/SAFETY.md`.

## Executable benchmark manifest

`schemas/benchmark-manifest.schema.json` defines the versioned ground-truth format.
`manifests/example.json` covers controlled code, public and connected layers, an
external informational target, all lifecycle states, and example TP/FP/TN/FN
outcomes. Scanner evidence is input only and is deliberately excluded from reports.

Run the bundled example without installing dependencies:

```sh
npm test
node src/compare.mjs manifests/example.json
```

A separate observation file has the same shape as `exampleRun`: `status` is one of
`completed`, `partial` or `failed`, and `observations` contains `caseId` and boolean
`present` values. Generate both report formats with:

```sh
node src/compare.mjs manifests/example.json run.json \
  --json report.json --markdown report.md
```

Partial and failed runs are always non-clean. Controlled target discrepancies block
the verdict; external target discrepancies remain informational.

## Controlled code corpus

`corpus/code` contains four static, non-deployable revisions: `vulnerable`,
`partially-fixed`, `fixed` and `reintroduced`. Each revision has a JavaScript
dynamic-code fixture, a Rappor-owned non-functional marker fixture and a Kubernetes
configuration fixture. The fixed variants preserve the same deterministic
`parseQuantity("2") === 2` assertion.

The files under `scanner-profiles` pin the local Semgrep rule, Gitleaks marker rule
and Trivy misconfiguration mode. No scanner or network access is required for the
repository checks:

```sh
npm run check
```

`src/verify-corpus.mjs` verifies the expected signal matrix, functional assertion
and content digests referenced by the benchmark manifest. These fixtures are for
static scanning only. Do not build, run or publish the Kubernetes manifests as a
service.

## Autonomous execution

The reviewed operational contract, controls and user-service examples for João are
documented in [`ops/joao/README.md`](ops/joao/README.md). Installation is an
explicit owner action; repository checks do not install or start the units.
