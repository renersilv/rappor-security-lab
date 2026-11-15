#!/usr/bin/env python3
"""The installed Python validator accepts only authentic closed origin evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('settlement_contract', ROOT / 'ops/joao/settlement-contract.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)
ENCODE = lambda value: (json.dumps(value, sort_keys=True) + '\n').encode()


class SettlementEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.installed = Path(self.temporary.name)
        self.evidence = json.loads((ROOT / 'test/fixtures/settlement-early-failure.json').read_text())

    def bundle(self, mutate_evidence=None, mutate_manifest=None, full=False):
        evidence = copy.deepcopy(self.evidence)
        if mutate_evidence:
            mutate_evidence(evidence)
        candidate = dict(origin='https://lab.example.invalid', sha='a' * 40, version='v0.1.0')
        context = dict(issue=19, executorPass=226, authorizationId='issue19-native-windows-20261023', candidate=candidate)
        manifest = dict(context, files={})
        bundle = dict(executorPass=228, candidate=candidate, sources={})

        def put(name, raw):
            bundle['sources'][name] = dict(content=raw.decode(), sha256=S.digest(raw), omitted=False)
            return dict(file=name, sha256=S.digest(raw))

        names = dict(transport='pass226-transport.json', cleanup='pass226-cleanup.json', runner='runtime/run-pass226.mjs',
                     interactive='runtime/interactive.ps1', observer='runtime/observe.ps1')
        references = {}
        for key, name in names.items():
            raw = ENCODE(evidence[key]) if key in {'transport', 'cleanup'} else evidence[key].encode()
            references[key] = dict(put('origin-' + key, raw), manifestName=name)
            manifest['files'][name] = S.digest(raw)
        runtime = dict(context, artifacts={'runtime/interactive.ps1': 'b' * 64, 'runtime/observe.ps1': 'c' * 64})
        if full:
            runtime_ref = dict(put('origin-runtime.json', ENCODE(runtime)), manifestName='live-pass226-ide-mcp-discovery.json')
            manifest['files'][runtime_ref['manifestName']] = runtime_ref['sha256']
        if mutate_manifest:
            mutate_manifest(manifest)
        origin = put('origin-manifest.json', ENCODE(manifest))
        plan = dict(context, schema=1, kind='windows_task_settlement', executorPass=229, originPass=226,
                    incident='e' * 64, originManifest=origin, taskName='RapporLab-Pass226-IdeReadiness',
                    guestRoot='C:\\RapporLab\\runtime\\pass226-ide-readiness',
                    ownershipFiles=['owned-processes.json', 'observer-ownership.json'], maxDurationMs=55000, sourceHashes={})
        plan['originRuntimeReceipt' if full else 'originRuntimeEvidence'] = runtime_ref if full else references
        for name in S.SOURCE_NAMES:
            raw = ('// Synthetic installed fixture: ' + name + '\n').encode()
            path = self.installed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            plan['sourceHashes'][name] = put(name, raw)['sha256']
        bundle.update(settlementOrigins={'226': origin['sha256']},
                      settlementCleanupOrigin=dict(executorPass=226, manifestSha256=origin['sha256']))
        return plan, bundle

    def validate(self, plan, bundle):
        raw = ENCODE(plan)
        bundle['sources']['plan.json'] = dict(content=raw.decode(), sha256=S.digest(raw))
        return S.plan(bundle, 'plan.json', plan['incident'], installed_root=self.installed)

    def test_full_receipt_and_early_failure_are_distinct_valid_evidence(self):
        for full in (False, True):
            with self.subTest(full=full):
                plan, bundle = self.bundle(full=full)
                self.assertEqual(self.validate(plan, bundle)[0], plan)

    def test_missing_mixed_forged_unprotected_and_wrong_pending_origin_fail(self):
        for kind in ('missing', 'mixed', 'extra', 'missing_source', 'forged_source', 'wrong_entry', 'pending', 'protected'):
            with self.subTest(kind=kind):
                plan, bundle = self.bundle()
                if kind == 'missing': del plan['originRuntimeEvidence']
                if kind == 'mixed': plan['originRuntimeReceipt'] = dict(file='invented.json', sha256='a' * 64, manifestName='live-pass226-ide-mcp-discovery.json')
                if kind == 'extra': plan['originRuntimeEvidence']['command'] = 'arbitrary'
                if kind == 'missing_source': del bundle['sources']['origin-runner']
                if kind == 'forged_source': bundle['sources']['origin-interactive']['content'] += 'changed'
                if kind == 'wrong_entry': plan['originRuntimeEvidence']['runner']['manifestName'] = 'runtime/run-pass225.mjs'
                if kind == 'pending': bundle['settlementCleanupOrigin']['executorPass'] = 225
                if kind == 'protected': bundle['settlementOrigins']['226'] = 'f' * 64
                with self.assertRaises(ValueError): self.validate(plan, bundle)

    def test_pass_activity_retry_preparation_and_missing_flags_fail(self):
        mutations = [lambda e: e['transport'].update(executorPass=225), lambda e: e['cleanup'].update(executorPass=225),
                     lambda e: e['transport'].update(retryIssued=True), lambda e: e['transport'].update(requestCount=2),
                     lambda e: e['transport']['operations'][1].update(label='activate'),
                     lambda e: e['cleanup']['cleanup'].update(preparationResponseValidated=True),
                     lambda e: e['cleanup']['cleanup'].update(status='verified'),
                     lambda e: e['transport']['operations'].__setitem__(0, dict(e['transport']['operations'][1], label='prepare'))]
        for flag in S.EARLY_FLAGS:
            mutations.extend([lambda e, f=flag: e['cleanup'].__setitem__(f, True), lambda e, f=flag: e['cleanup'].pop(f)])
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                plan, bundle = self.bundle(mutate_evidence=mutate)
                with self.assertRaises(ValueError): self.validate(plan, bundle)

    def test_early_form_cannot_hide_an_existing_runtime_receipt(self):
        plan, bundle = self.bundle(mutate_manifest=lambda m: m['files'].update({'live-pass226-ide-mcp-discovery.json': 'a' * 64}))
        with self.assertRaises(ValueError): self.validate(plan, bundle)


if __name__ == '__main__':
    unittest.main()
