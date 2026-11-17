#!/usr/bin/env python3
"""Reviewed Web ZIP retries use existing history; all execution is synthetic."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('web_zip_retry_fixture', HERE / 'web-zip-host-tests.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
R, C, H = F.R, F.C, F.H


class WebZipRetryTests(F.WebZipHostTests):
    def retry_material(self):
        self.execute(lambda _: (65, b'', b''))
        before = C.private(self.state / 'campaign.json')
        prior = C.artifact(before['reviewCheckpoint'], protected=True)
        previous = C.artifact(prior['correction'], protected=True)
        directory = self.operator / f'corrected-runtime-{before["executorPasses"]}'
        directory.mkdir(mode=0o700)
        sources = directory / 'source'
        sources.mkdir(mode=0o700)
        files = {}
        for name in H.SOURCE_NAMES:
            raw = (H.SOURCE_ROOT / name).read_bytes()
            if name == 'web-zip-runner.mjs':
                raw += f'\n// Synthetic corrected runtime {before["executorPasses"]}.\n'.encode()
            files['source/' + name] = R.put(sources / name, raw)['sha256']
        files['regression.test.mjs'] = R.put(directory / 'regression.test.mjs', b'// Fixed synthetic regression.\n')['sha256']
        for outcome in ('failed', 'passed'):
            files[outcome + '.txt'] = R.put(directory / (outcome + '.txt'),
                f'Synthetic regression {outcome}; pass {before["executorPasses"]}.\n'.encode())['sha256']
        fingerprint = R.sha(R.encoded(sorted(files['source/' + name] for name in H.SOURCE_NAMES)))
        request = copy.deepcopy(C.artifact(previous['webZipRequest'], protected=True))
        request.update(executorPass=before['executorPasses'] + 1, previousReview=before['reviewCheckpoint'],
                       sourceHashes={name: files['source/' + name] for name in H.SOURCE_NAMES})
        request_ref = R.put(directory / 'web-zip-request.json', R.encoded(request))
        files['web-zip-request.json'] = request_ref['sha256']
        for name, source, outcome, passed, failed in (
                ('before.json', previous['sourceFingerprint'], 'failed', 0, 1),
                ('after.json', fingerprint, 'passed', 1, 0)):
            proof = dict(schema=1, kind='web_zip_runtime_retry_regression',
                         requestSha256=previous['webZipRequest']['sha256'], sourceFingerprint=source,
                         command='node --test regression.test.mjs', outcome=outcome,
                         passed=passed, failed=failed, skipped=0, regression='regression.test.mjs',
                         regressionSha256=files['regression.test.mjs'],
                         log=dict(name=outcome + '.txt', sha256=files[outcome + '.txt']))
            files[name] = R.put(directory / name, R.encoded(proof))['sha256']
        manifest = R.put(directory / 'manifest.json', R.encoded(dict(files=files)))
        selected = dict(manifest=manifest, sourceFingerprint=fingerprint)
        verdict = dict(verdict='pass', findings=[], scope='bounded_no_model', cleanupAssessment='verified',
                       objectiveId='web-entries', evidenceLevel='preparation', progress='behavior_change',
                       ownerRequest=None, workContinuation=dict(targetObjectiveId='web-entries'),
                       nextAction='Run only the newly reviewed corrected Web ZIP request once within its existing deadline.',
                       evidence=['source/web-zip-runner.mjs', 'before.json', 'after.json'],
                       technicalCorrection=dict(incident=before['reviewCheckpoint']['sha256'],
                                                regressionBefore='before.json', regressionAfter='after.json'))
        return dict(before=before, prior=prior, previous=previous, directory=directory, sources=sources,
                    files=files, selected=selected, verdict=verdict, request=request, request_ref=request_ref)

    def admit(self, material):
        m = material
        bundle = dict(**m['selected'], sources={name: dict(content=(m['directory'] / name).read_text(), sha256=digest)
                                               for name, digest in m['files'].items()})
        bundle['sources']['manifest'] = dict(content=C.artifact(m['selected']['manifest'], text=True),
                                              sha256=m['selected']['manifest']['sha256'])
        events = m['directory'] / 'events.jsonl'
        R.put(events, R.encoded(dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(m['verdict'])))))
        verdict = R.result(events, bundle)
        grant = R.WORK.select(m['before'], verdict, m['selected'], C.artifact)
        receipt = dict(m['prior'], reviewedThroughPass=m['before']['executorPasses'],
                       previousReview=m['before']['reviewCheckpoint'],
                       beforeState=R.put(m['directory'] / 'state-before.json', R.encoded(m['before'])),
                       diagnosis=R.put(m['directory'] / 'diagnosis.json', R.encoded(verdict)),
                       correction=R.put(m['directory'] / 'correction.json', R.encoded(dict(
                           **m['selected'], scope=verdict['scope'], workContinuation=grant, webZipRequest=m['request_ref']))),
                       cleanup=R.put(m['directory'] / 'cleanup.json', R.encoded(dict(verified=True, synthetic=True,
                                                                                   executorPass=m['before']['executorPasses']))),
                       handoff=R.put(m['directory'] / 'handoff.md', b'One corrected synthetic runtime; no reset or replay.\n'))
        value = dict(m['before'], phase='active', reviewCheckpoint=R.put(m['directory'] / 'review.json', R.encoded(receipt)))
        C.save(self.state / 'campaign.json', value)
        with mock.patch.object(H, 'SOURCE_ROOT', m['sources']):
            self.assertEqual(H.checkpoint(R, self.state)[3], m['request'])
        self.assertEqual(R.WORK.active(value, C.artifact), grant)
        return grant

    def test_second_third_fourth_reviewed_runtime_and_fifth_rejected_without_reset(self):
        original = self.checkpoint
        history = {p: p.read_bytes() for p in self.operator.rglob('*') if p.is_file()}
        second = self.retry_material()
        self.assertEqual(self.admit(second)['runtimeCheckpoints'], 2)
        with mock.patch.object(H, 'SOURCE_ROOT', second['sources']):
            third = self.retry_material()
        self.assertEqual(self.admit(third)['runtimeCheckpoints'], 3)
        with mock.patch.object(H, 'SOURCE_ROOT', third['sources']):
            fourth = self.retry_material()
        self.assertEqual(self.admit(fourth)['runtimeCheckpoints'], 4)
        with mock.patch.object(H, 'SOURCE_ROOT', fourth['sources']):
            fifth = self.retry_material()
        with self.assertRaisesRegex(ValueError, 'budget-exhausted'):
            R.WORK.select(fifth['before'], fifth['verdict'], fifth['selected'], C.artifact)
        self.assertEqual(C.artifact(original, protected=True)['reviewedThroughPass'], 237)
        for path, raw in {**history, **self.preserved}.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_runtime_retry_rejects_unbound_or_unproven_changes(self):
        material = self.retry_material()
        for kind in ('missing_proof', 'wrong_incident', 'same_source', 'unfinished', 'wrong_scope', 'unresolved_cleanup'):
            with self.subTest(kind=kind):
                m = copy.deepcopy(material)
                if kind == 'missing_proof': m['verdict']['technicalCorrection'] = None
                elif kind == 'wrong_incident': m['verdict']['technicalCorrection']['incident'] = '0' * 64
                elif kind == 'same_source': m['selected']['sourceFingerprint'] = m['previous']['sourceFingerprint']
                elif kind == 'unfinished': m['before']['lastFinishedPass'] -= 1
                elif kind == 'wrong_scope': m['verdict']['scope'] = 'read_only_preflight'
                elif kind == 'unresolved_cleanup': m['verdict']['cleanupAssessment'] = 'unresolved'
                with self.assertRaises(ValueError):
                    R.WORK.select(m['before'], m['verdict'], m['selected'], C.artifact)
        for filename, field, replacement in (('before.json', 'failed', 0), ('after.json', 'failed', 1),
                                              ('after.json', 'skipped', 1), ('after.json', 'regressionSha256', '0' * 64),
                                              ('after.json', 'command', 'different regression')):
            with self.subTest(field=field, filename=filename):
                path = material['directory'] / filename
                original = path.read_bytes()
                check = json.loads(original)
                check[field] = replacement
                C.save(path, check)
                files = dict(material['files'], **{filename: C.digest(path)})
                manifest_path = material['directory'] / 'negative-manifest.json'
                C.save(manifest_path, dict(files=files))
                with self.assertRaises(ValueError):
                    R.WORK.select(material['before'], material['verdict'],
                                  dict(material['selected'], manifest=R.reference(manifest_path)), C.artifact)
                path.write_bytes(original)

    def test_retry_history_revalidates_proof_and_does_not_allow_replay(self):
        material = self.retry_material()
        self.admit(material)
        value = C.private(self.state / 'campaign.json')
        with self.assertRaises(ValueError):
            R.WORK.select(value, material['verdict'], material['selected'], C.artifact)
        path = material['directory'] / 'failed.txt'
        path.write_text('substituted regression evidence\n')
        with self.assertRaises(ValueError):
            R.WORK.history(value, C.artifact)

    def test_extra_runtime_without_exact_current_request_cannot_fall_back_to_model(self):
        material = self.retry_material()
        self.admit(material)
        value = C.private(self.state / 'campaign.json')
        receipt = C.artifact(value['reviewCheckpoint'], protected=True)
        correction = C.artifact(receipt['correction'], protected=True)
        request = C.artifact(correction['webZipRequest'], protected=True)
        for kind in ('missing', 'old_pass', 'wrong_predecessor', 'changed_source'):
            with self.subTest(kind=kind):
                modified = copy.deepcopy(correction)
                if kind == 'missing':
                    del modified['webZipRequest']
                else:
                    changed = copy.deepcopy(request)
                    if kind == 'old_pass': changed['executorPass'] -= 1
                    elif kind == 'wrong_predecessor': changed['previousReview'] = material['prior']['previousReview']
                    else: changed['sourceHashes']['web-zip-runner.mjs'] = '0' * 64
                    modified['webZipRequest'] = R.put(material['directory'] / f'wrong-request-{kind}.json', R.encoded(changed))
                bad_correction = R.put(material['directory'] / f'wrong-correction-{kind}.json', R.encoded(modified))
                bad_receipt = R.put(material['directory'] / f'wrong-review-{kind}.json', R.encoded(dict(receipt, correction=bad_correction)))
                C.save(self.state / 'campaign.json', dict(value, reviewCheckpoint=bad_receipt))
                with self.assertRaises(ValueError):
                    H.checkpoint(R, self.state)
        C.save(self.state / 'campaign.json', value)


if __name__ == '__main__': unittest.main()
