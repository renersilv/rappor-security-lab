#!/usr/bin/env python3
"""Objective accounting against temporary real files, snapshots and replay."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('objectives', HERE.parent / 'objectives.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


O = load()


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data if isinstance(data, bytes) else encoded(data))
    path.chmod(0o600)


class ObjectiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.attempts = self.root / 'attempts'
        self.candidate = dict(version='v0.85.0', sha='a' * 40, origin='https://synthetic.invalid')

    def tearDown(self):
        self.temporary.cleanup()

    def packet(self, number=1, runtime=False, identity=None, observation='rendered_web', mock=False,
               artifact_pass=None, artifact_candidate=None):
        candidate_dir = self.attempts / 'candidates' / f'pass-{number}'
        files = {'worker.py': f'# Harness preparation pass {number}.\nraise RuntimeError("offline preparation")\n'.encode(),
                 'note.md': b'Prepared review notes.\n'}
        if runtime:
            artifact = dict(executorPass=number if artifact_pass is None else artifact_pass,
                            candidate=self.candidate if artifact_candidate is None else artifact_candidate, observationType=observation,
                            screenshotSha256=identity or digest(f'synthetic-observation-{number}'.encode()),
                            scoreMatched=True, mock=mock)
            files['live-dom-artifact.json'] = encoded(artifact)
            files['live-observation.json'] = encoded(dict(
                objectiveId='web-entries', executorPass=number, candidate=self.candidate,
                observationType=observation, artifacts={'live-dom-artifact.json': digest(files['live-dom-artifact.json'])}))
        for name, raw in files.items():
            private(candidate_dir / name, raw)
        manifest = dict(issue=19, executorPass=number, candidate=self.candidate, newLiveActivity=runtime,
                        authorizationId='issue19-native-windows-20261023', files={name: digest(raw) for name, raw in files.items()})
        manifest_path = candidate_dir / f'manifest-pass{number}.json'
        private(manifest_path, manifest)
        manifest_raw = manifest_path.read_bytes()
        sources = {name: dict(content=raw.decode(), sha256=digest(raw)) for name, raw in files.items()}
        sources['manifest'] = dict(content=manifest_raw.decode(), sha256=digest(manifest_raw))
        bundle = dict(candidate=self.candidate, executorPass=number,
                      manifest=dict(path=str(manifest_path), sha256=digest(manifest_raw)), sources=sources)
        directory = self.root / f'review-{number}'
        directory.mkdir(mode=0o700)
        state = dict(candidate=self.candidate, executorPasses=number, attemptsRoot=str(self.attempts))
        private(self.root / 'campaign.json', state)
        private(directory / 'before.json', state)
        private(directory / 'bundle.json', bundle)
        verdict = dict(verdict='pass', objectiveId='web-entries', evidenceLevel='runtime_observation' if runtime else 'preparation',
                       evidence=['live-observation.json'] if runtime else ['worker.py', 'note.md'],
                       nextAction='Continue the next bounded observation on the authorized synthetic fixture.')
        return directory, verdict

    def nested_packet(self, number=207, mutate=None, outer_activity=None):
        directory, verdict = self.packet(number)
        bundle = json.loads((directory / 'bundle.json').read_text())
        manifest_path = Path(bundle['manifest']['path'])
        context = dict(issue=19, executorPass=number, candidate=self.candidate,
                       authorizationId='issue19-native-windows-20261023', objectiveId='ide-mcp')
        descriptor = encoded({'synthetic': 'public response material'})
        operation = dict(context, observationType='public_contract', inferenceStarted=False, windowsAccessed=False,
                         operationFingerprint=digest(b'unchanged-synthetic-descriptor'),
                         artifacts={'public-descriptor.json': digest(descriptor)})
        live_name = f'live-pass{number}-public-descriptor.json'
        receipt = dict(operation, artifacts={'public-observation.json': digest(encoded(operation))})
        files = {'public-descriptor.json': descriptor, 'public-observation.json': encoded(operation),
                 live_name: encoded(receipt)}
        runtime = dict(context, schema=1, observationType='public_contract', newLiveActivity=True,
                       inferenceStarted=False, windowsAccessed=False, scanStarted=False, maxDurationMs=15000,
                       files={name: digest(raw) for name, raw in files.items()})
        if mutate:
            mutate(runtime, files)
        files['runtime-manifest.json'] = encoded(runtime)
        manifest = {key: context[key] for key in ('issue', 'executorPass', 'candidate', 'authorizationId')}
        manifest['files'] = {name: digest(raw) for name, raw in files.items()}
        if outer_activity is not None:
            manifest['newLiveActivity'] = outer_activity
        for name, raw in files.items():
            private(manifest_path.parent / name, raw)
        private(manifest_path, manifest)
        raw = manifest_path.read_bytes()
        bundle['manifest']['sha256'] = digest(raw)
        bundle['sources'] = {name: dict(content=data.decode(), sha256=digest(data)) for name, data in files.items()}
        bundle['sources']['manifest'] = dict(content=raw.decode(), sha256=digest(raw))
        private(directory / 'bundle.json', bundle)
        verdict.update(objectiveId='ide-mcp', evidenceLevel='runtime_observation', evidence=[live_name])
        return directory, verdict

    def test_two_level_packet_records_bound_material_without_changing_acceptance(self):
        directory, verdict = self.nested_packet()
        campaign = (self.root / 'campaign.json').read_bytes()
        record = O.record_review(self.root, directory, verdict)
        self.assertTrue(record['materialProgress'])
        self.assertEqual(record['validatedEvidenceLevel'], 'runtime_observation')
        self.assertFalse(record['acceptanceChanged'])
        self.assertEqual(campaign, (self.root / 'campaign.json').read_bytes())
        self.assertEqual(O.record_review(self.root, directory, verdict), record)
        directory, verdict = self.nested_packet(208)
        repeated = O.record_review(self.root, directory, verdict)
        self.assertFalse(repeated['materialProgress'])
        self.assertEqual(repeated['runtimeIdentityHashes'], record['runtimeIdentityHashes'])

    def test_nested_context_flags_and_material_hashes_cannot_claim_progress(self):
        changes = [dict(schema=2), dict(schema=True), dict(executorPass=1), dict(candidate=dict(self.candidate, sha='b' * 40)),
                   dict(authorizationId='other'), dict(issue=20), dict(objectiveId='web-entries'),
                   dict(observationType='official_runtime'), dict(newLiveActivity=False),
                   dict(inferenceStarted=True), dict(windowsAccessed=True), dict(scanStarted=True),
                   dict(maxDurationMs=600000)]
        mutations = [(lambda runtime, files, change=change: runtime.update(change)) for change in changes]
        mutations += [lambda runtime, files: runtime['files'].update({'public-descriptor.json': '0' * 64}),
                      lambda runtime, files: runtime['files'].pop('public-descriptor.json'),
                      lambda runtime, files: files.update({'public-descriptor.json': b'changed material'})]
        for number, mutate in enumerate(mutations, 207):
            with self.subTest(number=number):
                directory, verdict = self.nested_packet(number, mutate=mutate)
                record = O.record_review(self.root, directory, verdict)
                self.assertFalse(record['materialProgress'])
                self.assertEqual(record['runtimeEvidenceHashes'], [])

    def test_nested_artifact_links_and_context_are_checked_after_outer_hash_binding(self):
        cases = [('public-observation.json', dict(artifacts={'public-descriptor.json': '0' * 64})),
                 ('public-observation.json', dict(executorPass=1)),
                 ('public-observation.json', dict(operationFingerprint='invalid')),
                 ('live', dict(artifacts={'public-observation.json': '0' * 64})),
                 ('live', dict(objectiveId='web-entries')),
                 ('live', dict(operationFingerprint='e' * 64))]
        for number, (target, change) in enumerate(cases, 207):
            def mutate(runtime, files):
                name = f'live-pass{number}-public-descriptor.json' if target == 'live' else target
                value = json.loads(files[name]); value.update(change)
                files[name] = encoded(value)
                runtime['files'][name] = digest(files[name])
            with self.subTest(target=target, change=change):
                directory, verdict = self.nested_packet(number, mutate=mutate)
                self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])

    def test_present_non_boolean_outer_activity_cannot_promote_nested_evidence(self):
        for number, activity in enumerate((0, None, 'false'), 207):
            directory, verdict = self.nested_packet(number)
            bundle = json.loads((directory / 'bundle.json').read_text())
            path = Path(bundle['manifest']['path'])
            manifest = json.loads(path.read_text()); manifest['newLiveActivity'] = activity
            private(path, manifest)
            raw = path.read_bytes()
            bundle['manifest']['sha256'] = digest(raw)
            bundle['sources']['manifest'] = dict(content=raw.decode(), sha256=digest(raw))
            private(directory / 'bundle.json', bundle)
            with self.subTest(activity=activity):
                self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])

    def test_nested_observation_does_not_override_outer_veto_or_preparation_review(self):
        directory, verdict = self.nested_packet(207, outer_activity=False)
        self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])
        directory, verdict = self.nested_packet(208)
        verdict['evidenceLevel'] = 'preparation'
        self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])

    def test_claimed_pass_and_acceptance_flag_never_change_documented_baseline(self):
        before = O.status(self.root)
        directory, verdict = self.packet()
        verdict.update(evidenceLevel='acceptance_candidate', accepted=True, progress='behavior_change')
        record = O.record_review(self.root, directory, verdict)
        self.assertFalse(record['acceptanceChanged'])
        self.assertFalse(record['materialProgress'])
        self.assertEqual(record['validatedEvidenceLevel'], 'preparation')
        after = O.status(self.root)
        self.assertEqual([row['acceptanceState'] for row in before], [row['acceptanceState'] for row in after])
        self.assertEqual([row['objectiveId'] for row in after if row['acceptanceState'] == 'accepted_documented'], ['windows-cli-local'])

    def test_three_real_preparation_records_request_diagnostic_replanning(self):
        for number in range(1, 4):
            directory, verdict = self.packet(number)
            verdict['evidenceLevel'] = 'runtime_observation'
            record = O.record_review(self.root, directory, verdict)
        self.assertEqual(record['preparationStreak'], 3)
        self.assertEqual(record['nextActionCode'], 'diagnostic_replanning')
        self.assertIn('bounded discriminating check', O.prompt(self.root))
        self.assertNotIn('suspended', O.prompt(self.root))
        self.assertTrue(O.review_context(self.root)['diagnosticReplanning'])
        self.assertIn('Replanejamento diagnóstico', O.public_status(self.root))

    def test_mocked_observation_does_not_advance(self):
        directory, verdict = self.packet(runtime=True, mock=True)
        record = O.record_review(self.root, directory, verdict)
        self.assertFalse(record['materialProgress'])
        self.assertEqual(record['runtimeEvidenceHashes'], [])

    def test_new_runtime_files_bound_to_pass_and_candidate_advance_only_evidence(self):
        directory, verdict = self.packet()
        O.record_review(self.root, directory, verdict)
        directory, verdict = self.packet(2, runtime=True)
        campaign = (self.root / 'campaign.json').read_bytes()
        verdict['evidenceLevel'] = 'acceptance_candidate'
        record = O.record_review(self.root, directory, verdict)
        self.assertTrue(record['materialProgress'])
        self.assertEqual(record['preparationStreak'], 0)
        self.assertEqual(record['validatedEvidenceLevel'], 'acceptance_candidate')
        actual = self.attempts / 'candidates/pass-2/live-dom-artifact.json'
        self.assertEqual(record['runtimeEvidenceHashes'], [digest(actual.read_bytes())])
        self.assertFalse(record['acceptanceChanged'])
        self.assertEqual(campaign, (self.root / 'campaign.json').read_bytes())
        row = next(row for row in O.status(self.root) if row['objectiveId'] == 'web-entries')
        self.assertEqual(row['acceptanceState'], 'partial')

    def test_wrong_candidate_or_pass_is_rejected_before_recording(self):
        directory, verdict = self.packet(runtime=True)
        state = json.loads((self.root / 'campaign.json').read_text())
        for change in [dict(candidate=dict(self.candidate, sha='b' * 40)), dict(executorPasses=2)]:
            private(self.root / 'campaign.json', dict(state, **change))
            with self.assertRaisesRegex(ValueError, 'current-pass-candidate-mismatch'):
                O.record_review(self.root, directory, verdict)
        self.assertFalse((self.root / 'objectives-history').exists())

    def test_changed_actual_file_cannot_use_snapshot_hash(self):
        directory, verdict = self.packet(runtime=True)
        private(self.attempts / 'candidates/pass-1/live-dom-artifact.json', {'changed': True})
        with self.assertRaisesRegex(ValueError, 'evidence-changed'):
            O.record_review(self.root, directory, verdict)

    def test_old_runtime_bytes_or_wrong_candidate_do_not_progress_under_fresh_receipt(self):
        directory, verdict = self.packet(2, runtime=True, artifact_pass=1)
        self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])
        directory, verdict = self.packet(3, runtime=True, artifact_candidate=dict(self.candidate, sha='b' * 40))
        self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])

    def test_historical_replay_after_campaign_advanced_does_not_append(self):
        directory, verdict = self.packet()
        first = O.record_review(self.root, directory, verdict)
        second_dir, second_verdict = self.packet(2)
        O.record_review(self.root, second_dir, second_verdict)
        self.assertEqual(O.record_review(self.root, directory, verdict), first)
        self.assertEqual(len(list((self.root / 'objectives-history').glob('*.json'))), 2)

    def test_partial_new_schema_does_not_silently_fall_back_to_historical(self):
        directory, verdict = self.packet()
        del verdict['evidenceLevel']
        with self.assertRaisesRegex(ValueError, 'invalid-objective-review-fields'):
            O.record_review(self.root, directory, verdict)

    def test_bound_host_review_marker_rejects_another_directory(self):
        directory, verdict = self.packet()
        private(self.root / 'campaign-auto-review.json', {'directory': str(self.root / 'another-review')})
        with self.assertRaisesRegex(ValueError, 'review-job-mismatch'):
            O.record_review(self.root, directory, verdict)

    def test_restart_replays_once_and_rejects_changed_verdict(self):
        directory, verdict = self.packet(runtime=True)
        record = O.record_review(self.root, directory, verdict)
        paths = list((self.root / 'objectives-history').glob('*.json'))
        previous = paths[0].read_bytes()
        restarted = load()
        self.assertEqual(restarted.record_review(self.root, directory, verdict), record)
        self.assertEqual(paths[0].read_bytes(), previous)
        self.assertEqual(len(list((self.root / 'objectives-history').glob('*.json'))), 1)
        with self.assertRaisesRegex(ValueError, 'replay-changed'):
            restarted.record_review(self.root, directory, dict(verdict, nextAction='Altered review outcome.'))

    def test_historical_review_without_new_fields_is_unclassified_preparation(self):
        directory, verdict = self.packet(runtime=True)
        del verdict['objectiveId']
        del verdict['evidenceLevel']
        original = (directory / 'bundle.json').read_bytes()
        record = O.record_review(self.root, directory, verdict)
        self.assertEqual(record['objectiveId'], 'unclassified')
        self.assertEqual(record['validatedEvidenceLevel'], 'preparation')
        self.assertFalse(record['materialProgress'])
        self.assertEqual(original, (directory / 'bundle.json').read_bytes())

    def test_relabeling_old_runtime_identity_as_current_pass_does_not_progress(self):
        identity = digest(b'unchanged-runtime-artifact')
        for number in [1, 2]:
            directory, verdict = self.packet(number, runtime=True, identity=identity)
            record = O.record_review(self.root, directory, verdict)
            self.assertEqual(record['materialProgress'], number == 1)
        self.assertEqual(record['preparationStreak'], 1)

    def test_runtime_receipt_for_other_objective_does_not_progress(self):
        directory, verdict = self.packet(runtime=True)
        verdict['objectiveId'] = 'ide-mcp'
        self.assertFalse(O.record_review(self.root, directory, verdict)['materialProgress'])

    def test_output_never_includes_review_prose_paths_or_secret_markers(self):
        directory, verdict = self.packet()
        verdict['nextAction'] = 'DO_NOT_DISCLOSE synthetic-private-value /private/user/path'
        O.record_review(self.root, directory, verdict)
        output = json.dumps(O.review_context(self.root)) + O.prompt(self.root) + O.public_status(self.root)
        for forbidden in ['DO_NOT_DISCLOSE', str(self.root), 'synthetic-private-value']:
            self.assertNotIn(forbidden, output)
        history = next((self.root / 'objectives-history').glob('*.json')).read_text()
        self.assertNotIn('DO_NOT_DISCLOSE', history)

    def test_symlinked_artifact_is_rejected(self):
        directory, verdict = self.packet(runtime=True)
        artifact = self.attempts / 'candidates/pass-1/live-dom-artifact.json'
        target = self.root / 'unrelated.json'
        private(target, artifact.read_bytes())
        artifact.unlink()
        artifact.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'unsafe-objective-path'):
            O.record_review(self.root, directory, verdict)


if __name__ == '__main__':
    unittest.main()
