#!/usr/bin/env python3
"""Real protected controller transitions with a synthetic entrypoint process boundary."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('web_zip_work_fixture', HERE / 'work-continuation-tests.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)
R, C = W.R, W.C
spec = importlib.util.spec_from_file_location('web_zip_host_under_test', HERE.parent / 'web-zip-host.py')
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)

class WebZipHostTests(unittest.TestCase):
    packet = W.WorkContinuationTests.packet
    approval = W.WorkContinuationTests.approval
    response = W.WorkContinuationTests.response
    prepare = W.WorkContinuationTests.prepare
    finish = W.WorkContinuationTests.finish
    attempt = W.WorkContinuationTests.attempt
    grant = W.WorkContinuationTests.grant
    reference = W.BASE.BASE.CampaignTests.reference

    def setUp(self):
        original = C.activate
        def activate(state, auth, attempts, candidate):
            C.save(candidate, dict(version='v0.92.0', sha='3105b01067ac415786d9c041cc922195c00c9cc4',
                                   origin='https://linux-ai2.taile60a95.ts.net:8443'))
            return original(state, auth, attempts, candidate)
        with mock.patch.object(C, 'activate', side_effect=activate):
            W.WorkContinuationTests.setUp(self)
        historical = C.private(self.state / 'campaign.json')
        historical.update(executorPasses=235, lastFinishedPass=235)
        C.save(self.state / 'campaign.json', historical)
        W.BASE.BASE.CampaignTests.independent_review(self)
        self.packet(236)
        self.approval('web-entries'); self.finish()
        self.packet(237)
        manifest = C.private(self.manifest)
        for name in H.SOURCE_NAMES:
            destination = self.candidate_dir / 'source' / name
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            manifest['files']['source/' + name] = R.put(destination, (H.SOURCE_ROOT / name).read_bytes())['sha256']
        C.save(self.manifest, manifest)
        self.approval('web-entries', objectiveId='web-entries', scope='bounded_no_model'); self.finish()
        value = C.private(self.state / 'campaign.json')
        self.checkpoint_dir = Path(value['reviewCheckpoint']['path']).parent
        receipt = C.artifact(value['reviewCheckpoint'], protected=True)
        correction = C.artifact(receipt['correction'], protected=True)
        self.request = dict(schema=1, kind='web_zip_execution_request', issue=19,
            authorizationId=self.auth['authorizationId'], candidate=value['candidate'], executorPass=238,
            fixtureRoot=str(self.root / 'synthetic-fixture'),
            sourceHashes={name: C.digest(H.SOURCE_ROOT / name) for name in H.SOURCE_NAMES},
            desktop=dict(account='joao', sid='S-1-5-21-100-200-300-1001', sessionId=1),
            product=dict(productId='00000000-0000-4000-8000-000000000001',
                         analysisName='Rappor Lab Web ZIP pass238', environment='Development'), previousReview=receipt['previousReview'])
        correction['webZipRequest'] = R.put(self.checkpoint_dir / 'web-zip-request.json', R.encoded(self.request))
        # The fixture materializes the same acyclic host-owned adoption used by the operator.
        correction_path = Path(receipt['correction']['path'])
        C.save(correction_path, correction)
        receipt['correction'] = R.reference(correction_path)
        receipt_path = Path(value['reviewCheckpoint']['path'])
        C.save(receipt_path, receipt)
        value['reviewCheckpoint'] = R.reference(receipt_path)
        C.save(self.state / 'campaign.json', value)
        self.checkpoint = value['reviewCheckpoint']
        self.request_ref = correction['webZipRequest']
        self.output = self.checkpoint_dir / 'web-zip-output-pass238'
        self.packet_dir = self.state / 'tmp/issue19-native-windows-20261023/candidates/host-web-zip-pass238'
        self.preserved = {path: path.read_bytes() for path in (self.auth_path, self.ledger,
            self.state / 'session', self.attempts / 'attempt-1/receipt.json')}
        self.before = copy.deepcopy(value)

    def tearDown(self):
        W.WorkContinuationTests.tearDown(self)

    def invoke_success(self, command):
        self.assertEqual(command, ['node', str(H.SOURCE_ROOT / 'web-zip-runner.mjs'), 'run',
            '--request', self.request_ref['path'], '--sha256', self.request_ref['sha256'], '--output', str(self.output)])
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 238)
        self.assertTrue((self.checkpoint_dir / 'web-zip-host-intent.json').is_file())
        self.output.mkdir(mode=0o700)
        instruction_ref = R.put(self.output / 'instruction.json', R.encoded(dict(executorPass=238,
            candidate=self.request['candidate'], product=self.request['product'])))
        images = {}
        for name in ('confirmation.png', 'execution.png', 'history.png'):
            images[name] = R.put(self.output / name, b'\x89PNG\r\n\x1a\n' + name.encode() * 20)['sha256']
        primary = dict(outcome='completed', requestSha256=self.request_ref['sha256'],
            sourceHashes=self.request['sourceHashes'], candidate=self.request['candidate'],
            execution=dict(self.request['product'], id='00000000-0000-4000-8000-000000000004',
                analysisDefinitionId='00000000-0000-4000-8000-000000000002', revisionId='00000000-0000-4000-8000-000000000003',
                idempotencyKey='00000000-0000-4000-8000-000000000005',
                uploadPath='/api/products/' + self.request['product']['productId'] + '/analysis-definitions/uploaded-code'),
            confirmationScreenshotSha256=images['confirmation.png'], rendered=dict(
                executionId='00000000-0000-4000-8000-000000000004', historyExecutionId='00000000-0000-4000-8000-000000000004',
                analysisDefinitionId='00000000-0000-4000-8000-000000000002', revisionId='00000000-0000-4000-8000-000000000003',
                productId=self.request['product']['productId'],
                executionScreenshotSha256=images['execution.png'], historyScreenshotSha256=images['history.png']))
        cleanup = dict(requestSha256=self.request_ref['sha256'], sourceHashes=self.request['sourceHashes'],
            instructionSha256=instruction_ref['sha256'], failureCode=None, credentialClosed=True,
            remoteQuiescenceObserved=True, elapsedMs=1234,
            cleanup=dict(verified=True, runtimeRootAbsent=True, loginMaterialAbsent=True))
        C.save(self.output / 'primary.json', primary)
        C.save(self.output / 'cleanup.json', cleanup)
        C.save(self.checkpoint_dir / 'web-zip-pass238.intent.json', dict(schema=1,
            requestSha256=self.request_ref['sha256'], sourceHashes=self.request['sourceHashes']))
        return 0, R.encoded(dict(outcome='completed', outputDirectory=str(self.output))), b''

    def execute(self, invoke):
        with mock.patch.object(H, 'invoke', side_effect=invoke) as called, contextlib.redirect_stdout(io.StringIO()):
            H.execute(R, self.state)
        return called

    def assert_preserved(self):
        value = C.private(self.state / 'campaign.json')
        for key in set(self.before) - {'phase', 'executorPasses', 'lastFinishedPass', 'reviewReason'}:
            self.assertEqual(value[key], self.before[key], key)
        for path, raw in self.preserved.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        self.assertFalse(value['allowsFinalDelivery'])

    def test_real_begin_finish_retains_runtime_for_independent_review_without_model(self):
        self.assertEqual(H.mode(R, self.state), 'pending')
        called = self.execute(self.invoke_success)
        self.assertEqual(called.call_count, 1)
        value = C.private(self.state / 'campaign.json')
        self.assertEqual((value['executorPasses'], value['lastFinishedPass'], value['phase']), (238, 238, 'review_pending'))
        self.assertEqual(H.mode(R, self.state), 'none')
        self.assertTrue((self.packet_dir / 'live-web-zip.json').is_file())
        self.assert_preserved()
        # This is the actual review packet boundary, not a direct private parser call.
        directory = self.prepare()
        self.assertTrue((directory / 'bundle.json').is_file())
        record = R.OBJECTIVES.record_review(self.state, directory, dict(verdict='pass',
            objectiveId='web-entries', evidenceLevel='runtime_observation',
            evidence=['live-web-zip.json'], nextAction='Review the retained rendered observation.'))
        self.assertEqual(record['validatedEvidenceLevel'], 'runtime_observation')
        self.assertFalse(record['acceptanceChanged'])

    def test_nonzero_exit_finishes_unresolved_without_live_evidence(self):
        called = self.execute(lambda _: (124, b'', b''))
        self.assertEqual(called.call_count, 1)
        result = C.private(self.checkpoint_dir / 'web-zip-host-result.json')
        self.assertEqual((result['exitCode'], result['outcome']), (124, 'unresolved'))
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        self.assert_preserved()

    def test_intent_crash_never_relaunches_and_keeps_partial_output(self):
        class Interruption(BaseException): pass
        with self.assertRaises(Interruption):
            self.execute(lambda _: (_ for _ in ()).throw(Interruption()))
        self.output.mkdir(mode=0o700)
        C.save(self.output / 'primary.json', dict(outcome='inconclusive', evidence='partial'))
        partial = (self.output / 'primary.json').read_bytes()
        called = self.execute(lambda _: self.fail('interrupted operation was relaunched'))
        self.assertEqual(called.call_count, 0)
        self.assertEqual((self.output / 'primary.json').read_bytes(), partial)
        self.assertEqual(C.private(self.checkpoint_dir / 'web-zip-host-result.json')['exitCode'], 125)
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        self.assert_preserved()

    def test_completed_result_crash_replays_only_packet_finish(self):
        real = H.retain_packet
        with mock.patch.object(H, 'retain_packet', side_effect=RuntimeError('fixture interrupted after durable result')):
            with self.assertRaisesRegex(RuntimeError, 'durable result'):
                self.execute(self.invoke_success)
        raw = (self.checkpoint_dir / 'web-zip-host-result.json').read_bytes()
        with mock.patch.object(H, 'retain_packet', side_effect=real):
            called = self.execute(lambda _: self.fail('completed operation was relaunched'))
        self.assertEqual(called.call_count, 0)
        self.assertEqual((self.checkpoint_dir / 'web-zip-host-result.json').read_bytes(), raw)
        self.assert_preserved()

    def test_changed_request_is_rejected_before_begin_or_launch(self):
        path = Path(self.request_ref['path'])
        path.write_bytes(path.read_bytes() + b' ')
        before = (self.state / 'campaign.json').read_bytes()
        with self.assertRaises(ValueError): self.execute(self.invoke_success)
        self.assertEqual((self.state / 'campaign.json').read_bytes(), before)
        self.assertFalse((self.checkpoint_dir / 'web-zip-host-intent.json').exists())

    def test_installed_source_drift_is_rejected_before_launch(self):
        installed = self.root / 'changed-installed'
        installed.mkdir()
        for name in H.SOURCE_NAMES: shutil.copyfile(H.SOURCE_ROOT / name, installed / name)
        (installed / H.SOURCE_NAMES[0]).write_bytes(b'// changed\n')
        with mock.patch.object(H, 'SOURCE_ROOT', installed), self.assertRaises(ValueError):
            self.execute(self.invoke_success)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 237)

    def rebind(self, mutate):
        value = C.private(self.state / 'campaign.json')
        receipt = C.artifact(value['reviewCheckpoint'], protected=True)
        correction = C.artifact(receipt['correction'], protected=True)
        diagnosis = C.artifact(receipt['diagnosis'], protected=True)
        mutate(correction, diagnosis)
        C.save(Path(receipt['diagnosis']['path']), diagnosis)
        receipt['diagnosis'] = R.reference(Path(receipt['diagnosis']['path']))
        C.save(Path(receipt['correction']['path']), correction)
        receipt['correction'] = R.reference(Path(receipt['correction']['path']))
        C.save(Path(value['reviewCheckpoint']['path']), receipt)
        value['reviewCheckpoint'] = R.reference(Path(value['reviewCheckpoint']['path']))
        C.save(self.state / 'campaign.json', value)

    def test_offline_checkpoint_cannot_authorize_runtime(self):
        self.rebind(lambda correction, _: correction.update(scope='offline'))
        with self.assertRaises(ValueError): self.execute(self.invoke_success)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 237)

    def test_unresolved_cleanup_cannot_authorize_runtime(self):
        self.rebind(lambda _, diagnosis: diagnosis.update(cleanupAssessment='unresolved'))
        with self.assertRaises(ValueError): self.execute(self.invoke_success)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 237)

    def test_owner_required_checkpoint_cannot_authorize_runtime(self):
        self.rebind(lambda _, diagnosis: diagnosis.update(ownerRequest=dict(action='interactive_login', location='windows_ide')))
        with self.assertRaises(ValueError): self.execute(self.invoke_success)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 237)

    def test_packet_symlink_is_rejected_before_runtime_and_never_writes_outside(self):
        outside = self.root / 'outside'
        outside.mkdir(mode=0o700)
        R.HOST.private_directory(self.packet_dir.parent, self.state)
        self.packet_dir.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError), mock.patch.object(H, 'invoke') as called:
            H.execute(R, self.state)
        called.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 237)

    def test_real_phase_after_begin_crash_reconciles_without_starting_entrypoint(self):
        R.HOST.control(C, 'begin', self.state)
        R.HOST.control(C, 'phase', self.state)
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        with mock.patch.object(H, 'invoke', side_effect=AssertionError('reconcile launched runtime')) as called:
            H.reconcile(R, self.state)
        called.assert_not_called()
        result = C.private(self.checkpoint_dir / 'web-zip-host-result.json')
        self.assertEqual((result['exitCode'], result['outcome']), (125, 'unresolved'))
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 238)
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        self.assert_preserved()
        self.assertTrue((self.prepare() / 'bundle.json').is_file())

    def test_atomic_publication_interruption_leaves_no_partial_final_file(self):
        path = self.checkpoint_dir / 'atomic-fixture.json'
        real_write = H.os.write
        calls = 0
        def interrupted_write(descriptor, raw):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(descriptor, raw[:3])
            raise OSError('synthetic write interruption')
        with mock.patch.object(H.os, 'write', side_effect=interrupted_write):
            with self.assertRaises(OSError): H.put(R, path, b'{"complete":true}\n')
        self.assertFalse(path.exists())
        expected = H.put(R, path, b'{"complete":true}\n')
        self.assertEqual(C.artifact(expected, protected=True), {'complete': True})
        with self.assertRaises(ValueError): H.put(R, path, b'{"different":true}\n')
        self.assertEqual(path.read_bytes(), b'{"complete":true}\n')

    def test_partial_entrypoint_json_after_interruption_is_reviewable_without_relaunch(self):
        class Interruption(BaseException): pass
        with self.assertRaises(Interruption):
            self.execute(lambda _: (_ for _ in ()).throw(Interruption()))
        self.output.mkdir(mode=0o700)
        raw = b'{"outcome":"incom'
        R.put(self.output / 'primary.json', raw)
        R.HOST.control(C, 'phase', self.state)
        with mock.patch.object(H, 'invoke', side_effect=AssertionError('partial output relaunched')) as called:
            H.reconcile(R, self.state)
        called.assert_not_called()
        self.assertEqual((self.output / 'primary.json').read_bytes(), raw)
        result = C.private(self.checkpoint_dir / 'web-zip-host-result.json')
        self.assertEqual(result['outcome'], 'unresolved')
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        self.assertTrue((self.prepare() / 'bundle.json').is_file())
        self.assert_preserved()

    def interrupted_with_partial_file(self, name, raw):
        class Interruption(BaseException): pass
        with self.assertRaises(Interruption):
            self.execute(lambda _: (_ for _ in ()).throw(Interruption()))
        self.output.mkdir(mode=0o700)
        paths = ([self.output / item for item in ('primary.json', 'cleanup.json', 'instruction.json')]
                 + [self.checkpoint_dir / 'web-zip-pass238.intent.json'] if name == 'empty-all' else
                 [self.checkpoint_dir / 'web-zip-pass238.intent.json' if name == 'entrypoint-intent' else self.output / name])
        for path in paths:
            R.put(path, raw)
        R.HOST.control(C, 'phase', self.state)
        with mock.patch.object(H, 'invoke', side_effect=AssertionError('partial write relaunched')) as called:
            H.reconcile(R, self.state)
        called.assert_not_called()
        for path in paths:
            self.assertEqual(path.read_bytes(), raw)
        result = C.private(self.checkpoint_dir / 'web-zip-host-result.json')
        self.assertEqual((result['exitCode'], result['outcome']), (125, 'unresolved'))
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        self.assertTrue((self.prepare() / 'bundle.json').is_file())
        self.assert_preserved()

    def test_empty_partial_entrypoint_output_is_preserved_and_reviewable(self):
        self.interrupted_with_partial_file('empty-all', b'')

    def test_truncated_entrypoint_intent_is_unresolved_and_never_relaunched(self):
        self.interrupted_with_partial_file('entrypoint-intent', b'{"schema":')

    def test_screenshot_hash_substitution_never_emits_runtime_evidence(self):
        def corrupted(command):
            result = self.invoke_success(command)
            (self.output / 'confirmation.png').write_bytes(b'x' * 120)
            return result
        with self.assertRaises(ValueError): self.execute(corrupted)
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        called = self.execute(lambda _: self.fail('corrupted run was relaunched'))
        self.assertEqual(called.call_count, 0)
        self.assertEqual(C.private(self.checkpoint_dir / 'web-zip-host-result.json')['outcome'], 'unresolved')

    def test_created_revision_substitution_never_emits_runtime_evidence(self):
        def corrupted(command):
            result = self.invoke_success(command)
            primary = C.private(self.output / 'primary.json')
            primary['execution']['revisionId'] = '00000000-0000-4000-8000-000000000099'
            C.save(self.output / 'primary.json', primary)
            return result
        with self.assertRaises(ValueError): self.execute(corrupted)
        self.assertFalse((self.packet_dir / 'live-web-zip.json').exists())
        called = self.execute(lambda _: self.fail('substituted revision was relaunched'))
        self.assertEqual(called.call_count, 0)
        self.assertEqual(C.private(self.checkpoint_dir / 'web-zip-host-result.json')['outcome'], 'unresolved')
        self.assert_preserved()

if __name__ == '__main__': unittest.main()
