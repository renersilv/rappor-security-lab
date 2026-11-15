#!/usr/bin/env python3
"""Protected real campaign transitions with deterministic model/sandbox adapters."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

T = load('candidate_technical_tests', HERE / 'technical-continuation-tests.py')
M = load('candidate_repair', HERE.parent / 'candidate-repair.py')
B = load('candidate_sandbox_contract', HERE.parent / 'candidate-repair-sandbox.py')
R, C = T.R, T.C
M.R, M.C = R, C

class CandidateRepairTests(unittest.TestCase):
    attempt = T.TechnicalTests.attempt
    prepare = T.TechnicalTests.prepare
    response = T.TechnicalTests.response
    finish = T.TechnicalTests.finish
    early_rejection = T.TechnicalTests.early_rejection
    next_packet = T.TechnicalTests.next_packet

    def setUp(self):
        T.BASE.ReviewTests.setUp(self)
        self.early_rejection()
        for number in (2, 3):
            self.next_packet(number)
            folder = self.candidate_dir / 'source'
            folder.mkdir(mode=0o700)
            self.source.rename(folder / 'worker.ps1')
            self.source = folder / 'worker.ps1'
            value = C.private(self.manifest)
            value['files'].pop('worker.ps1')
            value['files']['source/worker.ps1'] = C.digest(self.source)
            C.save(self.manifest, value)
            if number == 3:
                # Valid JSON need not use the controller's canonical serialization.
                campaign_path = self.state / 'campaign.json'
                campaign = C.private(campaign_path)
                campaign_path.write_bytes((json.dumps(dict(reversed(list(campaign.items()))), indent=3) + '\n').encode())
            self.response(technicalCorrection=None, objectiveId='ide-mcp', evidenceLevel='preparation',
                          cleanupAssessment='unresolved', evidence=['source/worker.ps1'])
            self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.before = C.private(self.state / 'campaign.json')
        self.assertEqual(R.technical_history(self.before)[0]['attempt'], 2)
        for name, value in [('branch', self.stage['branch']), ('base_sha', 'a' * 40)]:
            R.put(self.state / name, (value + '\n').encode())
        (self.state / 'tmp').mkdir(mode=0o700)
        self.ledger = self.state / 'tmp/issue-19-ai-consumption.json'
        C.save(self.ledger, dict(active=False, attempts=[dict(sequence=22, outcome='failed')]))
        self.history = {p: p.read_bytes() for p in self.operator.rglob('*') if p.is_file()}
        self.original_source = self.source.read_bytes()
        self.auth_before = self.auth_path.read_bytes()
        self.ledger_before = self.ledger.read_bytes()
        self.calls, self.checks, self.stopped = [], [], []
        self.proposal = dict(disposition='repair', diagnosis='Replace the defective worker with a bounded offline return.', files=[
            dict(path='source/worker.ps1', content='function Invoke-Worker { return 42 }\n'),
            dict(path='tests/repair-worker.py', content='assert 42 == 42\n')])
        self.review = dict(verdict='pass', findings=[])
        self.check_codes = [1, 0]
        self.original_protected = M.RECOVERY.protected
        self.original_spec = importlib.util.spec_from_file_location

    def tearDown(self):
        T.BASE.ReviewTests.tearDown(self)

    def protected(self, root):
        # Rebind only the controller's protected root; execute original bound/protected checks.
        controller = C
        class Loader:
            def create_module(self, spec):
                return controller
            def exec_module(self, loaded):
                pass
        def spec(name, path, *args, **kwargs):
            if name == 'recovery_campaign':
                return importlib.machinery.ModuleSpec(name, Loader())
            return self.original_spec(name, path, *args, **kwargs)
        with mock.patch.object(M.RECOVERY.importlib.util, 'spec_from_file_location', side_effect=spec):
            return self.original_protected(root)

    def model(self, folder, label, prompt, schema, model, effort):
        self.calls.append((label, model, effort, str(schema), prompt))
        self.assertEqual(model, 'fixture-model')
        self.assertEqual(effort, 'high')
        self.assertIn('UNTRUSTED', prompt)
        result = copy.deepcopy(self.proposal if label == 'proposal' else self.review)
        R.put(folder / 'events.jsonl', R.encoded(dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(result)))))
        return result

    def sandbox(self, tree, tests, log):
        self.checks.append((str(tree), copy.deepcopy(tests)))
        code = self.check_codes[(len(self.checks) - 1) % len(self.check_codes)]
        R.put(log, ('ASSERTION_FAILURE: fixture worker return\n' if code == 1 else f'FIXTURE_VALIDATION_EXIT:{code}\n').encode())
        return code

    @contextlib.contextmanager
    def adapters(self, model=None, sandbox=None, snapshot=None):
        adapter = types.SimpleNamespace(validate_proposal=B.validate_proposal, snapshot=snapshot or B.snapshot,
            tree_hashes=B.tree_hashes, stop_incomplete=lambda log: self.stopped.append(str(log)),
            sandbox=sandbox or self.sandbox)
        with mock.patch.object(M.RECOVERY, 'protected', side_effect=self.protected), \
             mock.patch.object(M.RECOVERY, 'call_model', side_effect=model or self.model), \
             mock.patch.object(M, 'sandbox_module', return_value=adapter):
            yield

    def run_repair(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return M.run(self.state, 'fixture-model', 'high')

    def dispatch_repair(self):
        # Exercise the same CLI eligible -> run boundary used by the shell dispatcher.
        output = io.StringIO()
        with mock.patch.object(M.sys, 'argv', ['candidate-repair.py', 'eligible', str(self.state)]), contextlib.redirect_stdout(output):
            M.main()
        self.assertEqual(output.getvalue().strip(), 'yes')
        output = io.StringIO()
        with mock.patch.object(M.sys, 'argv', ['candidate-repair.py', 'run', str(self.state),
                '--model', 'fixture-model', '--effort', 'high']), contextlib.redirect_stdout(output):
            M.main()
        return output.getvalue().strip().splitlines()[-1]

    def assert_preserved(self):
        self.assertEqual(self.auth_path.read_bytes(), self.auth_before)
        self.assertEqual(self.ledger.read_bytes(), self.ledger_before)
        self.assertEqual(self.source.read_bytes(), self.original_source)
        for path, content in self.history.items():
            # The review marker belongs to state, never to these immutable review packets.
            self.assertEqual(path.read_bytes(), content, str(path))
        current = C.private(self.state / 'campaign.json')
        for key in set(self.before) - {'phase', 'reviewCheckpoint'}:
            self.assertEqual(current[key], self.before[key], key)

    def state_value(self):
        return M.pointed_state(self.state)[1]

    def test_approval_adopts_offline_preserving_exhausted_incident_and_evidence(self):
        ctx = M.context(self.state)
        self.assertEqual(ctx['route']['attempt'], 2)
        with self.adapters():
            self.assertEqual(self.run_repair(), 'completed')
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assertEqual(self.checks[0][1], self.checks[1][1])
        current = C.private(self.state / 'campaign.json')
        checkpoint = C.artifact(current['reviewCheckpoint'], protected=True)
        correction = C.artifact(checkpoint['correction'], protected=True)
        self.assertEqual(correction['scope'], 'offline')
        self.assertEqual(correction['technicalRoute']['attempt'], 2)
        self.assertEqual(correction['technicalRoute']['incident'], ctx['incident'])
        self.assertIn('No Windows, SSH, IDE, MCP', C.artifact(checkpoint['handoff'], protected=True, text=True))
        self.assert_preserved()

    def test_only_matching_operational_retry_is_archived_after_checkpoint(self):
        fingerprint = R.sha(f'v1:{"a" * 40}:{self.stage["branch"]}:19:codex_exit:{R.incident_key(self.state)}'.encode())
        raw = f'issue=19\nbranch={self.stage["branch"]}\nerror_class=codex_exit\nfingerprint={fingerprint}\n'.encode()
        R.put(self.state / 'issue-retry', raw)
        with self.adapters():
            self.assertEqual(self.run_repair(), 'completed')
        self.assertFalse((self.state / 'issue-retry').exists())
        folder = M.pointed_state(self.state)[0]
        self.assertEqual(C.private(folder / 'released-retry.json')['content'].encode(), raw)
        self.assertTrue((folder / 'attempt-1/proposal-call-1/events.jsonl').exists())
        self.assertTrue((folder / 'attempt-1/review-call-1/events.jsonl').exists())
        self.assertEqual(self.calls[0][3], str(HERE.parent / 'candidate-repair-result.schema.json'))
        self.assertEqual(self.calls[1][3], str(HERE.parent / 'review-result.schema.json'))
        self.assert_preserved()

    def test_atomic_publish_failure_is_retryable_without_overwriting_final_artifact(self):
        folder = self.operator / 'atomic-publish-fixture'
        folder.mkdir(mode=0o700)
        target = folder / 'receipt.json'
        raw = b'{"fixture":true}\n'
        with mock.patch.object(M.os, 'link', side_effect=OSError('fixture-link-interrupted')):
            with self.assertRaisesRegex(OSError, 'fixture-link-interrupted'):
                M.atomic_put(target, raw)
        self.assertFalse(target.exists())
        self.assertEqual(list(folder.iterdir()), [])
        reference = M.atomic_put(target, raw)
        self.assertEqual(reference, R.reference(target))
        self.assertEqual(target.read_bytes(), raw)
        self.assertEqual(M.atomic_put(target, raw), reference)
        with self.assertRaisesRegex(ValueError, 'immutable-candidate-repair-artifact-changed'):
            M.atomic_put(target, b'{"fixture":false}\n')
        self.assertEqual(target.read_bytes(), raw)

    def test_adoption_preserves_original_noncanonical_campaign_bytes(self):
        original = (self.state / 'campaign.json').read_bytes()
        self.assertNotEqual(original, R.encoded(C.private(self.state / 'campaign.json')))
        self.assertEqual(M.context(self.state)['marker']['beforeSha256'], R.sha(original))
        with self.adapters():
            self.assertEqual(self.dispatch_repair(), 'completed')
        campaign = C.private(self.state / 'campaign.json')
        checkpoint = C.artifact(campaign['reviewCheckpoint'], protected=True)
        self.assertEqual(checkpoint['beforeState']['sha256'], R.sha(original))
        self.assertEqual(Path(checkpoint['beforeState']['path']).read_bytes(), original)
        self.assert_preserved()

    def test_tampered_source_rejected_before_model(self):
        self.source.write_text('function Invoke-Worker { return 999 }\n')
        with self.adapters(), self.assertRaises(ValueError):
            self.run_repair()
        self.assertEqual(self.calls, [])

    def test_state_drift_after_reserved_proposal_cannot_continue(self):
        def failed(*args):
            raise ValueError('recovery-model-failed')
        with self.adapters(failed):
            self.assertEqual(self.run_repair(), 'proposing')
        C.save(self.ledger, dict(active=True))
        with self.adapters(), self.assertRaisesRegex(ValueError, 'protected-state-changed'):
            self.run_repair()
        self.assertEqual(self.calls, [])

    def test_unrelated_operational_retry_is_not_released(self):
        R.put(self.state / 'issue-retry', b'issue=19\nbranch=unrelated\nerror_class=codex_exit\nfingerprint=bad\n')
        prior = (self.state / 'issue-retry').read_bytes()
        with self.adapters(), self.assertRaisesRegex(ValueError, 'unrelated-retry'):
            self.run_repair()
        self.assertEqual((self.state / 'issue-retry').read_bytes(), prior)
        self.assertEqual(self.calls, [])

    def test_two_independent_rejections_exhaust_repair_without_counter_reset(self):
        self.review = dict(verdict='changes_requested', findings=['The correction remains defective.'])
        with self.adapters():
            self.assertEqual(self.run_repair(), 'failed')
            self.assertEqual(self.run_repair(), 'failed')
            self.assertEqual(self.run_repair(), 'exhausted')
            self.assertEqual(self.run_repair(), 'exhausted')
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review', 'proposal', 'review'])
        self.assertEqual(self.state_value()['attempts'], 2)
        self.assertEqual(C.private(self.state / 'campaign.json'), self.before)
        self.assert_preserved()

    def test_model_transport_retry_caches_same_proposal_and_checks(self):
        attempts = []
        def interrupted(folder, label, *args):
            attempts.append(label)
            if label == 'review' and attempts.count('review') == 1:
                raise ValueError('recovery-model-failed')
            return self.model(folder, label, *args)
        with self.adapters(interrupted):
            self.assertEqual(self.run_repair(), 'proposing')
            self.assertEqual(self.run_repair(), 'completed')
        self.assertEqual(attempts, ['proposal', 'review', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assertEqual(self.state_value()['attempts'], 1)
        self.assert_preserved()

    def test_setup_error_and_timeout_are_not_reproduced_defects(self):
        for code in (2, 124):
            self.check_codes = [code]
            with self.adapters():
                self.assertEqual(self.run_repair(), 'failed')
            self.assertEqual(self.state_value()['reason'], 'candidate-repair-regression-did-not-reproduce')
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'proposal'])
        self.assertEqual(C.private(self.state / 'campaign.json'), self.before)

    def test_partial_snapshot_interruption_does_not_publish_tree_or_repeat_proposal(self):
        class WorkerKilled(BaseException):
            pass
        snapshots = []
        def interrupted_snapshot(bundle, destination):
            snapshots.append(destination)
            if len(snapshots) == 1:
                destination.mkdir(mode=0o700)
                R.put(destination / 'partial.py', b'raise RuntimeError("partial fixture")\n')
                raise WorkerKilled('fixture-killed-during-snapshot-copy')
            return B.snapshot(bundle, destination)
        with self.adapters(snapshot=interrupted_snapshot), self.assertRaises(WorkerKilled):
            self.run_repair()
        folder, saved = M.pointed_state(self.state)
        attempt = folder / 'attempt-1'
        self.assertEqual(saved['phase'], 'checking')
        self.assertFalse((attempt / 'before').exists())
        self.assertFalse((attempt / 'after').exists())
        self.assertEqual(list(attempt.glob('.candidate-tree-*')), [])
        self.assertEqual(self.checks, [])
        with self.adapters(snapshot=interrupted_snapshot):
            self.assertEqual(self.dispatch_repair(), 'completed')
        self.assertTrue((attempt / 'before').is_dir())
        self.assertTrue((attempt / 'after').is_dir())
        self.assertEqual(len(snapshots), 3)
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assertEqual(self.state_value()['attempts'], 1)
        self.assert_preserved()

    def test_complete_snapshot_with_changed_bytes_is_not_replaced_or_accepted(self):
        sources = M.packet_sources(M.context(self.state))
        target = self.operator / 'complete-snapshot-fixture'
        self.assertEqual(M.make_tree(B, target, sources), target)
        changed = target / 'candidates/current/source/worker.ps1'
        changed.write_bytes(b'function Invoke-Worker { return 999 }\n')
        before = B.tree_hashes(target)
        with self.assertRaisesRegex(ValueError, 'candidate-repair-snapshot-changed'):
            M.make_tree(B, target, sources)
        self.assertEqual(B.tree_hashes(target), before)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.checks, [])
        self.assert_preserved()

    def test_crash_between_baseline_and_checks_reuses_baseline_and_proposal(self):
        class WorkerKilled(BaseException):
            pass
        invocations = []
        interrupted = False
        def kill_first_check(tree, tests, log):
            nonlocal interrupted
            invocations.append(Path(tree).name)
            if Path(tree).name == 'after' and not interrupted:
                interrupted = True
                raise WorkerKilled('fixture-worker-killed-during-check-launch')
            return self.sandbox(tree, tests, log)
        with self.adapters(sandbox=kill_first_check), self.assertRaises(WorkerKilled):
            self.run_repair()
        folder, saved = M.pointed_state(self.state)
        self.assertEqual(saved['phase'], 'checking')
        attempt = folder / 'attempt-1'
        baseline = (attempt / 'baseline-result.json').read_bytes()
        baseline_log = (attempt / 'baseline-run-1.txt').read_bytes()
        self.assertFalse((attempt / 'checks-result.json').exists())
        self.assertFalse((attempt / 'checks.txt').exists())
        self.assertTrue((attempt / 'checks-run-1.json').exists())
        with self.adapters(sandbox=kill_first_check):
            self.assertEqual(self.dispatch_repair(), 'completed')
        self.assertEqual(invocations, ['before', 'after', 'after'])
        self.assertEqual(self.stopped, [str(attempt / 'checks-run-1.txt')])
        self.assertEqual((attempt / 'baseline-result.json').read_bytes(), baseline)
        self.assertEqual((attempt / 'baseline-run-1.txt').read_bytes(), baseline_log)
        self.assertFalse((attempt / 'baseline-run-2.json').exists())
        self.assertTrue((attempt / 'checks-run-2.json').exists())
        self.assertEqual(C.private(attempt / 'checks-result.json')['log']['path'], str(attempt / 'checks-run-2.txt'))
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assertEqual(self.state_value()['attempts'], 1)
        self.assert_preserved()

    def test_crash_between_adoption_state_and_pointer_save_recovers_authoritative_state(self):
        real_save = C.save
        interrupted = False
        def fail_pointer(path, value):
            nonlocal interrupted
            if (path == self.state / 'candidate-repair.json' and value.get('phase') == 'adopting'
                    and not interrupted):
                interrupted = True
                raise OSError('fixture-interrupted-before-pointer-save')
            return real_save(path, value)
        with self.adapters(), mock.patch.object(C, 'save', side_effect=fail_pointer):
            self.assertEqual(self.run_repair(), 'adopting')
        self.assertTrue(interrupted)
        self.assertEqual(C.private(self.state / 'candidate-repair.json')['phase'], 'reviewing')
        self.assertEqual(M.pointed_state(self.state)[1]['phase'], 'adopting')
        self.assertEqual(C.private(self.state / 'campaign.json'), self.before)
        with self.adapters():
            self.assertEqual(self.dispatch_repair(), 'completed')
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assertEqual(self.state_value()['attempts'], 1)
        self.assert_preserved()

    def test_crash_after_campaign_save_replays_without_new_proposal_or_sandbox(self):
        real_reconcile = R.reconcile
        crashed = False
        def interrupted(root):
            nonlocal crashed
            if not crashed and C.private(root / 'campaign.json')['phase'] == 'active':
                crashed = True
                raise OSError('fixture-interrupted-after-campaign-save')
            return real_reconcile(root)
        with self.adapters(), mock.patch.object(R, 'reconcile', side_effect=interrupted):
            self.assertEqual(self.run_repair(), 'adopting')
        self.assertTrue(crashed)
        with self.adapters():
            self.assertEqual(self.dispatch_repair(), 'completed')
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assert_preserved()

    def test_crash_after_reconcile_reenters_cli_gate_without_new_work(self):
        real_reconcile = R.reconcile
        interrupted = False
        def fail_after_reconcile(root):
            nonlocal interrupted
            result = real_reconcile(root)
            if not interrupted and C.private(root / 'campaign-auto-review.json')['phase'] == 'operator_reviewed':
                interrupted = True
                raise OSError('fixture-interrupted-after-reconcile')
            return result
        with self.adapters(), mock.patch.object(R, 'reconcile', side_effect=fail_after_reconcile):
            self.assertEqual(self.run_repair(), 'adopting')
        self.assertTrue(interrupted)
        self.assertEqual(C.private(self.state / 'campaign-auto-review.json')['phase'], 'operator_reviewed')
        with self.adapters():
            self.assertEqual(self.dispatch_repair(), 'completed')
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assert_preserved()

    def test_completed_state_survives_final_pointer_failure_without_becoming_failed(self):
        real_save = C.save
        interrupted = False
        def fail_completed_pointer(path, value):
            nonlocal interrupted
            if (path == self.state / 'candidate-repair.json' and value.get('phase') == 'completed'
                    and not interrupted):
                interrupted = True
                raise OSError('fixture-interrupted-before-completed-pointer-save')
            return real_save(path, value)
        with self.adapters(), mock.patch.object(C, 'save', side_effect=fail_completed_pointer):
            self.assertEqual(self.run_repair(), 'completed')
        self.assertTrue(interrupted)
        self.assertEqual(C.private(self.state / 'candidate-repair.json')['phase'], 'adopting')
        self.assertEqual(self.state_value()['phase'], 'completed')
        with self.adapters():
            self.assertEqual(self.dispatch_repair(), 'completed')
        self.assertEqual(self.state_value()['phase'], 'completed')
        self.assertEqual(self.state_value()['attempts'], 1)
        self.assertEqual([call[0] for call in self.calls], ['proposal', 'review'])
        self.assertEqual(len(self.checks), 2)
        self.assert_preserved()

if __name__ == '__main__':
    unittest.main()
