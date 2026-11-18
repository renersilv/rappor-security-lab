#!/usr/bin/env python3
"""Consumed review transports reach bounded recovery without renewing work grants."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('review_transport_fixture', HERE / 'campaign-review-tests.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
R, C = BASE.R, BASE.C
spec = importlib.util.spec_from_file_location('transport_recovery_fixture', HERE.parent / 'recovery.py')
RECOVERY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RECOVERY)


class TransportTests(BASE.ReviewTests):
    # Reuse fixture methods, not its unrelated inherited test cases.
    def consumed(self, count=3):
        self.job = self.prepare()
        R.put(self.job / 'model-attempts', (str(count) + '\n').encode())
        R.put(self.job / 'events.jsonl', b'{"type":"turn.failed","error":{"message":"synthetic transport failure"}}\n')
        (self.state / 'base_sha').write_text('a' * 40 + '\n')
        (self.state / 'branch').write_text('joao/batch-20261118T000000Z-19-19\n')
        (self.state / 'current_issue').write_text('19\n')
        for name in ('base_sha', 'branch', 'current_issue'):
            (self.state / name).chmod(0o600)
        self.limit = mock.patch.object(R, 'transport_limit', return_value=3)
        self.limit_mock = self.limit.start()
        self.addCleanup(self.limit.stop)
        return self.job

    def test_consumed_transports_suspend_once_and_preserve_history(self):
        self.consumed()
        campaign = (self.state / 'campaign.json').read_bytes()
        counter = (self.job / 'model-attempts').read_bytes()
        self.assertEqual(R.transport_status(self.state)['status'], 'exhausted')
        R.record_transport_exhaustion(self.state)
        first = (self.state / 'issue-retry').read_bytes()
        receipt = (self.job / 'transport-exhaustion-3.json').read_bytes()
        for _ in range(3):
            R.record_transport_exhaustion(self.state)
        self.assertEqual((self.state / 'issue-retry').read_bytes(), first)
        self.assertEqual((self.job / 'transport-exhaustion-3.json').read_bytes(), receipt)
        self.assertIn(b'attempts=3\nsuspended=true', first)
        self.assertEqual((self.state / 'campaign.json').read_bytes(), campaign)
        self.assertEqual((self.job / 'model-attempts').read_bytes(), counter)

    def test_matching_first_failure_is_promoted_using_actual_transport_consumption(self):
        self.consumed()
        desired = R.transport_retry(self.state)
        prior = desired.replace('attempts=3\nsuspended=true', 'attempts=1\nsuspended=false')
        R.put(self.state / 'issue-retry', prior.encode())
        R.record_transport_exhaustion(self.state)
        self.assertEqual((self.state / 'issue-retry').read_text(), desired)
        receipt = C.private(self.job / 'transport-exhaustion-3.json')
        self.assertEqual(receipt['previousRetry'], prior)

    def test_different_incident_cannot_be_overwritten(self):
        self.consumed()
        prior = R.transport_retry(self.state).replace('fingerprint=', 'fingerprint=ffff')
        R.put(self.state / 'issue-retry', prior.encode())
        with self.assertRaisesRegex(ValueError, 'unrelated-review-transport-retry'):
            R.record_transport_exhaustion(self.state)
        self.assertEqual((self.state / 'issue-retry').read_text(), prior)

    def test_work_rereview_never_grants_generic_recovery(self):
        self.consumed()
        bundle = C.private(self.job / 'bundle.json')
        bundle['workRereview'] = {'synthetic': True}
        self.limit_mock.return_value = 9
        C.save(self.job / 'bundle.json', bundle)
        marker = C.private(self.state / 'campaign-auto-review.json')
        marker['bundleSha256'] = C.digest(self.job / 'bundle.json')
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.assertEqual(R.transport_status(self.state)['status'], 'hard_limit')
        with self.assertRaisesRegex(ValueError, 'review-transport-not-exhausted'):
            R.record_transport_exhaustion(self.state)
        self.assertFalse((self.state / 'issue-retry').exists())

    def test_unconsumed_transport_does_not_suspend(self):
        self.consumed(2)
        self.assertEqual(R.transport_status(self.state)['status'], 'pending')
        with self.assertRaisesRegex(ValueError, 'review-transport-not-exhausted'):
            R.record_transport_exhaustion(self.state)

    def test_valid_verdict_is_not_a_transport_failure(self):
        self.consumed()
        verdict = dict(verdict='changes_requested', findings=['worker.ps1: bounded synthetic correction required'],
                       nextAction='Correct the isolated fixture and rerun its offline test.', scope='offline',
                       evidence=['worker.ps1'], cleanupAssessment='not_required', progress='none', ownerRequest=None)
        C.save(self.job / 'events.jsonl', dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(verdict))))
        R.put(self.job / 'model-completed', b'completed\n')
        self.assertEqual(R.validate_response(self.state), 'valid')
        self.assertEqual(R.transport_status(self.state)['status'], 'verdict_pending')
        with self.assertRaisesRegex(ValueError, 'review-transport-not-exhausted'):
            R.record_transport_exhaustion(self.state)

    def test_semantically_invalid_work_selection_exhausts_transport(self):
        self.consumed()
        verdict = dict(verdict='changes_requested', findings=['worker.ps1: synthetic correction required'],
                       nextAction='Correct the isolated fixture and rerun its offline test.', scope='offline',
                       evidence=['worker.ps1'], cleanupAssessment='not_required', progress='none', ownerRequest=None,
                       workContinuation=dict(targetObjectiveId='web-entries'))
        C.save(self.job / 'events.jsonl', dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(verdict))))
        R.put(self.job / 'model-completed', b'completed\n')
        # Syntactically valid output is not permission to enter another objective.
        self.assertEqual(R.result(self.job / 'events.jsonl', C.private(self.job / 'bundle.json')), verdict)
        with self.assertRaisesRegex(ValueError, 'unsafe-work-continuation'):
            value = C.private(self.state / 'campaign.json')
            R.WORK.select(value, verdict, R.packet(value, self.state), C.artifact)
        self.assertEqual(R.transport_status(self.state)['status'], 'exhausted')
        R.record_transport_exhaustion(self.state)
        self.assertTrue((self.state / 'issue-retry').exists())

    def test_valid_output_from_failed_cli_does_not_count_as_completed_review(self):
        self.consumed()
        verdict = dict(verdict='changes_requested', findings=['worker.ps1: synthetic correction required'],
                       nextAction='Correct the isolated fixture and rerun its offline test.', scope='offline',
                       evidence=['worker.ps1'], cleanupAssessment='not_required', progress='none', ownerRequest=None)
        event = json.dumps(dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(verdict))))
        for code in (124, 1):
            with self.subTest(exit_code=code):
                child = subprocess.run([sys.executable, '-c',
                    'import sys;print(sys.argv[1]);sys.exit(int(sys.argv[2]))', event, str(code)],
                    capture_output=True, timeout=10)
                self.assertEqual(child.returncode, code)
                (self.job / 'events.jsonl').write_bytes(child.stdout)
                self.assertEqual(R.result(self.job / 'events.jsonl', C.private(self.job / 'bundle.json')), verdict)
                self.assertFalse((self.job / 'model-completed').exists())
                self.assertEqual(R.transport_status(self.state)['status'], 'exhausted')
                R.record_transport_exhaustion(self.state)
                self.assertIn('suspended=true', (self.state / 'issue-retry').read_text())

    def test_non_regenerable_review_violation_remains_closed(self):
        self.consumed()
        C.save(self.job / 'events.jsonl', dict(type='item.started', item=dict(type='command_execution')))
        for operation in (R.validate_response, R.transport_status, R.record_transport_exhaustion):
            with self.assertRaisesRegex(ValueError, 'review-attempted-tool-use'):
                operation(self.state)
        self.assertFalse((self.state / 'issue-retry').exists())

    def test_terminal_recovery_state_is_never_reset(self):
        self.consumed()
        for phase in ('unrepairable', 'external_action', 'recovered'):
            C.save(self.state / 'recovery.json', dict(phase=phase, attempts=2))
            before = (self.state / 'recovery.json').read_bytes()
            R.record_transport_exhaustion(self.state)
            self.assertEqual((self.state / 'recovery.json').read_bytes(), before)

    def test_partial_receipt_reconciles_but_changed_retry_is_rejected(self):
        self.consumed()
        R.record_transport_exhaustion(self.state)
        desired = (self.state / 'issue-retry').read_bytes()
        (self.state / 'issue-retry').unlink()
        R.record_transport_exhaustion(self.state)
        self.assertEqual((self.state / 'issue-retry').read_bytes(), desired)
        changed = desired.replace(b'codex_exit', b'delivery_invalid')
        (self.state / 'issue-retry').write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'unrelated-review-transport-retry'):
            R.record_transport_exhaustion(self.state)
        self.assertEqual((self.state / 'issue-retry').read_bytes(), changed)

    def test_different_consumption_windows_preserve_each_receipt(self):
        self.consumed()
        R.record_transport_exhaustion(self.state)
        original = (self.job / 'transport-exhaustion-3.json').read_bytes()
        self.limit_mock.return_value = 6
        (self.job / 'model-attempts').write_text('6\n')
        R.record_transport_exhaustion(self.state)
        self.assertEqual((self.job / 'transport-exhaustion-3.json').read_bytes(), original)
        self.assertEqual(C.private(self.job / 'transport-exhaustion-6.json')['consumed'], 6)

    def granted_window(self, consumed=6, attempts=1):
        self.consumed()
        R.record_transport_exhaustion(self.state)
        desired = (self.state / 'issue-retry').read_text()
        fingerprint = dict(line.split('=', 1) for line in desired.splitlines())['fingerprint']
        folder = self.state / 'diagnostics/recovery' / fingerprint / str(attempts)
        folder.mkdir(parents=True, mode=0o700)
        target = 'b' * 40
        C.save(folder / 'released-retry.json', dict(sha256=C.digest(self.state / 'issue-retry'), content=desired, target=target))
        old = dict(fingerprint=fingerprint, attempts=attempts, phase='recovered', directory=str(folder),
                   target=target, protected={str(self.state / 'campaign.json'):C.digest(self.state / 'campaign.json')})
        C.save(self.state / 'recovery.json', old)
        limit = 6 if attempts == 1 else 9
        C.save(self.job / 'recovery-review-window.json', dict(target=target, maximum=limit,
               bundleSha256=C.private(self.state / 'campaign-auto-review.json')['bundleSha256'],
               receipt=dict(path=str(folder / 'released-retry.json'), sha256=C.digest(folder / 'released-retry.json'))))
        self.limit_mock.return_value = limit
        (self.job / 'model-attempts').write_text(str(consumed) + '\n')
        if consumed == limit:
            R.record_transport_exhaustion(self.state)
        return old

    def recovery_git(self, repo, *args):
        if args == ('rev-parse', 'HEAD'):
            return 'b' * 40
        if args == ('symbolic-ref', '--short', 'HEAD'):
            return 'main'
        if args == ('status', '--porcelain') or args[0] == 'merge-base':
            return ''
        raise AssertionError('Unexpected Git mutation')

    def test_new_consumed_window_uses_second_repair_without_resetting_fingerprint(self):
        old = self.granted_window()
        answer = dict(disposition='unrepairable', diagnosis='Synthetic second diagnosis; no safe patch proposed.', files=[])
        with mock.patch.object(RECOVERY.C, 'REVIEW_ROOT', self.operator), \
                mock.patch.object(RECOVERY, 'load_review', return_value=R), \
                mock.patch.object(RECOVERY, 'git', side_effect=self.recovery_git), \
                mock.patch.object(RECOVERY, 'sandbox_preflight'), \
                mock.patch.object(RECOVERY, 'protected', return_value=old['protected']), \
                mock.patch.object(RECOVERY, 'incident_bundle', return_value={'synthetic':True}), \
                mock.patch.object(RECOVERY, 'call_model', return_value=answer) as model:
            RECOVERY.supervise(self.state, self.worktree, 'fixture', 'fixture')
            self.assertEqual(C.private(self.state / 'recovery.json')['attempts'], 2)
            RECOVERY.supervise(self.state, self.worktree, 'fixture', 'fixture')
        current = C.private(self.state / 'recovery.json')
        self.assertEqual(current['attempts'], 2)
        self.assertEqual(current['fingerprint'], old['fingerprint'])
        self.assertEqual(model.call_count, 1)
        self.assertTrue((self.state / 'issue-retry').exists())
        self.assertEqual((self.job / 'model-attempts').read_text(), '6\n')

    def test_crash_after_grant_releases_gate_without_second_repair(self):
        self.granted_window(consumed=3)
        with mock.patch.object(RECOVERY.C, 'REVIEW_ROOT', self.operator), \
                mock.patch.object(RECOVERY, 'git', side_effect=self.recovery_git), \
                mock.patch.object(RECOVERY, 'call_model', side_effect=AssertionError('Unexpected model')):
            RECOVERY.supervise(self.state, self.worktree, 'fixture', 'fixture')
        self.assertFalse((self.state / 'issue-retry').exists())
        self.assertEqual(C.private(self.state / 'recovery.json')['attempts'], 1)

    def test_nine_consumed_transports_stop_after_two_repairs(self):
        old = self.granted_window(consumed=9, attempts=2)
        with mock.patch.object(RECOVERY.C, 'REVIEW_ROOT', self.operator), \
                mock.patch.object(RECOVERY, 'load_review', return_value=R), \
                mock.patch.object(RECOVERY, 'git', side_effect=self.recovery_git), \
                mock.patch.object(RECOVERY, 'call_model', side_effect=AssertionError('Unexpected model')):
            with self.assertRaisesRegex(ValueError, 'recovery-candidates-exhausted'):
                RECOVERY.supervise(self.state, self.worktree, 'fixture', 'fixture')
            RECOVERY.supervise(self.state, self.worktree, 'fixture', 'fixture')
        current = C.private(self.state / 'recovery.json')
        self.assertEqual(current['phase'], 'unrepairable')
        self.assertEqual(current['attempts'], 2)
        self.assertEqual(current['fingerprint'], old['fingerprint'])
        self.assertTrue((self.state / 'issue-retry').exists())

    def test_exhausted_window_without_its_receipt_cannot_clear_gate(self):
        self.granted_window()
        (self.job / 'transport-exhaustion-6.json').unlink()
        before = (self.state / 'issue-retry').read_bytes()
        with mock.patch.object(RECOVERY.C, 'REVIEW_ROOT', self.operator), \
                mock.patch.object(RECOVERY, 'load_review', return_value=R), \
                mock.patch.object(RECOVERY, 'git', side_effect=self.recovery_git), \
                mock.patch.object(RECOVERY, 'call_model', side_effect=AssertionError('Unexpected model')):
            with self.assertRaises(OSError):
                RECOVERY.supervise(self.state, self.worktree, 'fixture', 'fixture')
        self.assertEqual((self.state / 'issue-retry').read_bytes(), before)

    def test_mutated_snapshot_cannot_create_retry(self):
        self.consumed()
        campaign = C.private(self.state / 'campaign.json')
        campaign['lastSummary'] = 'changed'
        C.save(self.state / 'campaign.json', campaign)
        with self.assertRaises(ValueError):
            R.record_transport_exhaustion(self.state)
        self.assertFalse((self.state / 'issue-retry').exists())

    def test_marker_with_reviewed_verdict_is_not_transport_exhaustion(self):
        self.consumed()
        marker = C.private(self.state / 'campaign-auto-review.json')
        marker['phase'] = 'stalled'
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.assertEqual(R.transport_status(self.state)['status'], 'not_pending')


if __name__ == '__main__':
    suite = unittest.TestSuite(TransportTests(name) for name in TransportTests.__dict__ if name.startswith('test_'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
