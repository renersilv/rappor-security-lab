#!/usr/bin/env python3
"""Completed campaign evidence reaches review without changing executor authority."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pending_review_fixture', HERE / 'campaign-review-tests.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
R, C = BASE.R, BASE.C


class PendingReviewTests(BASE.ReviewTests):
    def setUp(self):
        super().setUp()
        value = C.private(self.state / 'campaign.json')
        R.put(self.state / 'issue-retry', (
            f"version=1\nissue=19\nbranch={value['branch']}\nerror_class=codex_exit\n"
            f"fingerprint={'f' * 64}\nattempts=3\nsuspended=true\n").encode())
        (self.state / 'current_issue').chmod(0o600)
        R.put(self.state / 'base_sha', b'a' * 40 + b'\n')
        R.put(self.state / 'branch', (value['branch'] + '\n').encode())

    def next_completed_pass(self):
        self.response()
        self.finish()
        directory, marker = R.job(self.state)
        marker['phase'] = 'operator_reviewed'
        C.save(self.state / 'campaign-auto-review.json', marker)
        value = C.private(self.state / 'campaign.json')
        value.update(phase='review_pending', executorPasses=2, lastFinishedPass=2)
        C.save(self.state / 'campaign.json', value)
        result = C.private(self.state / 'campaign-result.json')
        result.update(executorPass=2, phase='review_pending')
        C.save(self.state / 'campaign-result.json', result)
        manifest = C.private(self.manifest)
        manifest['executorPass'] = 2
        self.manifest = self.candidate_dir / 'manifest-pass2.json'
        C.save(self.manifest, manifest)
        return directory

    def test_completed_new_pass_ignores_previous_review_phase_without_mutation(self):
        self.next_completed_pass()
        before = {p: p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        self.assertTrue(R.pending_completed_review(self.state))
        self.assertEqual(before, {p: p.read_bytes() for p in self.state.rglob('*') if p.is_file()})

    def test_prepared_job_replays_same_directory_and_consumed_attempts(self):
        old = self.next_completed_pass()
        self.assertTrue(R.pending_completed_review(self.state))
        directory = self.prepare()
        R.put(directory / 'model-attempts', b'3\n')
        before = (self.state / 'issue-retry').read_bytes()
        for _ in range(3):
            self.assertTrue(R.pending_completed_review(self.state))
            self.assertEqual(self.prepare(), directory)
        self.assertNotEqual(directory, old)
        self.assertEqual((directory / 'model-attempts').read_bytes(), b'3\n')
        self.assertEqual((self.state / 'issue-retry').read_bytes(), before)

    def test_unfinished_active_or_owner_required_is_not_selected(self):
        self.next_completed_pass()
        original = C.private(self.state / 'campaign.json')
        for changes in ({'lastFinishedPass': 1}, {'phase': 'active'}, {'phase': 'owner_required'}):
            with self.subTest(changes=changes):
                C.save(self.state / 'campaign.json', dict(original, **changes))
                self.assertFalse(R.pending_completed_review(self.state))

    def test_changed_manifest_binding_or_ahead_marker_fails_closed(self):
        self.next_completed_pass()
        self.prepare()
        marker = C.private(self.state / 'campaign-auto-review.json')
        for changes in ({'executorPass': 3}, {'beforeSha256': 'a' * 64}, {'manifest': dict(marker['manifest'], sha256='a' * 64)}):
            with self.subTest(changes=changes):
                C.save(self.state / 'campaign-auto-review.json', dict(marker, **changes))
                with self.assertRaises(ValueError):
                    R.pending_completed_review(self.state)
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.source.write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'candidate-hash-changed'):
            R.pending_completed_review(self.state)

    def test_same_pass_terminal_review_cannot_be_renewed(self):
        self.prepare()
        marker = C.private(self.state / 'campaign-auto-review.json')
        for phase in ('stalled', 'owner_required', 'continued', 'operator_reviewed'):
            C.save(self.state / 'campaign-auto-review.json', dict(marker, phase=phase))
            self.assertFalse(R.pending_completed_review(self.state))

    def test_old_marker_requires_current_checkpoint_and_same_campaign_binding(self):
        self.next_completed_pass()
        value = C.private(self.state / 'campaign.json')
        value['reviewCheckpoint'] = None
        C.save(self.state / 'campaign.json', value)
        with self.assertRaises(ValueError):
            R.pending_completed_review(self.state)

    def test_old_marker_without_terminal_authority_is_not_selected(self):
        self.next_completed_pass()
        marker = C.private(self.state / 'campaign-auto-review.json')
        for phase in ('review_pending', 'stalled', 'owner_required'):
            C.save(self.state / 'campaign-auto-review.json', dict(marker, phase=phase))
            with self.assertRaisesRegex(ValueError, 'unbound-previous-completed-review'):
                R.pending_completed_review(self.state)

    def test_changed_retry_fingerprint_cannot_renew_same_job_budget(self):
        self.next_completed_pass()
        directory = self.prepare()
        R.put(directory / 'model-attempts', b'3\n')
        retry = self.state / 'issue-retry'
        for fingerprint in ('e' * 64, 'd' * 64):
            original = retry.read_text()
            retry.write_text('\n'.join('fingerprint=' + fingerprint if line.startswith('fingerprint=') else line
                                       for line in original.splitlines()) + '\n')
            self.assertTrue(R.pending_completed_review(self.state))
            self.assertEqual(self.prepare(), directory)
            self.assertEqual((directory / 'model-attempts').read_bytes(), b'3\n')

    def test_matching_review_transport_keeps_existing_recovery_lane(self):
        self.prepare()
        (self.state / 'issue-retry').write_text(R.transport_retry(self.state))
        self.assertFalse(R.pending_completed_review(self.state))

    def test_delivery_retry_keeps_its_existing_lane_and_exact_bytes(self):
        path = self.state / 'issue-retry'
        original = path.read_text().replace('error_class=codex_exit', 'error_class=delivery_invalid')
        for attempts, suspended in ((1, 'false'), (3, 'true')):
            path.write_text(original.replace('attempts=3', f'attempts={attempts}')
                           .replace('suspended=true', f'suspended={suspended}'))
            before = path.read_bytes()
            self.assertFalse(R.pending_completed_review(self.state))
            self.assertEqual(path.read_bytes(), before)

    def test_absent_retry_does_not_replace_normal_dispatch(self):
        (self.state / 'issue-retry').unlink()
        self.assertFalse(R.pending_completed_review(self.state))

    def test_completion_result_must_match_pass_and_authorization(self):
        self.next_completed_pass()
        original = C.private(self.state / 'campaign-result.json')
        for changes in ({'executorPass': 1}, {'authorizationId': 'unrelated'}, {'phase': 'active'}):
            C.save(self.state / 'campaign-result.json', dict(original, **changes))
            with self.assertRaises(ValueError):
                R.pending_completed_review(self.state)


if __name__ == '__main__':
    suite = unittest.TestSuite(PendingReviewTests(name) for name in PendingReviewTests.__dict__ if name.startswith('test_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
