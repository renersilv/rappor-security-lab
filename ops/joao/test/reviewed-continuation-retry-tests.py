#!/usr/bin/env python3
"""A fresh reviewed offline target supersedes only its exact historical gate."""
import contextlib
import importlib.util
import io
import os
import stat
import subprocess
import sys
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reviewed_continuation_fixture', HERE / 'work-continuation-tests.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
R, C = BASE.R, BASE.C


class ReviewedContinuationTests(BASE.WorkContinuationTests):
    def setUp(self):
        super().setUp()
        self.fingerprint = 'e' * 64
        self.retry = self.state / 'issue-retry'
        R.put(self.retry, (f'version=1\nissue=19\nbranch={self.before["branch"]}\nerror_class=codex_exit\n'
                          f'fingerprint={self.fingerprint}\nattempts=3\nsuspended=true\n').encode())
        self.recovery_dir = self.state / 'diagnostics/recovery' / self.fingerprint / '1'
        self.recovery_dir.mkdir(parents=True, mode=0o700)
        self.incident_path = self.recovery_dir / 'incident.json'
        C.save(self.incident_path, dict(base='a' * 40, incident=dict(
            fingerprint=self.fingerprint, executorPass=5, reviewExecutorPass=5,
            reviewMatchesCurrentPass=True, campaignPhase='review_pending',
            packetValidation='valid', responseValidation='valid', verdict='changes_requested',
            review={'scope': 'offline', 'objectiveId': 'ide-mcp', 'ownerRequest': None},
            **{'class': 'codex_exit'})))
        self.recovery_path = self.state / 'recovery.json'
        C.save(self.recovery_path, dict(phase='unrepairable', fingerprint=self.fingerprint,
            attempts=1, directory=str(self.recovery_dir), base='a' * 40, retrySha256=C.digest(self.retry),
            protected={str(p): C.digest(p) for p in (self.auth_path, self.state / 'stage.json', self.state / 'session')}))
        self.approval('web-entries')
        self.finish()
        self.review_dir, self.marker = R.job(self.state)
        R.put(self.review_dir / 'model-completed', b'completed\n')
        self.original_retry = self.retry.read_bytes()
        self.unchanged = {p: p.read_bytes() for p in (self.recovery_path, self.incident_path,
            self.ledger, self.auth_path, self.state / 'campaign.json', self.attempts / 'attempt-1/receipt.json')}

    def resume(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            R.resume_correction(self.state)
        return output.getvalue().strip()

    def assert_preserved(self):
        for path, raw in self.unchanged.items():
            self.assertEqual(path.read_bytes(), raw, str(path))

    def test_exact_historical_gate_is_archived_then_superseded(self):
        outcome = self.resume()
        self.assertFalse(self.retry.exists(), f'exact historical gate still blocks reviewed continuation: {outcome}')
        self.assertEqual(outcome, 'resumed')
        receipt = C.private(self.review_dir / 'superseded-executor-retry.json')
        self.assertEqual(receipt['retry']['content'].encode(), self.original_retry)
        self.assertEqual(receipt['retry']['sha256'], R.sha(self.original_retry))
        self.assertEqual(receipt['reason'], 'different_reviewed_offline_target')
        self.assert_preserved()
        for _ in range(3):
            self.assertEqual(self.resume(), 'resumed')
        self.assertEqual(C.private(self.review_dir / 'superseded-executor-retry.json'), receipt)
        self.assert_preserved()

    def test_notification_intent_survives_unlink_and_is_not_rearmed_after_ack(self):
        marker = C.private(self.state / 'campaign-auto-review.json')
        marker['noticePending'] = False
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.resume()
        self.assertTrue(C.private(self.state / 'campaign-auto-review.json')['noticePending'])
        marker = C.private(self.state / 'campaign-auto-review.json')
        marker['noticePending'] = False
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.resume()
        self.assertFalse(C.private(self.state / 'campaign-auto-review.json')['noticePending'])

    def test_status_distinguishes_archived_incident_and_new_gate_without_mutation(self):
        self.assertEqual(R.reviewed_retry_disposition(self.state), 'current')
        self.resume()
        self.assertEqual(R.reviewed_retry_disposition(self.state), 'historical_superseded')
        new = self.original_retry.replace(b'fingerprint=' + b'e' * 64, b'fingerprint=' + b'f' * 64)
        self.retry.write_bytes(new)
        self.retry.chmod(0o600)
        self.assertEqual(R.reviewed_retry_disposition(self.state), 'historical_superseded_new_gate')
        self.assertEqual(self.retry.read_bytes(), new)
        self.assert_preserved()

    def test_crash_after_archive_replays_exact_unlink(self):
        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path == self.retry:
                raise OSError('synthetic interruption before gate unlink')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', interrupted), self.assertRaises(OSError):
            self.resume()
        self.assertEqual(self.retry.read_bytes(), self.original_retry)
        self.assertTrue((self.review_dir / 'superseded-executor-retry.json').exists())
        self.assertEqual(R.reviewed_retry_disposition(self.state), 'archived_gate_pending')
        self.assertEqual(self.resume(), 'resumed')
        self.assert_preserved()

    def test_new_gate_after_crash_is_never_removed(self):
        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path == self.retry:
                raise OSError('synthetic interruption')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', interrupted), self.assertRaises(OSError):
            self.resume()
        new = self.original_retry.replace(b'fingerprint=' + b'e' * 64, b'fingerprint=' + b'f' * 64)
        self.retry.write_bytes(new)
        with self.assertRaises(ValueError):
            self.resume()
        self.assertEqual(self.retry.read_bytes(), new)

    def test_fifo_archive_is_rejected_without_blocking_or_removing_gate(self):
        archive = self.review_dir / 'superseded-executor-retry.json'
        os.mkfifo(archive, 0o600)
        script = """import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('archive_fixture',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.archive_superseded_retry(Path(sys.argv[2]),b'{}')
"""
        result = subprocess.run([sys.executable, '-B', '-c', script, str(R.__file__), str(archive)],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('immutable-review-artifact-changed', result.stderr)
        self.assertEqual(self.retry.read_bytes(), self.original_retry)
        self.assertTrue(stat.S_ISFIFO(archive.stat().st_mode))

    def test_partial_archive_write_never_publishes_partial_authority(self):
        original_write = os.write
        calls = 0
        def partial_then_fail(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(fd, data[:max(1, len(data) // 2)])
            raise OSError('synthetic disk full during archive')
        with mock.patch.object(R.os, 'write', partial_then_fail), self.assertRaises(OSError):
            self.resume()
        self.assertFalse((self.review_dir / 'superseded-executor-retry.json').exists())
        self.assertEqual(list(self.review_dir.glob('.superseded-retry-*')), [])
        self.assertEqual(self.retry.read_bytes(), self.original_retry)
        self.assertEqual(self.resume(), 'resumed')
        self.assert_preserved()

    def test_archive_file_sync_failure_never_publishes_and_replay_syncs_existing_file(self):
        original = os.fsync
        def fail_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError('synthetic archive file sync failure')
            return original(fd)
        with mock.patch.object(R.os, 'fsync', fail_file), self.assertRaises(OSError):
            self.resume()
        self.assertFalse((self.review_dir / 'superseded-executor-retry.json').exists())
        self.assertEqual(self.retry.read_bytes(), self.original_retry)
        # Publish a complete record, then interrupt directory durability before unlink.
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('synthetic directory sync failure')
            return original(fd)
        with mock.patch.object(R.os, 'fsync', fail_directory), self.assertRaises(OSError):
            self.resume()
        self.assertTrue((self.review_dir / 'superseded-executor-retry.json').exists())
        with mock.patch.object(R.os, 'fsync', fail_file), self.assertRaises(OSError):
            self.resume()
        self.assertEqual(self.retry.read_bytes(), self.original_retry)
        self.assertEqual(self.resume(), 'resumed')
        self.assert_preserved()

    def test_archive_directory_sync_failure_preserves_gate(self):
        original = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('synthetic directory sync failure')
            return original(fd)
        with mock.patch.object(R.os, 'fsync', fail_directory), self.assertRaises(OSError):
            self.resume()
        self.assertEqual(self.retry.read_bytes(), self.original_retry)
        self.assertTrue((self.review_dir / 'superseded-executor-retry.json').exists())
        self.assertEqual(self.resume(), 'resumed')
        self.assert_preserved()

    def test_root_sync_after_unlink_failure_replays_without_rearming_notice(self):
        original = os.fsync
        root_identity = self.state.stat().st_ino
        root_syncs = 0
        def fail_after_unlink(fd):
            nonlocal root_syncs
            metadata = os.fstat(fd)
            if stat.S_ISDIR(metadata.st_mode) and metadata.st_ino == root_identity:
                root_syncs += 1
                if root_syncs == 2:
                    raise OSError('synthetic final root sync failure')
            return original(fd)
        with mock.patch.object(R.os, 'fsync', fail_after_unlink), self.assertRaises(OSError):
            self.resume()
        self.assertFalse(self.retry.exists())
        marker = C.private(self.state / 'campaign-auto-review.json')
        self.assertTrue(marker['noticePending'])
        self.assertEqual(self.resume(), 'resumed')
        self.assert_preserved()

    def test_gate_replaced_during_archive_is_preserved(self):
        original_put = R.archive_superseded_retry
        replacement = self.original_retry.replace(b'fingerprint=' + b'e' * 64, b'fingerprint=' + b'f' * 64)
        def replace_gate(path, data):
            value = original_put(path, data)
            if path.name == 'superseded-executor-retry.json':
                self.retry.write_bytes(replacement)
            return value
        with mock.patch.object(R, 'archive_superseded_retry', replace_gate), self.assertRaises(ValueError):
            self.resume()
        self.assertEqual(self.retry.read_bytes(), replacement)
        self.assert_preserved()

    def test_divergent_archive_cannot_be_rewritten(self):
        archive = self.review_dir / 'superseded-executor-retry.json'
        R.put(archive, b'{"schema":999}\n')
        with self.assertRaisesRegex(ValueError, 'immutable-review-artifact-changed'):
            self.resume()
        self.assertEqual(archive.read_bytes(), b'{"schema":999}\n')
        self.assertEqual(self.retry.read_bytes(), self.original_retry)

    def test_symlink_recovery_directory_is_rejected(self):
        moved = self.recovery_dir.with_name('moved')
        self.recovery_dir.rename(moved)
        self.recovery_dir.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'supersession-recovery-directory-invalid'):
            self.resume()
        self.assertEqual(self.retry.read_bytes(), self.original_retry)

    def test_missing_gate_without_archive_is_not_success(self):
        self.retry.unlink()
        self.assertEqual(self.resume(), 'not_eligible')
        self.assertFalse((self.review_dir / 'superseded-executor-retry.json').exists())

    def test_retry_without_recovery_preserves_existing_operational_lane(self):
        self.recovery_path.unlink()
        for attempts, suspended in ((1, 'false'), (2, 'false'), (3, 'true')):
            raw = self.original_retry.replace(b'attempts=3', f'attempts={attempts}'.encode())
            raw = raw.replace(b'suspended=true', f'suspended={suspended}'.encode())
            self.retry.write_bytes(raw)
            self.assertEqual(self.resume(), 'not_eligible')
            self.assertEqual(self.retry.read_bytes(), raw)
            self.assertFalse((self.review_dir / 'superseded-executor-retry.json').exists())

    def test_recovery_external_or_other_incident_is_not_released(self):
        original = C.private(self.recovery_path)
        for changes in ({'phase': 'external_action'}, {'phase': 'ready'}, {'fingerprint': 'f' * 64},
                        {'retrySha256': '0' * 64}, {'directory': str(self.state)}):
            with self.subTest(changes=changes):
                C.save(self.recovery_path, dict(original, **changes))
                try:
                    self.assertEqual(self.resume(), 'not_eligible')
                except ValueError:
                    pass
                self.assertEqual(self.retry.read_bytes(), self.original_retry)
        C.save(self.recovery_path, original)

    def test_incident_must_match_previous_pass_and_origin(self):
        original = C.private(self.incident_path)
        for changes in ({'executorPass': 4}, {'executorPass': 6}, {'verdict': 'owner_required'},
                        {'review': dict(original['incident']['review'], objectiveId='managed-technical')},
                        {'review': dict(original['incident']['review'], ownerRequest={'action': 'login'})}):
            with self.subTest(changes=changes):
                C.save(self.incident_path, dict(original, incident=dict(original['incident'], **changes)))
                with self.assertRaises(ValueError):
                    self.resume()
                self.assertEqual(self.retry.read_bytes(), self.original_retry)
        C.save(self.incident_path, original)

    def test_changed_review_artifact_prevents_release(self):
        for name in ('events.jsonl', 'result.json', 'bundle.json', 'prompt.md', 'after.json', 'model-completed'):
            with self.subTest(artifact=name):
                path = self.review_dir / name
                raw = path.read_bytes()
                path.write_bytes(b'{}\n')
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.resume()
                self.assertEqual(self.retry.read_bytes(), self.original_retry)
                path.write_bytes(raw)

    def test_altered_retry_or_delivery_failure_is_not_released(self):
        for old, new in ((b'codex_exit', b'delivery_invalid'), (b'suspended=true', b'suspended=false'),
                         (self.before['branch'].encode(), b'joao/batch-20000101T000000Z-19-19')):
            self.retry.write_bytes(self.original_retry.replace(old, new))
            with self.assertRaises(ValueError):
                self.resume()
            self.assertTrue(self.retry.exists())
        self.retry.write_bytes(self.original_retry)

    def test_nonfresh_or_runtime_grant_is_not_selected(self):
        original = C.private(self.state / 'campaign-auto-review.json')
        for changes in ({'phase': 'runtime'}, {'offlineCheckpoints': 2}, {'runtimeCheckpoints': 1},
                        {'targetObjectiveId': 'ide-mcp'}, {'nextPass': 8}):
            marker = dict(original, workContinuation=dict(original['workContinuation'], **changes))
            C.save(self.state / 'campaign-auto-review.json', marker)
            try:
                self.assertEqual(self.resume(), 'not_eligible')
            except ValueError:
                pass
            self.assertEqual(self.retry.read_bytes(), self.original_retry)
        C.save(self.state / 'campaign-auto-review.json', original)


if __name__ == '__main__':
    suite = unittest.TestSuite(ReviewedContinuationTests(name) for name in ReviewedContinuationTests.__dict__ if name.startswith('test_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
