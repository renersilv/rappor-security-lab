#!/usr/bin/env python3
"""Offline recovery contracts and opt-in real isolated synthetic repair.

No model is called. JOAO_RECOVERY_E2E=1 explicitly enables the real resource-bound
sandbox; it is never inherited by tests inside that sandbox.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('recovery_under_test', HERE.parent / 'recovery.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
FINGERPRINT = 'a' * 64
REGRESSION = 'ops/joao/test/recovery-regression-duration.sh'
BROKEN = '\nrecovery_fixture_seconds() { printf "%s\\n" "$(($1 * 59))"; }\n'
FIXED = '\nrecovery_fixture_seconds() { printf "%s\\n" "$(($1 * 60))"; }\n'
REGRESSION_SOURCE = '''#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../campaign.sh"
[[ $(recovery_fixture_seconds 2) == 120 ]]
[[ $(recovery_fixture_seconds 0) == 0 ]]
'''


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='recovery-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repository'
        self.repo.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.remote = self.root / 'remote.git'
        self.command('git', 'init', '-q', '--bare', str(self.remote))
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Recovery fixture')
        self.git('config', 'user.email', 'recovery@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'core.hooksPath', '/dev/null')
        self.ops = self.repo / 'ops/joao'
        (self.ops / 'test').mkdir(parents=True)
        (self.ops / 'test/.keep').write_text('Synthetic test directory.\n')
        for name in R.ALLOWED:
            (self.ops / name).write_text('# Synthetic automation fixture.\n')
        (self.ops / 'campaign.sh').write_text('#!/usr/bin/env bash\n' + BROKEN)
        self.commit('test: synthetic faulty baseline')
        self.git('remote', 'add', 'origin', str(self.remote))
        self.git('push', '-qu', 'origin', 'main')
        self.base = self.git('rev-parse', 'HEAD')
        self.session = self.state / 'session'
        self.session.write_text('unchanged-synthetic-session\n')
        self.binding = {str(self.session): R.C.digest(self.session)}
        self.retry_path = self.state / 'issue-retry'
        self.retry_path.write_text('version=1\nissue=19\nsuspended=true\nerror_class=codex_exit\n'
                                   'fingerprint=' + FINGERPRINT + '\nattempts=3\n')
        self.retry_path.chmod(0o600)
        self.retry_bytes = self.retry_path.read_bytes()

    def command(self, *args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout.strip()

    def git(self, *args):
        return self.command('git', '-C', str(self.repo), *args)

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)

    def proposal(self):
        source = (self.ops / 'campaign.sh').read_text().replace(BROKEN, FIXED)
        return dict(disposition='repair', diagnosis='Convert fixture minutes to seconds using sixty seconds per minute.',
                    files=[dict(path='ops/joao/campaign.sh', content=source),
                           dict(path=REGRESSION, content=REGRESSION_SOURCE)])

    def test_allowlist_rejects_authority_product_existing_tests_and_traversal(self):
        for name in ['ops/joao/campaign-control.py', 'ops/joao/recovery.py',
                     'ops/joao/campaign-contract.md', 'ops/joao/contracts/issue-19.md',
                     'src/product.py', 'ops/joao/test/campaign-tests.py',
                     'ops/joao/../joao/campaign.sh', 'ops/joao/test/../../campaign.sh']:
            with self.subTest(path=name):
                value = self.proposal()
                value['files'][0]['path'] = name
                with self.assertRaises(ValueError):
                    R.validate_proposal(value, self.repo)
        self.assertEqual(R.validate_proposal(self.proposal(), self.repo), [REGRESSION])

    def test_existing_regression_and_symlink_are_not_replaced(self):
        target = self.repo / REGRESSION
        target.write_text('existing regression\n')
        with self.assertRaisesRegex(ValueError, 'existing-test'):
            R.validate_proposal(self.proposal(), self.repo)
        target.unlink()
        source = self.ops / 'campaign.sh'
        source.unlink()
        source.symlink_to(self.session)
        with self.assertRaisesRegex(ValueError, 'repair-path'):
            R.validate_proposal(self.proposal(), self.repo)
        self.assertEqual(R.C.digest(self.session), self.binding[str(self.session)])

    def test_duplicate_file_and_oversized_content_are_rejected(self):
        value = self.proposal()
        value['files'].append(copy.deepcopy(value['files'][0]))
        with self.assertRaises(ValueError):
            R.validate_proposal(value, self.repo)
        value = self.proposal()
        value['files'][0]['content'] = 'x' * 80001
        with self.assertRaises(ValueError):
            R.validate_proposal(value, self.repo)

    def test_model_tool_events_are_rejected_even_before_valid_final_answer(self):
        events = self.root / 'events.jsonl'
        for kind in ['command_execution', 'mcp_tool_call', 'web_search']:
            events.write_text(json.dumps(dict(type='item.started', item=dict(type=kind))) + '\n' +
                              json.dumps(dict(type='item.completed', item=dict(type='agent_message',
                                  text=json.dumps(self.proposal())))) + '\n')
            with self.assertRaisesRegex(ValueError, 'attempted-tool-use'):
                R.response(events)

    def test_only_two_failed_model_candidates_are_consumed(self):
        with patch.object(R, 'protected', return_value=self.binding), \
                patch.object(R, 'call_model', side_effect=ValueError('synthetic-model-failure')) as model:
            for number in [1, 2]:
                with self.assertRaisesRegex(ValueError, 'synthetic-model-failure'):
                    R.supervise(self.state, self.repo, 'fixture', 'fixture')
                state = R.C.private(self.state / 'recovery.json')
                self.assertEqual(state['attempts'], number)
                self.assertTrue((Path(state['directory']) / 'failure.json').exists())
            with self.assertRaisesRegex(ValueError, 'candidates-exhausted'):
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
            self.assertEqual(model.call_count, 2)
        self.assertEqual(self.retry_path.read_bytes(), self.retry_bytes)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)

    def ready(self):
        folder = self.root / 'ready-repair'
        folder.mkdir(mode=0o700)
        worktree = folder / 'worktree'
        self.git('worktree', 'add', '-qb', 'fixture-repair', str(worktree), self.base)
        proposal = self.proposal()
        R.apply_files(worktree, proposal['files'])
        paths = [item['path'] for item in proposal['files']]
        R.git(worktree, 'add', '--', *paths)
        state = dict(fingerprint=FINGERPRINT, attempts=1, phase='ready', directory=str(folder),
                     worktree=str(worktree), base=self.base, paths=paths, protected=self.binding,
                     retrySha256=R.C.digest(self.retry_path), reviewedTree=R.git(worktree, 'write-tree'))
        R.C.save(self.state / 'recovery.json', state)
        return state

    def test_push_failure_replays_same_commit_without_model(self):
        state = self.ready()
        real_git = R.git
        def failing_push(repo, *args):
            if args[:1] == ('push',):
                raise subprocess.CalledProcessError(1, ['git', 'push'])
            return real_git(repo, *args)
        with patch.object(R, 'git', side_effect=failing_push):
            with self.assertRaises(subprocess.CalledProcessError):
                R.integrate(self.state, self.repo, state)
        pending = R.C.private(self.state / 'recovery.json')
        self.assertEqual(pending['phase'], 'publishing')
        target = self.git('rev-parse', 'HEAD')
        self.assertNotEqual(target, self.base)
        self.assertEqual(self.command('git', '--git-dir=' + str(self.remote), 'rev-parse', 'main'), self.base)
        with patch.object(R, 'call_model', side_effect=AssertionError('Unexpected model')):
            R.supervise(self.state, self.repo, 'fixture', 'fixture')
        self.assertEqual(self.git('rev-parse', 'HEAD'), target)
        self.assertEqual(self.command('git', '--git-dir=' + str(self.remote), 'rev-parse', 'main'), target)
        self.assertEqual(self.git('rev-list', '--count', self.base + '..HEAD'), '1')
        self.assertFalse(self.retry_path.exists())
        R.unchanged(self.binding)

    def test_crash_after_recovered_releases_only_matching_gate(self):
        R.integrate(self.state, self.repo, self.ready())
        target = self.git('rev-parse', 'HEAD')
        self.retry_path.write_bytes(self.retry_bytes)
        self.retry_path.chmod(0o600)
        with patch.object(R, 'call_model', side_effect=AssertionError('Unexpected model')):
            R.supervise(self.state, self.repo, 'fixture', 'fixture')
        self.assertFalse(self.retry_path.exists())
        self.assertEqual(self.git('rev-parse', 'HEAD'), target)

    def test_changed_protected_state_stops_integration(self):
        state = self.ready()
        self.session.write_text('changed externally\n')
        with self.assertRaisesRegex(ValueError, 'protected-state-changed'):
            R.integrate(self.state, self.repo, state)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)
        self.assertTrue(self.retry_path.exists())

    def test_changed_reviewed_tree_stops_integration(self):
        state = self.ready()
        (Path(state['worktree']) / 'ops/joao/campaign.sh').write_text('unreviewed change\n')
        with self.assertRaisesRegex(ValueError, 'reviewed-tree-changed'):
            R.integrate(self.state, self.repo, state)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)

    def test_recovered_replay_cannot_remove_changed_retry_gate(self):
        R.integrate(self.state, self.repo, self.ready())
        self.retry_path.write_bytes(self.retry_bytes + b'changed=true\n')
        self.retry_path.chmod(0o600)
        with patch.object(R, 'call_model', side_effect=AssertionError('Unexpected model')):
            with self.assertRaisesRegex(ValueError, 'recovered-gate-changed'):
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
        self.assertTrue(self.retry_path.exists())

    def review_job(self):
        operator = self.root / 'operator-reviews'
        operator.mkdir(mode=0o700)
        directory = operator / 'current-job'
        directory.mkdir(mode=0o700)
        counter = directory / 'model-attempts'
        counter.write_text('3\n')
        counter.chmod(0o600)
        R.C.save(self.state / 'campaign-auto-review.json', dict(
            directory=str(directory), phase='review_pending', bundleSha256='b' * 64))
        return operator, directory, counter

    def release_receipt(self, name, target):
        directory = self.state / 'diagnostics/recovery' / name
        directory.mkdir(parents=True, mode=0o700)
        receipt = directory / 'released-retry.json'
        R.immutable(receipt, dict(sha256=R.C.digest(self.retry_path),
                                 content=self.retry_path.read_text(), target=target))
        return receipt

    def test_successful_second_candidate_grants_only_three_more_transports(self):
        operator, directory, counter = self.review_job()
        receipt = self.release_receipt('candidate-two', self.base)
        with patch.object(R.C, 'REVIEW_ROOT', operator):
            self.assertEqual(R.review_limit(self.state, self.repo), 3)
            R.grant_review_window(self.state, dict(target=self.base, attempts=2), receipt, self.repo)
            self.assertEqual(R.review_limit(self.state, self.repo), 6)
        self.assertEqual(counter.read_text(), '3\n')
        self.assertEqual(R.C.private(directory / 'recovery-review-window.json')['maximum'], 6)

    def test_grant_replay_is_idempotent_and_second_installed_repair_adds_three(self):
        operator, directory, counter = self.review_job()
        receipt = self.release_receipt('first', self.base)
        with patch.object(R.C, 'REVIEW_ROOT', operator):
            R.grant_review_window(self.state, dict(target=self.base, attempts=1), receipt, self.repo)
            original = (directory / 'recovery-review-window.json').read_bytes()
            counter.write_text('6\n')
            R.grant_review_window(self.state, dict(target=self.base, attempts=1), receipt, self.repo)
            self.assertEqual((directory / 'recovery-review-window.json').read_bytes(), original)
            (self.repo / 'second-repair.txt').write_text('Distinct installed fixture repair.\n')
            self.commit('test: second installed repair')
            target = self.git('rev-parse', 'HEAD')
            second = self.release_receipt('second', target)
            R.grant_review_window(self.state, dict(target=target, attempts=2), second, self.repo)
            self.assertEqual(R.review_limit(self.state, self.repo), 9)
            counter.write_text('9\n')
            R.grant_review_window(self.state, dict(target=target, attempts=2), second, self.repo)
            self.assertEqual(R.review_limit(self.state, self.repo), 9)
        self.assertEqual(counter.read_text(), '9\n')

    def test_unexhausted_transport_window_does_not_gain_a_grant(self):
        operator, directory, counter = self.review_job()
        counter.write_text('2\n')
        receipt = self.release_receipt('early', self.base)
        with patch.object(R.C, 'REVIEW_ROOT', operator):
            R.grant_review_window(self.state, dict(target=self.base, attempts=2), receipt, self.repo)
            self.assertEqual(R.review_limit(self.state, self.repo), 3)
        self.assertFalse((directory / 'recovery-review-window.json').exists())

    def test_review_grant_rejects_tampered_bundle_target_receipt_and_limit(self):
        operator, directory, _ = self.review_job()
        receipt = self.release_receipt('valid', self.base)
        with patch.object(R.C, 'REVIEW_ROOT', operator):
            R.grant_review_window(self.state, dict(target=self.base, attempts=1), receipt, self.repo)
            grant_path = directory / 'recovery-review-window.json'
            original = R.C.private(grant_path)
            mutations = [dict(bundleSha256='c' * 64), dict(target='d' * 40), dict(maximum=12),
                         dict(receipt=dict(path=str(receipt), sha256='e' * 64))]
            for change in mutations:
                with self.subTest(change=change):
                    R.C.save(grant_path, dict(original, **change))
                    with self.assertRaises(ValueError):
                        R.review_limit(self.state, self.repo)
            R.C.save(grant_path, original)
            original_receipt = receipt.read_bytes()
            receipt.write_bytes(original_receipt + b' ')
            with self.assertRaisesRegex(ValueError, 'invalid-reviewed-recovery-window'):
                R.review_limit(self.state, self.repo)

    def test_final_notice_survives_retry_removal_and_cli_acknowledges_once(self):
        R.integrate(self.state, self.repo, self.ready())
        self.assertFalse(self.retry_path.exists())
        cli = [sys.executable, '-B', str(HERE.parent / 'recovery.py')]
        self.assertEqual(self.command(*cli, 'notice-pending', str(self.state)), 'yes')
        self.assertIn('instalado', self.command(*cli, 'notice', str(self.state)))
        # Reading/publishing may fail externally: reads cannot consume the notice.
        self.assertEqual(self.command(*cli, 'notice-pending', str(self.state)), 'yes')
        before = R.C.private(self.state / 'recovery.json')
        self.command(*cli, 'notice-done', str(self.state))
        self.assertEqual(self.command(*cli, 'notice-pending', str(self.state)), 'no')
        self.assertEqual(R.C.private(self.state / 'recovery.json'), dict(before, noticePending=False))
        self.command(*cli, 'notice-done', str(self.state))
        self.assertEqual(self.command(*cli, 'notice-pending', str(self.state)), 'no')

    def test_stalled_pending_repair_cannot_install_or_release(self):
        self.ready()
        R.C.save(self.state / 'campaign-auto-review.json', dict(phase='stalled'))
        with patch.object(R, 'call_model', side_effect=AssertionError('Unexpected model')):
            try:
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
            except ValueError as error:
                self.assertEqual(str(error), 'objective-stall-requires-diagnostic-replanning')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)
        self.assertEqual(self.command('git', '--git-dir=' + str(self.remote), 'rev-parse', 'main'), self.base)
        self.assertEqual(self.retry_path.read_bytes(), self.retry_bytes)
        self.assertEqual(R.status(self.state)['phase'], 'unrepairable')
        self.assertTrue(R.C.private(self.state / 'recovery.json')['noticePending'])

    def test_newly_reviewed_repair_preserves_terminal_objective_stall(self):
        R.C.save(self.state / 'campaign-auto-review.json', dict(phase='stalled'))
        answers = [self.proposal(), dict(verdict='pass', findings=[])]
        with patch.object(R, 'protected', return_value=self.binding), \
                patch.object(R, 'incident_bundle', return_value=dict(incident={}, sources={}, base=self.base)), \
                patch.object(R, 'call_model', side_effect=answers), \
                patch.object(R, 'sandbox', side_effect=self.simulated_checks):
            try:
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
            except ValueError as error:
                self.assertEqual(str(error), 'objective-stall-requires-diagnostic-replanning')
        self.assertEqual(R.status(self.state)['phase'], 'unrepairable')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)
        self.assertEqual(self.retry_path.read_bytes(), self.retry_bytes)

    def test_sandbox_applies_resource_limits_and_no_host_configuration_mount(self):
        observed = []
        def process(args, **kwargs):
            observed.extend(args)
            kwargs['stdout'].write(b'recovery_checks_started=true\nrecovery_case_finished=1\n')
            return subprocess.CompletedProcess(args, 1)
        with patch.object(R.subprocess, 'run', side_effect=process):
            self.assertEqual(R.sandbox(self.repo, ['sample.py'], self.root / 'sandbox.log'), 1)
        for required in ['--property=MemoryMax=1G', '--property=TasksMax=64', '--property=CPUQuota=100%',
                         '--property=RuntimeMaxSec=310s', '--unshare-all', '--clearenv']:
            self.assertIn(required, observed)
        self.assertNotIn('/etc', observed)
        read_only_mounts = [observed[index + 1] for index, value in enumerate(observed)
                            if value == '--ro-bind']
        self.assertEqual(read_only_mounts, ['/usr', str(self.repo)])
        self.assertNotIn('JOAO_RECOVERY_E2E', observed)
        self.assertIn('JOAO_RECOVERY_SANDBOX', observed)

    def test_sandbox_startup_failure_is_not_a_failing_regression(self):
        def process(args, **kwargs):
            kwargs['stdout'].write(b'sandbox startup failed\n')
            return subprocess.CompletedProcess(args, 1)
        with patch.object(R.subprocess, 'run', side_effect=process):
            with self.assertRaisesRegex(ValueError, 'sandbox-did-not-run-tests'):
                R.sandbox(self.repo, ['sample.py'], self.root / 'sandbox.log')

    def simulated_checks(self, worktree, tests, log):
        baseline = log.name == 'baseline-checks.log'
        log.write_text('recovery_checks_started=true\nrecovery_case_finished=' + ('1' if baseline else '0') + '\n')
        log.chmod(0o600)
        return 1 if baseline else 0

    def test_rejected_review_cannot_install_or_release_retry(self):
        answers = [self.proposal(), dict(verdict='changes_requested', findings=['Causal proof is insufficient.'])]
        with patch.object(R, 'protected', return_value=self.binding), \
                patch.object(R, 'call_model', side_effect=answers), \
                patch.object(R, 'sandbox', side_effect=self.simulated_checks):
            with self.assertRaisesRegex(ValueError, 'independent-repair-review-rejected'):
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.base)
        self.assertEqual(self.retry_path.read_bytes(), self.retry_bytes)
        self.assertEqual(R.status(self.state)['phase'], 'failed')

    def test_existing_regressions_run_and_baseline_log_reaches_reviewer(self):
        old = self.ops / 'test/recovery-regression-previous.py'
        old.write_text('raise AssertionError("synthetic prior regression")\n')
        self.commit('test: preserve prior regression')
        self.base = self.git('rev-parse', 'HEAD')
        self.git('push', '-q', 'origin', 'main')
        seen = []
        def model(folder, name, prompt, *args):
            if name == 'diagnosis':
                return self.proposal()
            self.assertIn('ACTUAL BASELINE REGRESSION FAILURE:', prompt)
            self.assertIn('recovery_case_finished=1', prompt)
            return dict(verdict='changes_requested', findings=['Synthetic review rejection.'])
        def checks(worktree, tests, log):
            seen.append(tests)
            return self.simulated_checks(worktree, tests, log)
        with patch.object(R, 'protected', return_value=self.binding), \
                patch.object(R, 'call_model', side_effect=model), patch.object(R, 'sandbox', side_effect=checks):
            with self.assertRaisesRegex(ValueError, 'independent-repair-review-rejected'):
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
        self.assertIn(old.name, seen[-1])
        self.assertIn(Path(REGRESSION).name, seen[-1])

    @unittest.skipUnless(os.environ.get('JOAO_RECOVERY_E2E') == '1' and
                         os.environ.get('JOAO_RECOVERY_SANDBOX') != '1',
                         'Requires explicit real sandbox opt-in outside nested checks')
    def test_real_sandbox_synthetic_repair_end_to_end(self):
        shutil.copytree(HERE.parent, self.ops, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        original = (self.ops / 'campaign.sh').read_text()
        (self.ops / 'campaign.sh').write_text(original + BROKEN)
        self.commit('test: full automation with synthetic conversion defect')
        self.base = self.git('rev-parse', 'HEAD')
        self.git('push', '-q', 'origin', 'main')
        calls = []
        def model(folder, name, prompt, *args):
            calls.append(name)
            if name == 'diagnosis':
                return self.proposal()
            baseline = (folder / 'baseline-checks.log').read_text()
            repaired = (folder / 'repair-checks.log').read_text()
            self.assertIn('recovery_case_finished=1', baseline)
            self.assertIn('recovery_case_finished=0', repaired)
            self.assertNotIn('recovery_case_finished=1', repaired)
            return dict(verdict='pass', findings=[])
        with patch.object(R, 'protected', return_value=self.binding), patch.object(R, 'call_model', side_effect=model):
            try:
                R.supervise(self.state, self.repo, 'fixture', 'fixture')
            except Exception as error:
                logs = '\n'.join(path.name + ':\n' + path.read_text()[-16000:]
                                 for path in self.state.glob('diagnostics/recovery/*/*/*-checks.log'))
                self.fail(f'Isolated synthetic recovery failed: {error}\n{logs}')
        self.assertEqual(calls, ['diagnosis', 'review'])
        self.assertEqual(R.status(self.state)['phase'], 'recovered')
        self.assertFalse(self.retry_path.exists())
        self.assertEqual(self.git('status', '--porcelain'), '')
        target = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.command('git', '--git-dir=' + str(self.remote), 'rev-parse', 'main'), target)
        self.assertNotEqual(target, self.base)
        self.assertEqual(self.git('rev-list', '--count', self.base + '..HEAD'), '1')
        R.unchanged(self.binding)


if __name__ == '__main__':
    unittest.main()
