#!/usr/bin/env python3
"""Offline tests for the authorization bridge, using isolated private state."""
import copy
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'campaign-control.py'
SPEC = importlib.util.spec_from_file_location('campaign', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.worktree = self.state / 'worktrees/joao-batch-20261023T000000Z-19-19'
        self.worktree.mkdir(parents=True)
        subprocess.run(['git', 'init', '-q', '-b', 'joao/batch-20261023T000000Z-19-19', str(self.worktree)], check=True)
        subprocess.run(['git', '-C', str(self.worktree), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'test: baseline'], check=True)
        self.stage = dict(schema=1, issue=19, worktree=str(self.worktree), branch='joao/batch-20261023T000000Z-19-19',
                          phase='waiting_owner', reason='campaign_authorization', reviews=3, snapshot='a'*64)
        MODULE.save(self.state / 'stage.json', self.stage)
        self.session = '11111111-1111-4111-8111-111111111111'
        (self.state / 'session').write_text(self.session + '\n')
        (self.state / 'current_issue').write_text('19\n')
        self.auth = dict(schemaVersion=1, issue=19, authorizationId='issue19-native-windows-20261023',
                         client='cli-windows-native', additionalStarts=10, maxSecondsPerRun=600,
                         preserveAllPreviousAttempts=True, preserveIdeWindowsReservations=2,
                         sequentialOnly=True, consumeBeforeStart=True, countFailedStarts=True,
                         allowOpenAiApiKey=False, allowNewVm=False, allowBaselineReset=False,
                         stopOnCompletedCycle=True, requireCorrectionBeforeRetry=True,
                         previousAuthorizationSha256='b'*64, previousConsumptionSha256='c'*64)
        self.auth_path = self.root / 'authorization.json'
        MODULE.save(self.auth_path, self.auth)
        self.attempts = self.root / 'attempts'
        self.attempts.mkdir()
        self.attempt(1)
        self.candidate = self.root / 'candidate.json'
        MODULE.save(self.candidate, dict(version='v0.84.0', sha='d'*40, origin='https://linux-ai2.taile60a95.ts.net:8443'))

    def tearDown(self):
        self.directory.cleanup()

    def attempt(self, number):
        path = self.attempts / f'attempt-{number}'
        path.mkdir()
        MODULE.save(path / 'receipt.json', dict(authorizationId=self.auth['authorizationId'], client='cli-windows-native',
                   attempt=number, consumed=True, maxAuthorizedStarts=10, maxSeconds=600, outcome='failed'))

    def activate(self):
        MODULE.activate(self.state, self.auth_path, self.attempts, self.candidate)
        return MODULE.private(self.state / 'campaign.json')

    def command(self, action, expected=0):
        result = subprocess.run(['python3', '-B', str(SCRIPT), action, str(self.state)], capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result.stdout

    def test_activation_preserves_preparation_session_and_history(self):
        paths = [self.state / 'stage.json', self.state / 'session', self.attempts / 'attempt-1' / 'receipt.json']
        before = [path.read_bytes() for path in paths]
        value = self.activate()
        self.assertEqual(value['consumedAtActivation'], 1)
        self.assertIs(value['allowsFinalDelivery'], False)
        self.assertEqual(before, [path.read_bytes() for path in paths])
        self.assertIn('campaign_remaining=9', self.command('status'))

    def test_authorization_cannot_change_platform_quota_or_safety(self):
        for key, value in [('client', 'cli-linux'), ('additionalStarts', 11), ('maxSecondsPerRun', 601),
                           ('preserveIdeWindowsReservations', 1), ('allowOpenAiApiKey', True),
                           ('allowNewVm', True), ('allowBaselineReset', True), ('consumeBeforeStart', False),
                           ('requireCorrectionBeforeRetry', False), ('additionalStarts', True)]:
            with self.subTest(key=key, value=value):
                item = copy.deepcopy(self.auth)
                item[key] = value
                with self.assertRaises(ValueError):
                    MODULE.authorization(item)

    def test_new_attempt_decreases_balance_without_new_authorization(self):
        self.activate()
        self.attempt(2)
        self.assertIn('campaign_remaining=8', self.command('status'))

    def test_original_receipt_change_rejects_resume(self):
        self.activate()
        path = self.attempts / 'attempt-1' / 'receipt.json'
        value = MODULE.private(path)
        value['outcome'] = 'passed'
        MODULE.save(path, value)
        self.command('status', 65)

    def test_history_gap_is_not_free_quota(self):
        self.attempt(3)
        with self.assertRaises(ValueError):
            self.activate()

    def test_incomplete_reserved_directory_fails_closed(self):
        (self.attempts / 'attempt-2').mkdir()
        with self.assertRaises(OSError):
            self.activate()

    def test_exhausted_budget_cannot_activate(self):
        for number in range(2, 11):
            self.attempt(number)
        with self.assertRaises(ValueError):
            self.activate()

    def test_other_owner_wait_is_not_released(self):
        self.stage['reason'] = 'external_requirement'
        MODULE.save(self.state / 'stage.json', self.stage)
        with self.assertRaises(ValueError):
            self.activate()

    def test_changed_session_or_preparation_rejects_resume(self):
        self.activate()
        (self.state / 'session').write_text('new-session\n')
        self.command('phase', 65)
        (self.state / 'session').write_text(self.session + '\n')
        self.stage['reviews'] = 0
        MODULE.save(self.state / 'stage.json', self.stage)
        self.command('phase', 65)

    def test_authorization_file_must_remain_private(self):
        self.activate()
        os.chmod(self.auth_path, 0o644)
        self.command('phase', 65)

    def test_reactivation_never_resets_passes_or_history(self):
        self.activate()
        with self.assertRaises(ValueError):
            self.activate()

    def test_executor_continuations_do_not_erase_review_count_or_consume_test_budget(self):
        self.activate()
        for number in range(1, 5):
            self.command('begin')
            self.assertIn(f'"executorPass": {number}', self.command('prompt'))
        self.assertEqual(self.command('phase').strip(), 'active')
        self.assertIn('campaign_remaining=9', self.command('status'))
        self.assertEqual(MODULE.private(self.state / 'stage.json')['reviews'], 3)

    def test_result_is_bound_and_cannot_deliver_issue(self):
        self.activate()
        self.command('begin')
        result = dict(schema=1, issue=19, executorPass=1, authorizationId=self.auth['authorizationId'],
                      phase='done', summary='Not an acceptance proof.')
        MODULE.save(self.state / 'campaign-result.json', result)
        self.command('finish', 65)
        result['phase'] = 'review_pending'
        result['executorPass'] = 0
        MODULE.save(self.state / 'campaign-result.json', result)
        self.command('finish', 65)
        result['executorPass'] = 1
        MODULE.save(self.state / 'campaign-result.json', result)
        self.assertEqual(self.command('finish').strip(), 'review_pending')
        self.assertIs(MODULE.private(self.state / 'campaign.json')['allowsFinalDelivery'], False)

    def test_existing_wrapper_routes_authorized_resume_before_old_stage(self):
        self.activate()
        wrapper = r'''
set -euo pipefail
SCRIPT_DIR=$1
STATE_ROOT=$2
REPOSITORY_SLUG=fixture/lab
GH_BIN=mock_gh
printf blocked > "$STATE_ROOT/mock-label"
mock_gh() { printf doing > "$STATE_ROOT/mock-label"; }
issue_operational_state() { cat "$STATE_ROOT/mock-label"; }
log() { printf '%s\n' "$*"; }
clear_issue_retry() { :; }
record_issue_failure() { printf failure > "$STATE_ROOT/mock-failure"; }
run_codex() {
  stage_prompt 19 > "$STATE_ROOT/mock-prompt"
  python3 - "$STATE_ROOT" <<'END'
import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]);v=json.loads((p/'campaign.json').read_text())
r=dict(schema=1, issue=19, executorPass=v['executorPasses'], authorizationId='issue19-native-windows-20261023', phase='review_pending', summary='Offline fixture completed.')
(p/'campaign-result.json').write_text(json.dumps(r));os.chmod(p/'campaign-result.json',0o600)
END
}
source "$SCRIPT_DIR/stages.sh"
execute_staged_item 19 "$3" joao/batch-20261023T000000Z-19-19
execute_staged_item 19 "$3" joao/batch-20261023T000000Z-19-19
'''
        before = (self.state / 'stage.json').read_bytes()
        result = subprocess.run(['bash', '-c', wrapper, 'fixture', str(SCRIPT.parent), str(self.state), str(self.worktree)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.state / 'mock-label').read_text(), 'doing')
        self.assertEqual(MODULE.private(self.state / 'campaign.json')['executorPasses'], 1)
        self.assertEqual((self.state / 'stage.json').read_bytes(), before)
        prompt = (self.state / 'mock-prompt').read_text()
        self.assertIn('Current #19 continuation', prompt)
        self.assertNotIn('CURRENT OPT-IN STAGE: preparation', prompt)
        self.assertFalse((self.state / 'mock-failure').exists())

    def test_status_reports_native_campaign_instead_of_stale_owner_wait(self):
        self.activate()
        environment = dict(os.environ, JOAO_STATE_ROOT=str(self.state))
        result = subprocess.run(['bash', str(SCRIPT.with_name('control.sh')), 'status'], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('stage=authorized_campaign', result.stdout)
        self.assertIn('campaign_remaining=9', result.stdout)
        self.assertNotIn('campaign_authorization', result.stdout)
        self.assertNotIn('preserved-session', result.stdout)

    def test_real_cycle_resumes_existing_session_and_cannot_integrate(self):
        self.activate()
        branch = self.stage['branch']
        head = subprocess.check_output(['git', '-C', str(self.worktree), 'rev-parse', 'HEAD']).decode().strip()
        for name, value in dict(batch='19', branch=branch, worktree=str(self.worktree), base_sha=head,
                                issue_base_sha=head, next='1', phase='issues').items():
            (self.state / name).write_text(value + '\n')
        (self.state / 'tmp').mkdir()
        (self.state / 'uncommitted-evidence').write_text('Preserve outside worktree.\n')
        (self.worktree / 'unfinished-proof.txt').write_text('Preserve source diff.\n')
        executable = self.root / 'fake-codex.py'
        executable.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
p=Path(os.environ['JOAO_STATE_ROOT'])
(p/'fake-model-args.json').write_text(json.dumps(sys.argv[1:]))
(p/'fake-model-prompt.txt').write_text(sys.stdin.read())
v=json.loads((p/'campaign.json').read_text())
r=dict(schema=1,issue=19,executorPass=v['executorPasses'],authorizationId='issue19-native-windows-20261023',phase='review_pending',summary='Offline fake transport, not AI proof.')
(p/'campaign-result.json').write_text(json.dumps(r));os.chmod(p/'campaign-result.json',0o600)
print(json.dumps(dict(type='item.completed',item=dict(type='agent_message',text='Offline fixture completed.'))))
''')
        executable.chmod(0o700)
        wrapper = r'''
set -euo pipefail
export JOAO_STATE_ROOT=$2
export JOAO_REPOSITORY_PATH=$3
source "$1/run.sh"
CODEX_BIN=$4
preflight() { :; }
issue_operational_state() { printf doing; }
list_open_with_label() { [[ $1 != doing ]] || printf '19\n'; }
integrate_batch() { printf forbidden > "$STATE_ROOT/forbidden-integration"; return 1; }
finalize_batch() { printf forbidden > "$STATE_ROOT/forbidden-finalization"; return 1; }
run_cycle
run_cycle
'''
        before = (self.state / 'stage.json').read_bytes()
        result = subprocess.run(['bash', '-c', wrapper, 'fixture', str(SCRIPT.parent), str(self.state),
                                  str(self.worktree), str(executable)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        args = json.loads((self.state / 'fake-model-args.json').read_text())
        self.assertIn('resume', args)
        self.assertIn(self.session, args)
        self.assertEqual((self.state / 'stage.json').read_bytes(), before)
        self.assertEqual((self.state / 'session').read_text().strip(), self.session)
        self.assertEqual((self.state / 'phase').read_text().strip(), 'issues')
        self.assertEqual((self.state / 'next').read_text().strip(), '1')
        self.assertEqual(MODULE.private(self.state / 'campaign.json')['executorPasses'], 1)
        self.assertEqual((self.worktree / 'unfinished-proof.txt').read_text(), 'Preserve source diff.\n')
        self.assertFalse((self.state / 'forbidden-integration').exists())
        self.assertFalse((self.state / 'forbidden-finalization').exists())

    def test_rollout_keeps_release_gate_and_sets_doing_before_service_start(self):
        rollout = SCRIPT.with_name('CAMPAIGN-ROLLOUT.md').read_text()
        self.assertIn('release gate', rollout)
        self.assertIn('--remove-label blocked --add-label doing', rollout)
        self.assertLess(rollout.index('activate-campaign.sh AUTHORIZATION_JSON'),
                        rollout.index('--remove-label blocked --add-label doing'))
        self.assertLess(rollout.index('--remove-label blocked --add-label doing'),
                        rollout.index('systemctl --user start'))

    def result(self, number, phase='active'):
        MODULE.save(self.state / 'campaign-result.json', dict(schema=1, issue=19, executorPass=number,
                    authorizationId=self.auth['authorizationId'], phase=phase, summary='Offline continuation.'))

    def test_candidate_and_counter_validation_on_every_use(self):
        original = self.activate()
        for field, invalid in [('executorPasses', -1), ('executorPasses', True), ('executorPasses', '1'),
                               ('candidate', {'version': 'v0.84.0', 'sha': 'd'*40, 'origin': 'https://other.invalid'}),
                               ('candidate', {'version': 'v0.85.0', 'sha': 'd'*40, 'origin': self.stage.get('origin', 'https://linux-ai2.taile60a95.ts.net:8443')}),
                               ('allowsFinalDelivery', True)]:
            with self.subTest(field=field, invalid=invalid):
                changed = copy.deepcopy(original)
                changed[field] = invalid
                MODULE.save(self.state / 'campaign.json', changed)
                for action in ['phase', 'status', 'prompt', 'begin']:
                    self.command(action, 65)

    def test_three_passes_without_source_or_attempt_progress_stop(self):
        self.activate()
        for number in range(1, 4):
            self.command('begin')
            self.result(number)
            expected = 'review_pending' if number == 3 else 'active'
            self.assertEqual(self.command('finish').strip(), expected)
        self.assertIn('campaign_no_progress_passes=3', self.command('status'))
        self.command('begin', 65)
        self.assertEqual(MODULE.private(self.state / 'stage.json')['reviews'], 3)
        self.assertIn('campaign_remaining=9', self.command('status'))

    def test_new_source_or_attempt_resets_only_no_progress_counter(self):
        self.activate()
        self.command('begin')
        self.result(1)
        self.command('finish')
        self.command('begin')
        (self.worktree / 'new-proof.txt').write_text('new independent technical evidence\n')
        self.result(2)
        self.command('finish')
        self.assertIn('campaign_no_progress_passes=0', self.command('status'))
        self.command('begin')
        self.result(3)
        self.command('finish')
        self.command('begin')
        self.attempt(2)
        self.result(4)
        self.command('finish')
        self.assertIn('campaign_no_progress_passes=0', self.command('status'))
        self.assertIn('campaign_remaining=8', self.command('status'))

    def test_repeated_finish_does_not_create_another_pass(self):
        self.activate()
        self.command('begin')
        self.result(1)
        self.command('finish')
        self.command('finish', 65)

    def test_new_finished_attempt_cannot_be_removed_to_restore_budget(self):
        self.activate()
        self.command('begin')
        self.attempt(2)
        self.result(1)
        self.command('finish')
        self.assertIn('campaign_remaining=8', self.command('status'))
        shutil.rmtree(self.attempts / 'attempt-2')
        for action in ['status', 'phase', 'begin']:
            self.command(action, 65)

    def test_new_finished_attempt_cannot_be_rewritten(self):
        self.activate()
        self.command('begin')
        self.attempt(2)
        self.result(1)
        self.command('finish')
        path = self.attempts / 'attempt-2' / 'receipt.json'
        value = MODULE.private(path)
        value['outcome'] = 'passed'
        MODULE.save(path, value)
        self.command('status', 65)

    def test_invalid_campaign_uses_existing_bounded_retry_without_model(self):
        self.activate()
        head = subprocess.check_output(['git', '-C', str(self.worktree), 'rev-parse', 'HEAD']).decode().strip()
        (self.state / 'base_sha').write_text(head + '\n')
        self.auth['additionalStarts'] = 11
        MODULE.save(self.auth_path, self.auth)
        wrapper = r'''
set -euo pipefail
export JOAO_STATE_ROOT=$2
export JOAO_REPOSITORY_PATH=$3
source "$1/run.sh"
GH_BIN=mock_gh
mock_gh() { [[ $1 != issue ]] || printf notification >> "$STATE_ROOT/mock-notification"; }
run_codex() { printf forbidden > "$STATE_ROOT/forbidden-model"; return 1; }
for attempt in 1 2 3; do
  result=0
  execute_staged_item 19 "$3" joao/batch-20261023T000000Z-19-19 || result=$?
  [[ $result == 70 ]]
done
result=0
check_issue_retry_gate 19 joao/batch-20261023T000000Z-19-19 || result=$?
[[ $result == 75 ]]
'''
        result = subprocess.run(['bash', '-c', wrapper, 'fixture', str(SCRIPT.parent), str(self.state), str(self.worktree)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        retry = (self.state / 'issue-retry').read_text()
        self.assertIn('attempts=3', retry)
        self.assertIn('suspended=true', retry)
        self.assertFalse((self.state / 'forbidden-model').exists())
        self.assertTrue((self.state / 'mock-notification').exists())

    def test_activation_and_status_do_not_dirty_installed_source_with_bytecode(self):
        clean = self.root / 'clean-installed-ops'
        clean.mkdir()
        for name in ['campaign-control.py', 'stage-control.py', 'campaign-contract.md']:
            shutil.copyfile(SCRIPT.with_name(name), clean / name)
        result = subprocess.run(['python3', str(clean / 'campaign-control.py'), 'activate', str(self.state),
                                 str(self.auth_path), str(self.attempts), str(self.candidate)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['python3', str(clean / 'campaign-control.py'), 'status', str(self.state)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(path.name for path in clean.iterdir()),
                         ['campaign-contract.md', 'campaign-control.py', 'stage-control.py'])


if __name__ == '__main__':
    unittest.main()
