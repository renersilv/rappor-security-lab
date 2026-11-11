#!/usr/bin/env python3
"""Real protected review/controller transitions; no live service or model calls."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock

import importlib.util

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('review_tests', HERE / 'campaign-review-tests.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
R, C = BASE.R, BASE.C


class TechnicalTests(BASE.ReviewTests):
    def stopped(self):
        for number in range(1, 7):
            self.changed_preparation_pass(number)
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.ledger = self.state / 'synthetic-inference-ledger.json'
        C.save(self.ledger, dict(attempts=[dict(sequence=22, outcome='failed')], active=False))
        self.protected = {p: p.read_bytes() for p in [self.auth_path, self.ledger, self.state / 'session',
                                                     self.attempts / 'attempt-1/receipt.json']}
        self.before = C.private(self.state / 'campaign.json')
        self.old_directory = R.job(self.state)[0]
        self.old_result = (self.old_directory / 'result.json').read_bytes()
        self.old_marker = C.private(self.state / 'campaign-auto-review.json')

    def resume(self):
        with contextlib.redirect_stdout(io.StringIO()):
            R.resume_correction(self.state)

    def next_packet(self, number, *, changed=True):
        value = C.private(self.state / 'campaign.json')
        value.update(phase='review_pending', executorPasses=number, lastFinishedPass=number)
        C.save(self.state / 'campaign.json', value)
        prior = self.source.read_bytes()
        self.candidate_dir = self.attempts / 'candidates' / f'correction{number}'
        self.candidate_dir.mkdir()
        self.source = self.candidate_dir / 'worker.ps1'
        R.put(self.source, f'function Invoke-Worker {{ return {number} }}\n'.encode() if changed else prior)
        for name, outcome in [('regression-before.json', 'reproduced'), ('regression-after.json', 'passed')]:
            C.save(self.candidate_dir / name, dict(fixtureOnly=True, test='bounded-worker', outcome=outcome))
        self.manifest = self.candidate_dir / f'manifest-pass{number}.json'
        C.save(self.manifest, dict(issue=19, executorPass=number, candidate=value['candidate'],
               authorizationId=self.auth['authorizationId'], newLiveActivity=False,
               files={p.name: C.digest(p) for p in self.candidate_dir.iterdir()}))

    def repair_response(self, *, accepted=True, proof=True, **changes):
        route = R.technical_history(C.private(self.state / 'campaign.json'))[0]
        fields = dict(technicalCorrection=None, objectiveId='ide-mcp', evidenceLevel='preparation',
                      progress='behavior_change')
        if accepted:
            fields.update(verdict='pass', findings=[], scope='read_only_preflight',
                          evidence=['worker.ps1', 'regression-before.json', 'regression-after.json'])
            if proof:
                fields['technicalCorrection'] = dict(incident=route['incident'],
                    regressionBefore='regression-before.json', regressionAfter='regression-after.json')
        fields.update(changes)
        return self.response(**fields)

    def assert_preserved(self):
        for path, original in self.protected.items():
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual((self.old_directory / 'result.json').read_bytes(), self.old_result)
        now = C.private(self.state / 'campaign.json')
        for key in set(self.before) - {'phase', 'reviewCheckpoint', 'executorPasses', 'lastFinishedPass'}:
            self.assertEqual(now[key], self.before[key], key)
        self.assertFalse(now['allowsFinalDelivery'])

    def test_saved_rejection_routes_offline_without_reset_and_restart_is_idempotent(self):
        self.stopped()
        self.resume()
        marker = R.job(self.state)[1]
        self.assertEqual(marker['unchangedReviews'], 6)
        self.assertEqual(marker['technicalRoute']['attempt'], 1)
        self.assertIn('Scope: offline', C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))[1])
        snapshot = (self.state / 'campaign.json').read_bytes()
        self.resume()
        R.reconcile(self.state)
        self.assertEqual((self.state / 'campaign.json').read_bytes(), snapshot)
        self.assertEqual(C.private(self.old_directory / 'stalled-marker-before-technical.json'), self.old_marker)
        self.assert_preserved()

    def test_reviewed_regression_permits_one_read_only_observation_without_reset(self):
        self.stopped()
        self.resume()
        self.next_packet(7)
        self.repair_response()
        self.finish()
        R.reconcile(self.state)
        marker = R.job(self.state)[1]
        self.assertEqual(marker['phase'], 'continued')
        self.assertEqual(marker['unchangedReviews'], 7)
        self.assertEqual(marker['technicalRoute']['phase'], 'observation')
        self.assert_preserved()
        self.next_packet(8)
        self.response(verdict='pass', findings=[], scope='read_only_preflight', technicalCorrection=None,
                      objectiveId='ide-mcp', evidenceLevel='preparation')
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')

    def test_rewording_and_source_changes_do_not_renew_same_incident(self):
        self.stopped()
        self.resume()
        identity = R.job(self.state)[1]['technicalRoute']['incident']
        first_key = R.incident_key(self.state)
        for number in [7, 8]:
            self.next_packet(number)
            self.repair_response(accepted=False, findings=[f'Rephrased unresolved defect {number}.'])
            self.finish()
            self.assertEqual(R.incident_key(self.state), first_key)
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.resume()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assertEqual(R.technical_history(C.private(self.state / 'campaign.json'))[0]['incident'], identity)
        self.assert_preserved()

    def test_distinct_defect_after_reviewed_resolution_has_separate_identity(self):
        self.stopped()
        self.resume()
        first = R.incident_key(self.state)
        self.next_packet(7)
        self.repair_response()
        self.finish()
        self.next_packet(8)
        self.response(technicalCorrection=None, findings=['A different concrete descriptor decoding defect.'],
                      objectiveId='ide-mcp', evidenceLevel='preparation')
        self.finish()
        self.assertNotEqual(R.incident_key(self.state), first)
        self.assertEqual(R.job(self.state)[1]['technicalRoute']['attempt'], 1)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 8)

    def test_real_operational_gate_separates_incidents_and_bounds_equivalent_failures(self):
        self.stopped()
        self.resume()
        first = R.incident_key(self.state)
        self.next_packet(7)
        self.repair_response()
        self.finish()
        self.next_packet(8)
        self.response(technicalCorrection=None, findings=['A different reviewed parser boundary defect.'],
                      objectiveId='ide-mcp', evidenceLevel='preparation')
        self.finish()
        second = R.incident_key(self.state)
        (self.state / 'base_sha').write_text('a' * 40 + '\n')
        shell = r'''
set -euo pipefail
export JOAO_SOURCE_ONLY=1 JOAO_STATE_ROOT=$2
source "$1/run.sh"
campaign_enabled() { return 1; }
notify_issue_retry_attention() { :; }
record_issue_failure 19 "$3" codex_exit "$4"
record_issue_failure 19 "$3" codex_exit "$4"
record_issue_failure 19 "$3" codex_exit "$4"
[[ $ISSUE_RETRY_ATTEMPTS == 3 && $ISSUE_RETRY_SUSPENDED == true ]]
record_issue_failure 19 "$3" codex_exit "$5"
[[ $ISSUE_RETRY_ATTEMPTS == 1 && $ISSUE_RETRY_SUSPENDED == false ]]
'''
        tested = subprocess.run(['bash', '-c', shell, 'fixture', str(HERE.parent), str(self.state),
            self.stage['branch'], first, second], capture_output=True, text=True, timeout=20)
        self.assertEqual(tested.returncode, 0, tested.stderr)
        self.assert_preserved()

    def test_missing_regression_and_unchanged_source_fail_closed(self):
        self.stopped()
        self.resume()
        self.next_packet(7, changed=False)
        self.repair_response()
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.resume()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assert_preserved()

    def test_pass_without_bound_regression_cannot_release_runtime(self):
        self.stopped()
        self.resume()
        self.next_packet(7)
        self.repair_response(proof=False)
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')

    def test_bounded_runtime_expansion_is_not_authorized_by_technical_repair(self):
        self.stopped()
        self.resume()
        self.next_packet(7)
        self.repair_response(scope='bounded_no_model', cleanupAssessment='verified')
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assert_preserved()

    def test_renamed_identical_regression_artifacts_cannot_claim_before_after(self):
        self.stopped()
        self.resume()
        self.next_packet(7)
        after = self.candidate_dir / 'regression-after.json'
        after.write_bytes((self.candidate_dir / 'regression-before.json').read_bytes())
        manifest = C.private(self.manifest)
        manifest['files'][after.name] = C.digest(after)
        C.save(self.manifest, manifest)
        self.repair_response()
        with self.assertRaisesRegex(ValueError, 'invalid-technical-correction-proof'):
            self.finish()
        self.assert_preserved()

    def test_confirmed_owner_action_remains_owner_required(self):
        self.stopped()
        self.resume()
        self.next_packet(7)
        self.response(verdict='owner_required', ownerRequest=dict(action='interactive_login', location='windows_ide'),
                      technicalCorrection=None, objectiveId='ide-mcp', evidenceLevel='preparation')
        self.finish()
        self.resume()
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'owner_required')
        self.assertEqual(R.job(self.state)[1]['phase'], 'owner_required')
        self.assert_preserved()

    def test_interrupted_launch_exhausts_single_technical_checkpoint(self):
        self.stopped()
        self.resume()
        value = C.private(self.state / 'campaign.json')
        value['executorPasses'] += 1
        C.enforce_review_limit(value, 1)
        self.assertEqual(value['phase'], 'review_pending')
        self.assertEqual(value['lastFinishedPass'], 6)
        self.assertEqual(value['reviewReason'], 'continuation_review_required')
        self.assert_preserved()

    def test_crash_after_campaign_save_recovers_same_checkpoint(self):
        self.stopped()
        original_save = C.save
        def interrupt(path, value):
            if path == self.state / 'campaign-auto-review.json' and value.get('phase') == 'continued':
                raise OSError('simulated-crash')
            original_save(path, value)
        with mock.patch.object(C, 'save', side_effect=interrupt), self.assertRaises(OSError):
            self.resume()
        checkpoint = C.private(self.state / 'campaign.json')['reviewCheckpoint']
        self.resume()
        self.assertEqual(C.private(self.state / 'campaign.json')['reviewCheckpoint'], checkpoint)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 6)
        self.assert_preserved()

    def test_matching_retry_is_archived_and_unrelated_retry_is_rejected(self):
        self.stopped()
        branch = self.before['branch']
        (self.state / 'branch').write_text(branch + '\n')
        (self.state / 'base_sha').write_text('a' * 40 + '\n')
        retry = self.state / 'issue-retry'
        fingerprint = R.sha(f'v1:{"a" * 40}:{branch}:19:codex_exit:campaign_70'.encode())
        raw = f'issue=19\nbranch={branch}\nerror_class=codex_exit\nfingerprint={fingerprint}\n'
        retry.write_text(raw.replace(fingerprint, '0' * 64))
        retry.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'unrelated-operational'):
            self.resume()
        retry.write_text(raw)
        self.resume()
        self.assertFalse(retry.exists())
        self.assertEqual(C.private(self.old_directory / 'technical-retry-before.json')['content'], raw)
        self.assert_preserved()

    def test_real_wrapper_reject_correct_review_resume_sequence(self):
        self.stopped()
        scripts = self.root / 'installed-wrapper'
        shutil.copytree(HERE.parent, scripts)
        for filename in ['campaign-control.py', 'recovery.py']:
            path = scripts / filename
            path.write_text(path.read_text().replace(
                "Path.home() / '.config/rappor-security-lab/campaign-reviews'",
                f'Path({str(self.operator)!r})'))
        verdict = C.private(self.old_directory / 'result.json')
        incident = R.sha(R.encoded(dict(objective=verdict['objectiveId'],
            findings=sorted(' '.join(f.lower().split()) for f in verdict['findings']))))
        approved = dict(verdict='pass', findings=[], scope='read_only_preflight',
            nextAction='Observe the existing public descriptor once under the existing read-only deadline.',
            evidence=['worker.ps1', 'regression-before.json', 'regression-after.json'],
            cleanupAssessment='not_required', progress='behavior_change', ownerRequest=None,
            objectiveId='ide-mcp', evidenceLevel='preparation',
            technicalCorrection=dict(incident=incident, regressionBefore='regression-before.json',
                                     regressionAfter='regression-after.json'))
        reviewer = self.root / 'reviewer.py'
        reviewer.write_text('#!/usr/bin/env python3\nimport json,sys\n'
            'assert "read-only" in sys.argv and "--disable" in sys.argv\n'
            'assert "TECHNICAL CORRECTION ROUTE" in sys.stdin.read()\n'
            'print(' + repr(json.dumps(dict(type='item.completed', item=dict(type='agent_message',
                text=json.dumps(approved))))) + ')\n')
        reviewer.chmod(0o700)
        executor = self.root / 'executor.py'
        executor.write_text('''import hashlib,json,os,sys
from pathlib import Path
r=Path(sys.argv[1]);v=json.loads((r/'campaign.json').read_text());n=v['executorPasses']
def save(p,x):
 p.write_text(json.dumps(x));p.chmod(0o600)
if n==7:
 folder=Path(v['attemptsRoot'])/'candidates'/'corrected7';folder.mkdir()
 save(folder/'regression-before.json',{'fixtureOnly':True,'result':'reproduced'})
 save(folder/'regression-after.json',{'fixtureOnly':True,'result':'passed'})
 p=folder/'worker.ps1';p.write_text('function Invoke-Worker { return 7 }');p.chmod(0o600)
 files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir()}
 save(folder/'manifest-pass7.json',dict(issue=19,executorPass=n,candidate=v['candidate'],authorizationId='issue19-native-windows-20261023',newLiveActivity=False,files=files))
 phase='review_pending'
else:
 assert n==8
 phase='active'
save(r/'campaign-result.json',dict(schema=1,issue=19,executorPass=n,authorizationId='issue19-native-windows-20261023',phase=phase,summary='Synthetic offline dispatcher boundary, no runtime evidence.'))
''')
        shell = r'''
set -euo pipefail
umask 077
SCRIPT_DIR=$1 STATE_ROOT=$2 CODEX_BIN=$3
TIMEOUT_BIN=timeout MODEL=fixture REASONING_EFFORT=xhigh
source "$SCRIPT_DIR/campaign.sh"
campaign_review_notice() { :; }
issue_operational_state() { printf doing; }
log() { :; }
FIXTURE_EXECUTOR=$6
run_codex() {
 campaign_command prompt >> "$STATE_ROOT/prompts"
 if [[ -f $STATE_ROOT/first-executor-finished ]]; then return 124; fi
 python3 "$FIXTURE_EXECUTOR" "$STATE_ROOT"
 touch "$STATE_ROOT/first-executor-finished"
}
execute_campaign_item 19 "$4" "$5"
result=0
execute_campaign_item 19 "$4" "$5" || result=$?
[[ $result == 124 ]]
'''
        executed = subprocess.run(['bash', '-c', shell, 'fixture', str(scripts), str(self.state),
            str(reviewer), str(self.worktree), self.stage['branch'], str(executor)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        prompts = (self.state / 'prompts').read_text()
        self.assertIn('Scope: offline', prompts)
        self.assertIn('Scope: read_only_preflight', prompts)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 8)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 7)
        self.assert_preserved()


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(TechnicalTests(name) for name in TechnicalTests.__dict__ if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main()
