#!/usr/bin/env python3
"""Independent review transitions against real files, hashes and Git bindings."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HERE = Path(__file__).resolve().parent
BASE = module('campaign_tests', HERE / 'campaign-tests.py')
R = module('campaign_review', HERE.parent / 'campaign-review.py')
C = BASE.MODULE
R.C = C


class ReviewTests(unittest.TestCase):
    def setUp(self):
        BASE.CampaignTests.setUp(self)
        self.state.chmod(0o700)
        self.old_review_root = C.REVIEW_ROOT
        C.REVIEW_ROOT = self.operator
        value = BASE.CampaignTests.activate(self)
        value.update(executorPasses=1, lastFinishedPass=1, phase='review_pending')
        C.save(self.state / 'campaign.json', value)
        C.save(self.state / 'campaign-result.json', dict(schema=1, issue=19, executorPass=1,
               authorizationId=self.auth['authorizationId'], phase='review_pending', summary='Prepared source.'))
        self.candidate_dir = self.attempts / 'candidates/pass1'
        self.candidate_dir.mkdir(parents=True)
        self.source = self.candidate_dir / 'worker.ps1'
        R.put(self.source, b'function Invoke-Worker { throw "not-ready" }\n')
        self.manifest = self.candidate_dir / 'manifest-pass1.json'
        C.save(self.manifest, dict(issue=19, executorPass=1, candidate=value['candidate'],
               authorizationId=self.auth['authorizationId'], files={'worker.ps1': C.digest(self.source)}))

    attempt = BASE.CampaignTests.attempt

    def tearDown(self):
        C.REVIEW_ROOT = self.old_review_root
        self.directory.cleanup()

    def prepare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare(self.state)
        return R.job(self.state)[0]

    def response(self, **changes):
        directory = self.prepare()
        verdict = dict(verdict='changes_requested', findings=['worker.ps1: replace the unconditional failure with the bounded offline check.'],
                       nextAction='Repair the worker implementation and add a focused negative test before any live action.',
                       scope='offline', evidence=['worker.ps1'], cleanupAssessment='not_required',
                       progress='none', ownerRequest=None)
        verdict.update(changes)
        C.save(directory / 'response.json', verdict)
        R.put(directory / 'events.jsonl', R.encoded(dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(verdict)))))
        return directory

    def finish(self):
        with contextlib.redirect_stdout(io.StringIO()):
            R.finish(self.state)

    def test_review_resumes_preserving_all_bindings_and_counters(self):
        before = C.private(self.state / 'campaign.json')
        preserved = [self.state / 'stage.json', self.state / 'session', self.auth_path, self.attempts / 'attempt-1/receipt.json']
        hashes = [C.digest(p) for p in preserved]
        directory = self.response()
        self.finish()
        after = C.private(self.state / 'campaign.json')
        for key in before.keys() - {'phase', 'reviewCheckpoint'}:
            self.assertEqual(before[key], after[key], key)
        self.assertEqual(after['phase'], 'active')
        self.assertEqual(hashes, [C.digest(p) for p in preserved])
        through, handoff = C.reviewed_checkpoint(after)
        self.assertEqual(through, 1)
        self.assertIn('Repair the worker implementation', handoff)
        self.assertEqual(C.private(directory / 'before.json'), before)
        self.assertIs(after['allowsFinalDelivery'], False)

    def test_completed_review_recovery_does_not_append_a_checkpoint(self):
        self.response()
        self.finish()
        exact = (self.state / 'campaign.json').read_bytes()
        self.finish()
        self.assertEqual(exact, (self.state / 'campaign.json').read_bytes())

    def test_interruption_after_intent_replays_only_identical_transition(self):
        self.response()
        before = (self.state / 'campaign.json').read_bytes()
        self.finish()
        after = (self.state / 'campaign.json').read_bytes()
        (self.state / 'campaign.json').write_bytes(before)
        self.finish()
        self.assertEqual(after, (self.state / 'campaign.json').read_bytes())

    def test_altered_source_is_rejected_without_resuming(self):
        self.response()
        self.source.write_text('changed after review snapshot')
        with self.assertRaises(ValueError):
            self.finish()
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')

    def test_c_source_is_reviewed_as_text_and_changes_code_fingerprint(self):
        state = C.private(self.state / 'campaign.json')
        before = R.packet(state, self.state)['sourceFingerprint']
        source = self.candidate_dir / 'disposable-check.c'
        R.put(source, b'int main(void) { return 0; }\n')
        manifest = C.private(self.manifest)
        manifest['files'][source.name] = C.digest(source)
        C.save(self.manifest, manifest)
        packet = R.packet(state, self.state)
        self.assertEqual(packet['sources'][source.name]['content'], source.read_text())
        self.assertNotEqual(packet['sourceFingerprint'], before)
        self.response(evidence=[source.name])
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'continued')

    def test_c_evidence_preserves_binary_hash_and_permission_rejection(self):
        state = C.private(self.state / 'campaign.json')
        source = self.candidate_dir / 'disposable-check.c'
        manifest = C.private(self.manifest)
        for content, mode, changed in [(b'\x7fELF\x00binary', 0o600, False),
                                       (b'int main(void) { return 0; }\n', 0o644, False),
                                       (b'int main(void) { return 0; }\n', 0o600, True)]:
            source.write_bytes(content)
            source.chmod(mode)
            manifest['files'][source.name] = '0' * 64 if changed else C.digest(source)
            C.save(self.manifest, manifest)
            with self.subTest(mode=mode, changed=changed, binary=b'\x00' in content):
                with self.assertRaisesRegex(ValueError, 'binary-review-evidence|invalid-candidate-source|candidate-hash-changed'):
                    R.packet(state, self.state)

    def test_changed_source_and_updated_manifest_are_also_rejected(self):
        self.response()
        self.source.write_text('new source')
        manifest = C.private(self.manifest)
        manifest['files']['worker.ps1'] = C.digest(self.source)
        C.save(self.manifest, manifest)
        with self.assertRaises(ValueError):
            self.finish()

    def test_changed_campaign_or_prompt_cannot_use_old_review(self):
        directory = self.response()
        (directory / 'prompt.md').write_text('fake instructions')
        with self.assertRaises(ValueError):
            self.finish()

    def test_source_symlink_or_nonprivate_file_is_rejected(self):
        contents = self.source.read_bytes()
        self.source.unlink()
        target = self.root / 'elsewhere.ps1'
        R.put(target, contents)
        self.source.symlink_to(target)
        with self.assertRaises(ValueError):
            self.prepare()
        self.source.unlink()
        R.put(self.source, contents)
        self.source.chmod(0o644)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_claimed_live_scope_cannot_override_correction_or_unknown_cleanup(self):
        self.response(scope='bounded_no_model')
        with self.assertRaises(ValueError):
            self.finish()

    def test_owner_action_does_not_create_a_continuation_checkpoint(self):
        self.response(verdict='owner_required', ownerRequest=dict(action='interactive_login', location='windows_ide'),
                      nextAction='Complete the unavailable interactive login in the existing client; no independent work remains.')
        self.finish()
        after = C.private(self.state / 'campaign.json')
        self.assertEqual(after['phase'], 'owner_required')
        self.assertIsNone(after['reviewCheckpoint'])

    def test_tool_use_and_unbound_citations_are_rejected(self):
        directory = self.response(evidence=['not-supplied.ps1'])
        with self.assertRaises(ValueError):
            self.finish()
        events = directory / 'events.jsonl'
        events.write_text(json.dumps(dict(type='item.completed', item=dict(type='command_execution'))) + '\n')
        with self.assertRaises(ValueError):
            self.finish()

    def test_exact_bound_manifest_filename_resumes_cached_review(self):
        directory = self.response(evidence=['worker.ps1', self.manifest.name])
        events = (directory / 'events.jsonl').read_bytes()
        self.finish()
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'active')
        self.assertEqual(C.private(directory / 'result.json')['evidence'], ['worker.ps1', 'manifest'])
        self.assertEqual(events, (directory / 'events.jsonl').read_bytes())

    def test_pass_with_findings_is_rejected_without_modifying_evidence_or_state(self):
        directory = self.response(verdict='pass', findings=['The correction is complete.'])
        before = (self.state / 'campaign.json').read_bytes()
        events = (directory / 'events.jsonl').read_bytes()
        with self.assertRaisesRegex(ValueError, 'invalid-review-findings'):
            self.finish()
        self.assertEqual(before, (self.state / 'campaign.json').read_bytes())
        self.assertEqual(events, (directory / 'events.jsonl').read_bytes())

    def test_empty_pass_can_continue_only_within_its_explicit_scope(self):
        self.response(verdict='pass', findings=[], scope='read_only_preflight', cleanupAssessment='unresolved')
        self.finish()
        through, handoff = C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))
        self.assertEqual(through, 1)
        self.assertIn('Scope: read_only_preflight', handoff)
        self.assertIs(C.private(self.state / 'campaign.json')['allowsFinalDelivery'], False)

    def test_unbound_manifest_name_and_duplicate_identity_are_rejected(self):
        directory = self.prepare()
        bundle = C.private(directory / 'bundle.json')
        for refs in [['manifest-pass999.json'], ['manifest', self.manifest.name]]:
            with self.subTest(refs=refs):
                response = dict(verdict='pass', findings=[], nextAction='Continue the existing offline preparation.',
                                scope='offline', evidence=refs, cleanupAssessment='not_required',
                                progress='none', ownerRequest=None)
                C.save(directory / 'events.jsonl', dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(response))))
                with self.assertRaises(ValueError):
                    R.result(directory / 'events.jsonl', bundle)

    def test_manifest_filename_cannot_alias_a_different_hash_or_source(self):
        directory = self.response(evidence=[self.manifest.name])
        bundle = C.private(directory / 'bundle.json')
        other_hash = copy.deepcopy(bundle)
        other_hash['manifest']['sha256'] = '0' * 64
        collision = copy.deepcopy(bundle)
        collision['sources'][self.manifest.name] = dict(content='unrelated', sha256='0' * 64)
        for invalid in [other_hash, collision]:
            with self.assertRaises(ValueError):
                R.result(directory / 'events.jsonl', invalid)

    def test_unchanged_executable_source_stops_third_review(self):
        for number in range(1, 4):
            if number > 1:
                value = C.private(self.state / 'campaign.json')
                value.update(phase='review_pending', executorPasses=number, lastFinishedPass=number)
                C.save(self.state / 'campaign.json', value)
                manifest = C.private(self.manifest)
                manifest['executorPass'] = number
                # Metadata and notes cannot renew executable progress.
                manifest['note'] = f'Another observation {number}'
                self.manifest = self.candidate_dir / f'manifest-pass{number}.json'
                C.save(self.manifest, manifest)
            self.response()
            self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        self.assertEqual(C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))[0], 2)

    def test_vendor_omission_is_explicit_and_cannot_be_cited_as_reviewed(self):
        vendor = self.candidate_dir / 'installed-client-artifacts/big.js'
        vendor.parent.mkdir()
        R.put(vendor, b'x' * 300001)
        manifest = C.private(self.manifest)
        manifest['files']['installed-client-artifacts/big.js'] = C.digest(vendor)
        C.save(self.manifest, manifest)
        directory = self.response(evidence=['installed-client-artifacts/big.js'])
        bundle = C.private(directory / 'bundle.json')
        self.assertTrue(bundle['sources']['installed-client-artifacts/big.js']['omitted'])
        with self.assertRaises(ValueError):
            self.finish()

    def test_classified_preparation_replans_then_stops_without_accepting(self):
        for number in range(1, 7):
            if number > 1:
                value = C.private(self.state / 'campaign.json')
                value.update(phase='review_pending', executorPasses=number, lastFinishedPass=number)
                C.save(self.state / 'campaign.json', value)
                manifest = C.private(self.manifest)
                manifest['executorPass'] = number
                self.manifest = self.candidate_dir / f'manifest-pass{number}.json'
                C.save(self.manifest, manifest)
            self.response(objectiveId='ide-mcp', evidenceLevel='preparation')
            self.finish()
            if number == 3:
                self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
                self.assertIn(R.OBJECTIVES.REPLAN, C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))[1])
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assertEqual(C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))[0], 5)
        self.assertIs(C.private(self.state / 'campaign.json')['allowsFinalDelivery'], False)

    def runtime_observation_pass(self, number, identity=None):
        """Create immutable synthetic runtime files through the real review path."""
        value = C.private(self.state / 'campaign.json')
        value.update(phase='review_pending', executorPasses=number, lastFinishedPass=number)
        C.save(self.state / 'campaign.json', value)
        C.save(self.state / 'campaign-result.json', dict(schema=1, issue=19, executorPass=number,
               authorizationId=self.auth['authorizationId'], phase='review_pending',
               summary='Current synthetic observation awaits independent validation.'))
        if number > 1:
            source = self.source.read_bytes()
            self.candidate_dir = self.attempts / 'candidates' / f'pass{number}'
            self.candidate_dir.mkdir()
            self.source = self.candidate_dir / 'worker.ps1'
            R.put(self.source, source)
            self.manifest = self.candidate_dir / f'manifest-pass{number}.json'
        files = {'worker.ps1': C.digest(self.source)}
        observation = dict(executorPass=number)
        if identity is not None:
            artifact = self.candidate_dir / 'runtime-artifact.json'
            C.save(artifact, dict(executorPass=number, candidate=value['candidate'],
                                 observationType='official_runtime', executionFingerprint=identity))
            files[artifact.name] = C.digest(artifact)
            observation.update(objectiveId='ide-mcp', candidate=value['candidate'],
                               observationType='official_runtime',
                               artifacts={artifact.name: C.digest(artifact)})
        receipt = self.candidate_dir / 'live-observation.json'
        C.save(receipt, observation)
        files[receipt.name] = C.digest(receipt)
        C.save(self.manifest, dict(issue=19, executorPass=number, candidate=value['candidate'],
               authorizationId=self.auth['authorizationId'], files=files, newLiveActivity=True))
        self.response(verdict='pass', findings=[], objectiveId='ide-mcp',
                      evidenceLevel='runtime_observation', progress='new_runtime_evidence',
                      evidence=['worker.ps1', receipt.name],
                      nextAction='Continue the next authorized preparation step using this observation and retain its limits.')
        self.finish()
        return R.OBJECTIVES._history(self.state)[-1]

    def test_insufficient_runtime_receipt_replans_at_three_and_stops_at_six(self):
        for number in range(1, 7):
            record = self.runtime_observation_pass(number)
            self.assertFalse(record['materialProgress'])
            self.assertEqual(record['validatedEvidenceLevel'], 'preparation')
            self.assertEqual(record['preparationStreak'], number)
            self.assertEqual(R.job(self.state)[1]['unchangedReviews'], number)
            if number == 3:
                self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
                handoff = C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))[1]
                self.assertIn(R.OBJECTIVES.REPLAN, handoff)
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assertEqual(C.reviewed_checkpoint(C.private(self.state / 'campaign.json'))[0], 5)
        self.assertIs(C.private(self.state / 'campaign.json')['allowsFinalDelivery'], False)

    def test_repackaged_runtime_identity_cannot_reset_review_counter(self):
        first = self.runtime_observation_pass(1, 'a' * 64)
        self.assertTrue(first['materialProgress'])
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 0)
        original = {path: C.digest(path) for path in self.candidate_dir.iterdir() if path.is_file()}
        second = self.runtime_observation_pass(2, 'a' * 64)
        self.assertNotEqual(first['runtimeEvidenceHashes'], second['runtimeEvidenceHashes'])
        self.assertEqual(first['runtimeIdentityHashes'], second['runtimeIdentityHashes'])
        self.assertFalse(second['materialProgress'])
        self.assertEqual(second['preparationStreak'], 1)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 1)
        self.assertEqual(original, {path: C.digest(path) for path in original})
        self.assertFalse(second['acceptanceChanged'])

    def test_new_valid_runtime_observation_resets_counter_without_acceptance(self):
        protected = [self.state / 'session', self.auth_path, self.attempts / 'attempt-1/receipt.json']
        before = [C.digest(path) for path in protected]
        self.runtime_observation_pass(1)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 1)
        record = self.runtime_observation_pass(2, 'c' * 64)
        self.assertTrue(record['materialProgress'])
        self.assertEqual(record['validatedEvidenceLevel'], 'runtime_observation')
        self.assertEqual(record['preparationStreak'], 0)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 0)
        objective = next(item for item in R.OBJECTIVES.status(self.state) if item['objectiveId'] == 'ide-mcp')
        self.assertEqual(objective['acceptanceState'], 'unproven')
        self.assertFalse(record['acceptanceChanged'])
        self.assertIs(C.private(self.state / 'campaign.json')['allowsFinalDelivery'], False)
        self.assertEqual(before, [C.digest(path) for path in protected])

    def test_owner_action_has_priority_over_stagnation_and_actionable_notice(self):
        self.response(verdict='owner_required', ownerRequest=dict(action='interactive_login', location='windows_ide'))
        directory, marker = R.job(self.state)
        marker['unchangedReviews'] = 3
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'owner_required')
        self.assertTrue((directory / 'result.json').exists())
        self.assertIn('@renersilv', R.owner_notice(self.state))
        self.assertIn('IDE do Windows', R.owner_notice(self.state))

    def test_renamed_source_does_not_change_executable_fingerprint(self):
        before = R.packet(C.private(self.state / 'campaign.json'), self.state)['sourceFingerprint']
        renamed = self.source.with_name('worker-renamed.ps1')
        self.source.rename(renamed)
        manifest = C.private(self.manifest)
        manifest['files'] = {'worker-renamed.ps1': C.digest(renamed)}
        C.save(self.manifest, manifest)
        after = R.packet(C.private(self.state / 'campaign.json'), self.state)['sourceFingerprint']
        self.assertEqual(before, after)

    def test_reviewer_does_not_reset_stagnation_for_comment_only_change(self):
        self.response(progress='none')
        _, marker = R.job(self.state)
        marker['unchangedReviews'] = 2
        marker['previousSourceFingerprint'] = 'a' * 64
        C.save(self.state / 'campaign-auto-review.json', marker)
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')

    def test_dispatch_reconciles_crash_between_campaign_and_marker(self):
        self.response()
        old_marker = C.private(self.state / 'campaign-auto-review.json')
        self.finish()
        exact = (self.state / 'campaign.json').read_bytes()
        C.save(self.state / 'campaign-auto-review.json', old_marker)
        R.reconcile(self.state)
        marker = R.job(self.state)[1]
        self.assertEqual(marker['phase'], 'continued')
        self.assertTrue(marker['noticePending'])
        self.assertEqual(marker['unchangedReviews'], 1)
        self.assertEqual(exact, (self.state / 'campaign.json').read_bytes())
        R.reconcile(self.state)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 1)

    def test_real_shell_review_and_checkpoint_resume_without_chat(self):
        scripts = self.root / 'installed-wrapper'
        shutil.copytree(HERE.parent, scripts)
        controller = scripts / 'campaign-control.py'
        controller.write_text(controller.read_text().replace(
            "REVIEW_ROOT = Path.home() / '.config/rappor-security-lab/campaign-reviews'",
            f'REVIEW_ROOT = Path({str(self.operator)!r})'))
        recovery = scripts / 'recovery.py'
        recovery.write_text(recovery.read_text().replace(
            "REVIEW_ROOT=Path.home() / '.config/rappor-security-lab/campaign-reviews'",
            f'REVIEW_ROOT=Path({str(self.operator)!r})'))
        fake = self.root / 'fake-reviewer.py'
        verdict = dict(verdict='changes_requested', findings=['worker.ps1: replace unconditional failure.'],
                       nextAction='Implement the bounded offline correction and validate its production path.',
                       scope='offline', cleanupAssessment='not_required', evidence=['worker.ps1'],
                       progress='none', ownerRequest=None)
        fake.write_text('#!/usr/bin/env python3\nimport json,sys\n'
                        'assert "resume" not in sys.argv\n'
                        'assert "read-only" in sys.argv\n'
                        'assert "--ignore-user-config" in sys.argv\n'
                        'assert "--disable" in sys.argv\n'
                        'assert "worker.ps1" in sys.stdin.read()\n'
                        'print(' + repr(json.dumps(dict(type='item.completed', item=dict(
                            type='agent_message', text=json.dumps(verdict))))) + ')\n')
        fake.chmod(0o700)
        shell = r'''
set -euo pipefail
umask 077
SCRIPT_DIR=$1 STATE_ROOT=$2 CODEX_BIN=$3
TIMEOUT_BIN=timeout MODEL=fixture REASONING_EFFORT=xhigh
source "$SCRIPT_DIR/campaign.sh"
state_file() { printf '%s/%s' "$STATE_ROOT" "$1"; }
campaign_review_notice() { printf '%s\n' "$1" >> "$STATE_ROOT/notices"; }
issue_operational_state() { printf doing; }
log() { :; }
run_codex() {
  campaign_command prompt > "$STATE_ROOT/resumed-prompt"
  python3 - "$STATE_ROOT" <<'PY'
import json,os,sys
from pathlib import Path
r=Path(sys.argv[1]);v=json.loads((r/'campaign.json').read_text())
p=r/'campaign-result.json'
p.write_text(json.dumps(dict(schema=1,issue=19,executorPass=v['executorPasses'],authorizationId='issue19-native-windows-20261023',phase='active',summary='Offline correction is underway.')))
os.chmod(p,0o600)
PY
}
execute_campaign_item 19 "$4" "$5"
'''
        run = subprocess.run(['bash', '-c', shell, 'fixture', str(scripts), str(self.state), str(fake),
                              str(self.worktree), self.stage['branch']], capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        after = C.private(self.state / 'campaign.json')
        self.assertEqual(after['executorPasses'], 2)
        self.assertEqual(C.reviewed_checkpoint(after)[0], 1)
        self.assertIn('Implement the bounded offline correction', (self.state / 'resumed-prompt').read_text())
        self.assertEqual((self.state / 'notices').read_text().splitlines(), ['reviewing', 'continued'])
        self.assertEqual((self.state / 'session').read_text().strip(), self.session)


if __name__ == '__main__':
    unittest.main()
