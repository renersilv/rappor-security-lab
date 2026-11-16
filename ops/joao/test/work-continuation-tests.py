#!/usr/bin/env python3
"""Real independent review boundaries; no live worker, guest or model execution."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

BASE = load('work_review_fixtures', HERE / 'campaign-review-tests.py')
SOURCE_ROOT = Path(os.environ.get('JOAO_WORK_CONTINUATION_SOURCE_ROOT', HERE.parent))
R = load('work_review_under_test', SOURCE_ROOT / 'campaign-review.py')
C = R.C
BASE.R, BASE.C, BASE.BASE.MODULE = R, C, C

class WorkContinuationTests(unittest.TestCase):
    attempt = BASE.ReviewTests.attempt
    prepare = BASE.ReviewTests.prepare
    response = BASE.ReviewTests.response
    finish = BASE.ReviewTests.finish

    def setUp(self):
        BASE.ReviewTests.setUp(self)
        for number in range(1, 6):
            self.packet(number)
            self.approval()
            self.finish()
            self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
        self.ledger = self.state / 'fixture-inference-ledger.json'
        C.save(self.ledger, dict(active=False, attempts=[dict(sequence=22, outcome='failed')]))
        self.protected = {p: p.read_bytes() for p in (self.auth_path, self.ledger, self.state / 'session',
            self.attempts / 'attempt-1/receipt.json')}
        self.history = {p: p.read_bytes() for parent in (self.operator, self.state / 'objectives-history')
            for p in parent.rglob('*') if p.is_file()}
        self.packet(6)
        self.before = C.private(self.state / 'campaign.json')

    def tearDown(self):
        BASE.ReviewTests.tearDown(self)

    def packet(self, number):
        value = C.private(self.state / 'campaign.json')
        value.update(phase='review_pending', executorPasses=number, lastFinishedPass=number)
        C.save(self.state / 'campaign.json', value)
        if number != 1:
            self.candidate_dir = self.attempts / 'candidates' / f'work-pass{number}'
            self.candidate_dir.mkdir(mode=0o700)
            self.source = self.candidate_dir / 'worker.ps1'
            R.put(self.source, f'function Invoke-Worker {{ return {number} }}\n'.encode())
        check = self.candidate_dir / 'offline-check.json'
        C.save(check, dict(schema=1, fixtureOnly=True, preparationOnly=True, passed=True))
        self.manifest = self.candidate_dir / f'manifest-pass{number}.json'
        C.save(self.manifest, dict(issue=19, executorPass=number, candidate=value['candidate'],
            authorizationId=self.auth['authorizationId'], newLiveActivity=False,
            files={'worker.ps1': C.digest(self.source), check.name: C.digest(check)}))

    def approval(self, target=None, **changes):
        fields = dict(verdict='pass', findings=[], scope='offline', cleanupAssessment='verified',
            objectiveId='ide-mcp', evidenceLevel='preparation', progress='none',
            evidence=['worker.ps1', 'offline-check.json'],
            nextAction='Prepare the already authorized independent Web ZIP journey offline; do not start inference or change quotas.')
        if target is not None:
            fields['workContinuation'] = dict(targetObjectiveId=target)
        fields.update(changes)
        return self.response(**fields)

    def grant(self):
        state = C.private(self.state / 'campaign.json')
        receipt = C.artifact(state['reviewCheckpoint'], protected=True)
        correction = C.artifact(receipt['correction'], protected=True)
        return correction.get('workContinuation')

    def preserved(self):
        for path, raw in {**self.protected, **self.history}.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        state = C.private(self.state / 'campaign.json')
        for key in set(self.before) - {'phase', 'reviewCheckpoint', 'executorPasses', 'lastFinishedPass', 'reviewReason'}:
            self.assertEqual(state[key], self.before[key], key)
        self.assertFalse(state['allowsFinalDelivery'])

    def rejected(self):
        before = (self.state / 'campaign.json').read_bytes()
        try:
            self.finish()
        except ValueError:
            self.assertEqual((self.state / 'campaign.json').read_bytes(), before)
        else:
            self.assertIn(C.private(self.state / 'campaign.json')['phase'], {'review_pending', 'owner_required'})
        self.preserved()

    def controller(self, action):
        output = io.StringIO()
        with mock.patch.object(C.sys, 'argv', ['campaign-control.py', action, str(self.state)]), contextlib.redirect_stdout(output):
            C.main()
        return output.getvalue().strip()

    def test_approved_typed_independent_handoff_crosses_real_finish_without_reset(self):
        self.approval('web-entries')
        self.finish()
        marker = R.job(self.state)[1]
        self.assertEqual(marker['phase'], 'continued')
        self.assertEqual(marker['unchangedReviews'], 6)
        state = C.private(self.state / 'campaign.json')
        self.assertEqual(state['phase'], 'active')
        self.assertEqual(state['executorPasses'], 6)
        grant = self.grant()
        self.assertEqual(grant['targetObjectiveId'], 'web-entries')
        self.assertEqual(grant['phase'], 'offline')
        self.assertEqual(grant['offlineCheckpoints'], 1)
        self.assertEqual(grant['runtimeCheckpoints'], 0)
        record = R.OBJECTIVES._history(self.state)[-1]
        self.assertEqual(record['preparationStreak'], 6)
        self.assertFalse(record['materialProgress'])
        self.assertFalse(record['acceptanceChanged'])
        self.preserved()

    def test_prose_only_handoff_remains_stalled_at_the_original_global_bound(self):
        self.approval()
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'stalled')
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 6)
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        self.preserved()

    def test_same_initial_objective_is_not_an_independent_handoff(self):
        self.approval('web-entries', objectiveId='web-entries')
        self.rejected()

    def test_unknown_or_unapproved_target_does_not_resume(self):
        self.approval('ide-mcp')
        self.rejected()

    def test_initial_runtime_scope_cannot_skip_the_offline_handoff(self):
        self.approval('web-entries', scope='read_only_preflight')
        self.rejected()

    def test_unresolved_cleanup_does_not_authorize_independent_work(self):
        self.approval('web-entries', cleanupAssessment='unresolved')
        self.rejected()

    def test_owner_requirement_cannot_be_overridden_by_work_selection(self):
        self.approval('web-entries', verdict='owner_required', findings=['A protected owner action is still missing.'],
            ownerRequest=dict(action='interactive_login', location='windows_ide'))
        self.rejected()

    def test_rejected_independent_review_cannot_resume(self):
        self.approval('web-entries', verdict='changes_requested', findings=['The proposed work source is not ready.'])
        self.rejected()

    def test_changed_source_after_review_snapshot_cannot_create_a_handoff(self):
        self.approval('web-entries')
        self.source.write_bytes(b'function Invoke-Worker { return 999 }\n')
        self.rejected()

    def test_changed_bound_evidence_after_snapshot_cannot_create_a_handoff(self):
        self.approval('web-entries')
        C.save(self.candidate_dir / 'offline-check.json', dict(passed=False, changedAfterReview=True))
        self.rejected()

    def test_missing_bound_evidence_cannot_authorize_handoff(self):
        self.approval('web-entries', evidence=['missing-evidence.json'])
        self.rejected()

    def test_third_offline_checkpoint_cannot_renew_target_budget(self):
        self.approval('web-entries'); self.finish()
        self.packet(7)
        self.approval('web-entries', objectiveId='web-entries'); self.finish()
        self.assertEqual(self.grant()['offlineCheckpoints'], 2)
        self.packet(8)
        self.approval('web-entries', objectiveId='web-entries')
        self.rejected()

    def test_rejected_current_work_uses_only_the_remaining_offline_correction_slot(self):
        self.approval('web-entries'); self.finish()
        self.packet(7)
        self.approval('web-entries', objectiveId='web-entries', verdict='changes_requested',
            findings=['The prepared ZIP flow requires a bounded offline correction.'])
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
        grant = self.grant()
        self.assertEqual(grant['offlineCheckpoints'], 2)
        self.assertEqual(grant['runtimeCheckpoints'], 0)
        self.assertEqual(grant['scope'], 'offline')
        self.packet(8)
        self.approval('web-entries', objectiveId='web-entries', verdict='changes_requested',
            findings=['The same offline source still fails its regression.'])
        self.rejected()

    def test_second_runtime_checkpoint_cannot_renew_target_budget(self):
        self.approval('web-entries'); self.finish()
        self.packet(7)
        self.approval('web-entries', objectiveId='web-entries', scope='read_only_preflight'); self.finish()
        self.assertEqual(self.grant()['runtimeCheckpoints'], 1)
        self.packet(8)
        self.approval('web-entries', objectiveId='web-entries', scope='read_only_preflight')
        self.rejected()

    def test_all_three_versioned_targets_can_receive_one_independent_offline_selection(self):
        previous = 'ide-mcp'
        for number, target in enumerate(('web-entries', 'managed-technical', 'negative-consent-cleanup'), 6):
            if number != 6:
                self.packet(number)
            self.approval(target, objectiveId=previous)
            self.finish()
            self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
            self.assertEqual(self.grant()['targetObjectiveId'], target)
            self.assertEqual(self.grant()['offlineCheckpoints'], 1)
            self.assertEqual(self.grant()['runtimeCheckpoints'], 0)
            self.assertEqual(R.job(self.state)[1]['unchangedReviews'], number)
            previous = target
        self.preserved()

    def test_switching_to_another_target_does_not_allow_return_to_a_visited_target(self):
        self.approval('web-entries'); self.finish()
        self.packet(7)
        self.approval('managed-technical', objectiveId='web-entries'); self.finish()
        self.packet(8)
        self.approval('web-entries', objectiveId='managed-technical')
        self.rejected()

    def test_finish_replay_reuses_grant_and_interrupted_launch_is_consumed(self):
        self.approval('web-entries'); self.finish()
        campaign = (self.state / 'campaign.json').read_bytes()
        marker = (self.state / 'campaign-auto-review.json').read_bytes()
        grant = self.grant()
        self.finish()
        self.assertEqual((self.state / 'campaign.json').read_bytes(), campaign)
        self.assertEqual((self.state / 'campaign-auto-review.json').read_bytes(), marker)
        self.assertEqual(self.grant(), grant)
        self.controller('begin')
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 7)
        with self.assertRaisesRegex(ValueError, 'campaign-not-active'):
            self.controller('begin')
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 7)
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        self.preserved()

    def test_historical_stalled_review_is_reassessed_separately_without_rewriting_or_progress(self):
        self.approval()
        self.finish()
        original_dir, original_marker = R.job(self.state)
        self.assertEqual(original_marker['phase'], 'stalled')
        retained = {p: p.read_bytes() for p in original_dir.rglob('*') if p.is_file()}
        objective_history = {p: p.read_bytes() for p in (self.state / 'objectives-history').glob('*.json')}
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        fresh_dir, fresh_marker = R.job(self.state)
        self.assertNotEqual(fresh_dir, original_dir)
        self.assertEqual(fresh_marker['executorPass'], 6)
        self.approval('web-entries')
        self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 6)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 6)
        self.assertEqual(self.grant()['offlineCheckpoints'], 1)
        for path, raw in retained.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        self.assertEqual({p: p.read_bytes() for p in (self.state / 'objectives-history').glob('*.json')}, objective_history)
        self.preserved()

    def test_stale_historical_reassessment_cannot_resume_changed_campaign(self):
        self.approval()
        self.finish()
        original_dir, _ = R.job(self.state)
        retained = {p: p.read_bytes() for p in original_dir.rglob('*') if p.is_file()}
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        self.approval('web-entries')
        changed = C.private(self.state / 'campaign.json')
        changed['lastSummary'] = 'Fixture changed after independent review snapshot.'
        C.save(self.state / 'campaign.json', changed)
        with self.assertRaises(ValueError):
            self.finish()
        self.assertEqual(C.private(self.state / 'campaign.json'), changed)
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        for path, raw in retained.items():
            self.assertEqual(path.read_bytes(), raw, str(path))
        for path, raw in self.protected.items():
            self.assertEqual(path.read_bytes(), raw, str(path))

    def retry_gate(self, *, unrelated=False):
        for name, text in (('base_sha', 'a' * 40), ('branch', 'joao/batch-fixture')):
            if not (self.state / name).exists():
                R.put(self.state / name, (text + '\n').encode())
        base = (self.state / 'base_sha').read_text().strip()
        branch = (self.state / 'branch').read_text().strip()
        detail = 'unrelated_transport' if unrelated else R.incident_key(self.state)
        fingerprint = R.sha(f'v1:{base}:{branch}:19:codex_exit:{detail}'.encode())
        raw = f'issue=19\nbranch={branch}\nerror_class=codex_exit\nfingerprint={fingerprint}\nattempts=3\nsuspended=true\n'.encode()
        R.put(self.state / 'issue-retry', raw)
        return raw

    def test_exact_retry_release_recovers_after_finish_without_another_review(self):
        self.approval(); self.finish()
        original = self.retry_gate()
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        self.approval('web-entries'); self.finish()
        self.assertEqual((self.state / 'issue-retry').read_bytes(), original)
        checkpoint = C.private(self.state / 'campaign.json')['reviewCheckpoint']
        for _ in range(2):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                R.resume_correction(self.state)
            self.assertEqual(output.getvalue().strip(), 'resumed')
            self.assertFalse((self.state / 'issue-retry').exists())
            self.assertEqual(C.private(self.state / 'campaign.json')['reviewCheckpoint'], checkpoint)
        self.preserved()

    def test_unrelated_retry_is_not_archived_or_released_by_historical_review(self):
        self.approval(); self.finish()
        original = self.retry_gate(unrelated=True)
        marker = (self.state / 'campaign-auto-review.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'unrelated-operational-retry-gate'):
            R.prepare_work_review(self.state)
        self.assertEqual((self.state / 'issue-retry').read_bytes(), original)
        self.assertEqual((self.state / 'campaign-auto-review.json').read_bytes(), marker)
        self.preserved()

    def test_retry_changed_after_snapshot_survives_approved_work_handoff(self):
        self.approval(); self.finish()
        original = self.retry_gate()
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        self.approval('web-entries'); self.finish()
        changed = original.replace(b'attempts=3', b'attempts=4')
        (self.state / 'issue-retry').write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'work-retry-changed'):
            R.resume_correction(self.state)
        self.assertEqual((self.state / 'issue-retry').read_bytes(), changed)
        self.preserved()

    def test_consumed_work_grant_does_not_release_a_later_retry_or_block_review(self):
        self.approval(); self.finish(); self.retry_gate()
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        self.approval('web-entries'); self.finish()
        with contextlib.redirect_stdout(io.StringIO()):
            R.resume_correction(self.state)
        self.controller('begin')
        later = self.retry_gate(unrelated=True)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            R.resume_correction(self.state)
        self.assertEqual(output.getvalue().strip(), 'not_eligible')
        self.assertEqual((self.state / 'issue-retry').read_bytes(), later)
        self.controller('phase')
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')

    def test_exhausted_target_is_regenerated_before_persisting_a_review_result(self):
        self.approval('web-entries'); self.finish()
        self.packet(7)
        self.approval('web-entries', objectiveId='web-entries'); self.finish()
        self.packet(8)
        self.approval('web-entries', objectiveId='web-entries')
        before = R.OBJECTIVES._history(self.state)
        with mock.patch.object(R.sys, 'argv', ['campaign-review.py', 'validate-response', str(self.state)]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                R.main()
        self.assertEqual(output.getvalue().strip(), 'regenerate')
        with self.assertRaisesRegex(ValueError, 'work-continuation-budget-exhausted'):
            self.finish()
        self.assertEqual(R.OBJECTIVES._history(self.state), before)
        self.assertFalse((R.job(self.state)[0] / 'result.json').exists())

    def test_full_sized_historical_artifacts_are_verified_without_handoff_text_limit(self):
        self.source.write_bytes(b'# bounded fixture source\n' * 9000)
        notes = self.candidate_dir / 'review-context.md'
        R.put(notes, b'Offline fixture evidence.\n' * 9000)
        manifest = C.private(self.manifest)
        manifest['files'].update({'worker.ps1': C.digest(self.source), notes.name: C.digest(notes)})
        C.save(self.manifest, manifest)
        directory = self.approval()
        events = directory / 'events.jsonl'
        reasoning = R.encoded(dict(type='item.completed', item=dict(type='reasoning', text='Bounded review. ' * 3000)))
        events.write_bytes(reasoning + events.read_bytes())
        self.finish()
        retained = {p: p.read_bytes() for p in directory.iterdir() if p.is_file()}
        self.assertGreater(len(retained[directory / 'bundle.json']), 420000)
        self.assertGreater(len(retained[directory / 'prompt.md']), 440000)
        self.assertGreater(len(retained[events]), 32768)
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        self.approval('web-entries'); self.finish()
        self.assertEqual(R.job(self.state)[1]['phase'], 'continued')
        for path, raw in retained.items():
            self.assertEqual(path.read_bytes(), raw)
        self.preserved()

    def artifact_snapshot(self):
        self.approval(); self.finish()
        with contextlib.redirect_stdout(io.StringIO()):
            R.prepare_work_review(self.state)
        directory, _ = R.job(self.state)
        return C.private(directory / 'bundle.json')['workRereview']

    def test_historical_full_artifact_hash_mismatch_is_rejected(self):
        snapshot = self.artifact_snapshot()
        snapshot['artifacts']['prompt.md']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            R.rereview_objective(self.state, snapshot)

    def test_historical_full_artifact_above_sixteen_mib_is_rejected(self):
        snapshot = self.artifact_snapshot()
        large = self.operator / 'oversized-full-artifact.txt'
        R.put(large, b'x' * (16 * 1024 * 1024 + 1))
        snapshot['artifacts']['prompt.md'] = R.reference(large)
        with self.assertRaises(ValueError):
            R.rereview_objective(self.state, snapshot)

    def test_historical_full_artifact_symlink_is_rejected(self):
        snapshot = self.artifact_snapshot()
        link = self.operator / 'linked-full-artifact.txt'
        link.symlink_to(snapshot['artifacts']['prompt.md']['path'])
        snapshot['artifacts']['prompt.md']['path'] = str(link)
        with self.assertRaises(ValueError):
            R.rereview_objective(self.state, snapshot)

if __name__ == '__main__':
    unittest.main()
