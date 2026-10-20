"""Real Git/private-state tests; no remote service or model is invoked."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('stage_control', ROOT / 'ops/joao/stage-control.py')
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.git('init', '-q', '-b', 'joao/batch-20261020T000000Z-19-19')
        self.git('config', 'user.name', 'Laboratory fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.work / 'source.txt').write_text('baseline\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'test: baseline')
        self.contract = ROOT / 'ops/joao/contracts/19.json'

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.work), *args])

    def command(self, action, success=True):
        result = subprocess.run(['python3', str(ROOT / 'ops/joao/stage-control.py'), action,
                                 str(self.state), '19', str(self.work), str(self.contract)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result.stdout.strip()

    def events(self, value):
        path = self.state / 'stage-review.events.jsonl'
        path.write_text(json.dumps({'type': 'item.completed', 'item': {
            'type': 'agent_message', 'text': json.dumps(value)}}) + '\n')
        path.chmod(0o600)

    def test_pass_waits_without_granting_budget_or_changing_git(self):
        original = self.git('rev-parse', 'HEAD')
        (self.work / 'unfinished.txt').write_text('preserve work\n')
        self.assertEqual(self.command('phase'), 'implementation')
        self.assertEqual(self.command('begin-review'), 'review')
        self.events({'verdict': 'pass', 'findings': []})
        self.assertEqual(self.command('finish-review'), 'waiting_owner')
        for _ in range(4):
            self.assertEqual(self.command('phase'), 'waiting_owner')
        self.command('begin-review', success=False)
        self.assertEqual(self.git('rev-parse', 'HEAD'), original)
        self.assertEqual((self.work / 'unfinished.txt').read_text(), 'preserve work\n')
        data = stage.private_read(self.state / 'stage.json')
        self.assertEqual(data['reviews'], 1)
        self.assertNotIn('authorization', data)

    def test_queued_review_survives_restart_without_reimplementation(self):
        self.command('phase')
        self.assertEqual(self.command('queue-review'), 'review_pending')
        self.assertEqual(self.command('phase'), 'review_pending')
        self.assertEqual(self.command('phase'), 'review_pending')
        self.assertEqual(self.command('begin-review'), 'review')

    def test_negative_review_returns_correction_and_preserves_findings(self):
        self.command('phase')
        self.command('begin-review')
        self.events({'verdict': 'changes_requested', 'findings': ['source.txt: missing cancellation test']})
        self.assertEqual(self.command('finish-review'), 'correction')
        result = stage.private_read(self.state / 'stage-review.result.json')
        self.assertIn('cancellation', result['findings'][0])

    def test_interrupted_reviews_are_counted_and_stop_after_three(self):
        self.command('phase')
        for attempt in range(3):
            self.command('begin-review')
            expected = 'exhausted' if attempt == 2 else 'correction'
            self.assertEqual(self.command('phase'), expected)
        self.command('begin-review', success=False)
        self.assertEqual(stage.private_read(self.state / 'stage.json')['reviews'], 3)

    def test_failed_checks_are_bounded_without_a_reviewer(self):
        self.command('phase')
        for attempt in range(3):
            self.command('begin-review')
            self.assertEqual(self.command('checks-failed'), 'exhausted' if attempt == 2 else 'correction')
        self.assertFalse((self.state / 'stage-review.events.jsonl').exists())

    def test_changed_untracked_source_invalidates_pass(self):
        self.command('phase')
        self.command('begin-review')
        (self.work / 'new-source.py').write_text('new behavior\n')
        self.events({'verdict': 'pass', 'findings': []})
        self.assertEqual(self.command('finish-review'), 'correction')
        self.assertEqual(stage.private_read(self.state / 'stage.json')['reason'], 'source_changed')

    def test_changed_source_after_pass_reopens_preparation_only(self):
        self.command('phase')
        self.command('begin-review')
        self.events({'verdict': 'pass', 'findings': []})
        self.command('finish-review')
        (self.work / 'source.txt').write_text('modified\n')
        self.assertEqual(self.command('phase'), 'correction')

    def test_malformed_evidence_and_inconsistent_verdict_fail_closed(self):
        self.command('phase')
        self.command('begin-review')
        self.events({'verdict': 'pass', 'findings': ['unresolved bug']})
        self.command('finish-review', success=False)
        self.assertEqual(stage.private_read(self.state / 'stage.json')['phase'], 'review')

    def test_branch_contract_and_private_file_binding(self):
        self.command('phase')
        self.git('checkout', '-qb', 'joao/batch-20261020T000001Z-19-19')
        self.command('phase', success=False)
        self.git('checkout', '-q', 'joao/batch-20261020T000000Z-19-19')
        path = self.state / 'stage.json'
        path.chmod(0o644)
        self.command('phase', success=False)
        path.chmod(0o600)
        real = self.state / 'original.json'
        path.rename(real)
        path.symlink_to(real)
        self.command('phase', success=False)

    def test_status_does_not_expose_paths_or_review_contents(self):
        self.command('phase')
        output = subprocess.check_output(['python3', str(ROOT / 'ops/joao/stage-control.py'),
                                          'status', str(self.state)], text=True)
        self.assertIn('stage=implementation', output)
        self.assertNotIn(str(self.work), output)
        self.assertNotIn('snapshot', output)

    def test_bundle_binds_source_and_never_includes_credentials(self):
        (self.work / 'src').mkdir()
        (self.work / 'src/helper.mjs').write_text('export const safe = true;\n')
        (self.work / 'src/change.mjs').write_text('import {safe} from "./helper.mjs";\n')
        (self.work / '.gitignore').write_text('.env\n')
        self.git('add', '.gitignore', 'src/helper.mjs')
        self.git('commit', '-qm', 'test: helper')
        (self.work / '.env').write_text('DO_NOT_INCLUDE=private\n')
        (self.state / 'stage-checks.log').write_text('ℹ tests 4\nℹ pass 4\nℹ fail 0\n')
        bundle = stage.review_bundle(self.work, self.git('rev-parse', 'HEAD').decode().strip(), self.state)
        self.assertIn('src/change.mjs', bundle['sources'])
        self.assertIn('src/helper.mjs', bundle['sources'])
        self.assertNotIn('DO_NOT_INCLUDE', json.dumps(bundle))
        self.assertEqual(bundle['sourceSnapshot'], stage.snapshot(self.work))

    def test_bundle_rejects_symlink_and_unapproved_files(self):
        (self.state / 'stage-checks.log').write_text('ℹ fail 0\n')
        outside = self.root / 'secret.mjs'
        outside.write_text('private')
        (self.work / 'src').mkdir()
        (self.work / 'src/link.mjs').symlink_to(outside)
        with self.assertRaises(ValueError):
            stage.review_bundle(self.work, self.git('rev-parse', 'HEAD').decode().strip(), self.state)

    def test_review_with_tool_use_is_rejected_even_if_final_verdict_passes(self):
        self.events({'verdict': 'pass', 'findings': []})
        path = self.state / 'stage-review.events.jsonl'
        path.write_text(json.dumps({'type': 'item.completed', 'item': {'type': 'command_execution'}}) +
                        '\n' + path.read_text())
        with self.assertRaises(ValueError):
            stage.review_result(path)

    def test_external_requirement_does_not_grant_campaign(self):
        self.command('phase')
        self.command('begin-review')
        self.events({'verdict': 'owner_required', 'findings': ['A new account scope needs owner approval.']})
        self.assertEqual(self.command('finish-review'), 'waiting_owner')
        self.assertEqual(stage.private_read(self.state / 'stage.json')['reason'], 'external_requirement')


if __name__ == '__main__':
    unittest.main()
