#!/usr/bin/env python3
"""Candidate repair boundaries; optional real sandbox never uses guest or credentials."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('candidate_sandbox', Path(__file__).resolve().parents[1] / 'candidate-repair-sandbox.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)
FIXTURE = "import test from 'node:test';\nimport assert from 'node:assert/strict';\nconst makeSnapshots = () => ({ value: 1 });\nconst observation = {};\ntest('original assertion', () => { assert.equal(makeSnapshots().value, 1); });\n"


def material(text):
    return dict(content=text, sha256=hashlib.sha256(text.encode()).hexdigest())


class CandidateSandboxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='candidate-sandbox-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = {'source/calculation.mjs': material('export const value = 1;\n'),
                        'source/calculation.test.mjs': material(FIXTURE),
                        'tests/repair-existing.test.mjs': material('// Existing test is immutable.\n')}
        self.proposal = dict(disposition='repair', diagnosis='Correct the exact synthetic calculation defect.', files=[
            dict(path='source/calculation.mjs', content='export const value = 2;\n'),
            dict(path='tests/repair-calculation.test.mjs', content="import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport {value} from '../source/calculation.mjs';\ntest('calculation',()=>assert.equal(value,2));\n")])

    def tree(self):
        destination = self.root / 'tree'
        S.snapshot(dict(sources=self.sources), destination)
        return destination

    def test_snapshot_materializes_only_bound_regular_private_files(self):
        target = self.root / 'tree'
        hashes = S.snapshot(dict(sources=self.sources), target)
        self.assertEqual(hashes, {name: value['sha256'] for name, value in self.sources.items()})
        self.assertEqual(S.tree_hashes(target), hashes)
        for name in hashes:
            self.assertEqual((target / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(FileExistsError): S.snapshot(dict(sources=self.sources), target)

    def test_snapshot_rejects_bad_hash_omitted_symlink_and_path_binding_before_write(self):
        for mutation in ['hash', 'omitted', 'symlink', 'traversal']:
            with self.subTest(mutation=mutation):
                sources = copy.deepcopy(self.sources)
                if mutation == 'hash': sources['source/calculation.mjs']['sha256'] = '0' * 64
                if mutation == 'omitted': sources['source/calculation.mjs']['omitted'] = True
                if mutation == 'symlink': sources['source/calculation.mjs']['symlink'] = '/home/forbidden'
                if mutation == 'traversal': sources['../outside'] = material('outside')
                with self.assertRaises(ValueError): S.snapshot(dict(sources=sources), self.root / mutation)
                self.assertFalse((self.root / mutation).exists())
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): S.snapshot(dict(sources=self.sources), alias / 'tree')

    def test_proposal_splits_existing_source_and_new_regressions(self):
        edits, tests = S.validate_proposal(self.proposal, self.sources)
        self.assertEqual(edits, [self.proposal['files'][0]])
        self.assertEqual(tests, [self.proposal['files'][1]])
        self.assertEqual(self.sources['source/calculation.mjs']['content'], 'export const value = 1;\n')

    def test_proposal_rejects_traversal_protected_files_test_overwrite_and_new_sources(self):
        names = ['../source/calculation.mjs', '/source/calculation.mjs', 'source/../calculation.mjs',
                 'source\\calculation.mjs', '.git/config', 'source/verify.mjs', 'source/check-target.py',
                 'source/package.mjs', 'source/offline-contract.mjs', 'source/review.mjs', 'source/new.mjs',
                 'installed/calculation.mjs', 'manifest.json', 'tests/repair-existing.test.mjs']
        for name in names:
            with self.subTest(name=name):
                sources = copy.deepcopy(self.sources)
                if name not in {'source/new.mjs', 'tests/repair-existing.test.mjs'}:
                    sources[name] = material('original')
                proposal = copy.deepcopy(self.proposal)
                proposal['files'][0]['path'] = name
                with self.assertRaises(ValueError): S.validate_proposal(proposal, sources)

    def test_fixture_change_preserves_imports_observation_and_all_test_assertions(self):
        proposal = copy.deepcopy(self.proposal)
        proposal['files'][0] = dict(path='source/calculation.test.mjs', content=FIXTURE.replace('({ value: 1 })', "({ value: 1, scope: 'offline' })"))
        with self.assertRaisesRegex(ValueError, 'needs-implementation'): S.validate_proposal(proposal, self.sources)
        proposal['files'].append(copy.deepcopy(self.proposal['files'][0]))
        edits, tests = S.validate_proposal(proposal, self.sources)
        self.assertEqual(len(edits), 2); self.assertEqual(len(tests), 1)
        self.assertEqual(edits[0]['content'].split('test(')[1:], FIXTURE.split('test(')[1:])
        for invalid in [FIXTURE.replace("'node:test'", "'no-op-test'"), FIXTURE.replace('assert.equal', 'assert.notEqual'),
                        FIXTURE.replace('const observation = {};', 'const observation = null;'),
                        FIXTURE.replace('const makeSnapshots = ', 'const alternate = '),
                        FIXTURE.replace('const observation = {};', 'const observation = {};\nconst observation = {};')]:
            proposal['files'][0]['content'] = invalid
            with self.assertRaises(ValueError): S.validate_proposal(proposal, self.sources)

    def test_closed_schema_size_limits_noops_and_nonrepair_files(self):
        variants = []
        for change in [dict(command='arbitrary'), dict(files=[]), dict(diagnosis='short'), dict(disposition='unknown'), dict(disposition='external_action')]:
            variants.append(dict(self.proposal, **change))
        variants.append(dict(self.proposal, files=self.proposal['files'] * 5))
        for content in ['\x00', '', 'a' * 250001, self.sources['source/calculation.mjs']['content']]:
            changed = copy.deepcopy(self.proposal)
            changed['files'][0]['content'] = content
            variants.append(changed)
        oversized = copy.deepcopy(self.proposal)
        oversized['files'][0]['content'] = 'a' * 250000
        oversized['files'][1]['content'] = 'b' * 250000
        oversized['files'].append(dict(path='tests/repair-extra.py', content='c'))
        variants.append(oversized)
        for proposal in variants:
            with self.subTest(proposal=str(proposal)[:100]):
                with self.assertRaises(ValueError): S.validate_proposal(proposal, self.sources)
        self.assertEqual(S.validate_proposal(dict(disposition='unrepairable', diagnosis='The exact required decision is unavailable.', files=[]), self.sources), ([], []))

    def test_sandbox_rejects_symlinks_and_changed_test_hashes_before_launch(self):
        tree = self.tree()
        test_name = 'tests/repair-existing.test.mjs'
        tests = {test_name: self.sources[test_name]['sha256']}
        (tree / test_name).write_text('changed assertion')
        with patch.object(S.subprocess, 'run') as execute:
            with self.assertRaises(ValueError): S.sandbox(tree, tests, self.root / 'checks.log')
            execute.assert_not_called()
        (tree / test_name).unlink()
        (tree / test_name).symlink_to(self.root / 'unreadable')
        with patch.object(S.subprocess, 'run') as execute:
            with self.assertRaises((ValueError, OSError)): S.sandbox(tree, tests, self.root / 'checks.log')
            execute.assert_not_called()

    def test_fixed_sandbox_arguments_provenance_and_clean_environment(self):
        tree = self.tree()
        name = 'tests/repair-existing.test.mjs'
        tests = {name: self.sources[name]['sha256']}
        observed = {}
        def execute(args, **kwargs):
            observed.update(args=args, kwargs=kwargs)
            kwargs['stdout'].write(b'candidate_checks_started=true\ncandidate_case_finished=1\n')
            return subprocess.CompletedProcess(args, 1)
        with patch.object(S.subprocess, 'run', side_effect=execute):
            self.assertEqual(S.sandbox(tree, tests, self.root / 'checks.log'), 1)
        args = observed['args']
        for expected in ['--unshare-all', '--clearenv', '--new-session', '--cap-drop', 'ALL', '--property=MemoryMax=1G',
                         '--property=TasksMax=64', '--property=RuntimeMaxSec=250s', '--property=LimitFSIZE=2M']:
            self.assertIn(expected, args)
        self.assertNotIn('/home', args); self.assertNotIn('/run', args); self.assertNotIn('/var/run/docker.sock', args)
        self.assertEqual(json.loads(args[-1]), [name])
        self.assertLessEqual(set(observed['kwargs']['env']), {'HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'PATH', 'LANG', 'LC_ALL'})
        proof = json.loads((self.root / 'checks.log').read_text().splitlines()[0])
        self.assertEqual(proof['tests'], tests); self.assertEqual(proof['files'], S.tree_hashes(tree))
        self.assertEqual(proof['unit'], S.unit_for_log(self.root / 'checks.log'))
        self.assertIn('--unit=' + proof['unit'], args)
        self.assertIn('/usr/bin/node', S.DRIVER); self.assertNotIn('npm', S.DRIVER)

    def test_startup_failure_cannot_be_reproduced_regression_and_tree_drift_fails(self):
        tree = self.tree()
        def unavailable(args, **kwargs):
            kwargs['stdout'].write(b'sandbox unavailable\n')
            return subprocess.CompletedProcess(args, 1)
        with patch.object(S.subprocess, 'run', side_effect=unavailable):
            with self.assertRaisesRegex(ValueError, 'did-not-run-tests'): S.sandbox(tree, {}, self.root / 'unavailable.log')
        def drift(args, **kwargs):
            (tree / 'source/calculation.mjs').write_text('unexpected host drift')
            kwargs['stdout'].write(b'candidate_checks_started=true\ncandidate_case_finished=0\n')
            return subprocess.CompletedProcess(args, 0)
        with patch.object(S.subprocess, 'run', side_effect=drift):
            with self.assertRaisesRegex(ValueError, 'snapshot-changed'): S.sandbox(tree, {}, self.root / 'drift.log')

    @staticmethod
    def service_result(args, *, active=False, missing=False, returncode=0, job='0'):
        return subprocess.CompletedProcess(args, returncode, stdout=(
            'LoadState=' + ('not-found' if missing else 'loaded') + '\nActiveState=' + ('active' if active else 'inactive') +
            '\nMainPID=' + ('123' if active else '0') + '\nControlPID=0\nJob=' + job + '\n'), stderr='')

    def test_unit_is_derived_only_from_the_exact_canonical_log_path(self):
        log = self.root / 'checks.log'
        expected = 'joao-candidate-check-' + hashlib.sha256(str(log).encode()).hexdigest() + '.service'
        self.assertEqual(S.unit_for_log(log), expected)
        log.write_text('Existing partial log is not interpreted as a unit name.')
        log.chmod(0o600)
        self.assertEqual(S.unit_for_log(log), expected)
        self.assertNotEqual(S.unit_for_log(self.root / 'another.log'), expected)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): S.unit_for_log(alias / 'checks.log')
        with self.assertRaises(ValueError): S.unit_for_log(Path('joao.service'))
        log.unlink()
        log.symlink_to(self.root / 'absent')
        with self.assertRaises(ValueError): S.unit_for_log(log)

    def test_stop_incomplete_targets_only_derived_unit_and_confirms_quiescence(self):
        log = self.root / 'checks.log'
        expected = S.unit_for_log(log)
        calls = []
        def execute(args, **kwargs):
            calls.append(args)
            self.assertEqual(args[-1], expected)
            self.assertLessEqual(kwargs['timeout'], 10)
            if args[2] == 'show': return self.service_result(args, active=len(calls) == 1)
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        with patch.object(S.subprocess, 'run', side_effect=execute):
            self.assertEqual(S.stop_incomplete(log), dict(unit=expected, stopped=True))
        self.assertEqual([args[2] for args in calls], ['show', 'stop', 'show'])
        self.assertFalse(log.exists())

    def test_stop_incomplete_accepts_missing_or_idle_only_from_structured_status(self):
        for missing, code in [(False, 0), (True, 1)]:
            with self.subTest(missing=missing), patch.object(S.subprocess, 'run',
                    side_effect=lambda args, **_kw: self.service_result(args, missing=missing, returncode=code)) as execute:
                self.assertFalse(S.stop_incomplete(self.root / 'checks.log')['stopped'])
                self.assertEqual(execute.call_count, 1)
        with patch.object(S.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stdout='', stderr='Unit not loaded')) as execute:
            with self.assertRaisesRegex(ValueError, 'status-invalid'): S.stop_incomplete(self.root / 'checks.log')
            self.assertEqual(execute.call_count, 1)

    def test_stop_does_not_claim_quiescence_when_process_or_job_remains(self):
        for active, job in [(True, '0'), (False, '55 /org/freedesktop/systemd1/job/55')]:
            with self.subTest(active=active, job=job):
                def execute(args, **_kw):
                    return self.service_result(args, active=active, job=job) if args[2] == 'show' else subprocess.CompletedProcess(args, 0, stdout='', stderr='')
                with patch.object(S.subprocess, 'run', side_effect=execute):
                    with self.assertRaisesRegex(ValueError, 'not-quiescent'): S.stop_incomplete(self.root / 'checks.log')

    def test_stop_shares_one_ten_second_budget(self):
        calls = []
        def execute(args, **kwargs):
            calls.append((args, kwargs['timeout']))
            return self.service_result(args, active=True) if args[2] == 'show' else subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        with patch.object(S.time, 'monotonic', side_effect=[0, 1, 7, 11]), patch.object(S.subprocess, 'run', side_effect=execute):
            with self.assertRaisesRegex(ValueError, 'stop-deadline'): S.stop_incomplete(self.root / 'checks.log')
        self.assertEqual([timeout for _args, timeout in calls], [9, 3])

    def test_timeout_stops_fixed_unit_without_reclassifying_it_as_assertion(self):
        tree = self.tree()
        calls = []
        def execute(args, **kwargs):
            calls.append(args)
            if len(calls) == 1: raise subprocess.TimeoutExpired(args, 260)
            if args[2] == 'show': return self.service_result(args, active=len(calls) == 2)
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        with patch.object(S.subprocess, 'run', side_effect=execute):
            self.assertEqual(S.sandbox(tree, {}, self.root / 'timeout.log'), 124)
        self.assertEqual(calls[2][:3], ['/usr/bin/systemctl', '--user', 'stop'])
        self.assertEqual(calls[2][3], S.unit_for_log(self.root / 'timeout.log'))

    @unittest.skipUnless(os.environ.get('JOAO_CANDIDATE_E2E') == '1' and os.environ.get('JOAO_CANDIDATE_SANDBOX') != '1',
                         'Explicit real sandbox probe is run separately by the host')
    def test_real_isolation_and_unchanged_new_test_fails_before_passes_after(self):
        sources = {'source/calculation.mjs': material('export const value=1;\n'),
                   'source/calculation.py': material('VALUE = 1\n'),
                   'tests/repair-calculation.test.mjs': material(self.proposal['files'][1]['content']),
                   'tests/repair-calculation.py': material('import runpy, unittest\nclass Calculation(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(runpy.run_path("/workspace/source/calculation.py")["VALUE"], 2)\n')}
        tree = self.root / 'real-tree'
        S.snapshot(dict(sources=sources), tree)
        self.assertEqual(S.sandbox(tree, {}, self.root / 'isolation.log'), 0)
        self.assertFalse(S.stop_incomplete(self.root / 'isolation.log')['stopped'])
        test_name = 'tests/repair-calculation.test.mjs'
        tests = {name: sources[name]['sha256'] for name in [test_name, 'tests/repair-calculation.py']}
        self.assertEqual(S.sandbox(tree, tests, self.root / 'before.log'), 1)
        (tree / 'source/calculation.mjs').write_text('export const value=2;\n')
        (tree / 'source/calculation.py').write_text('VALUE = 2\n')
        self.assertEqual(S.sandbox(tree, tests, self.root / 'after.log'), 0)
        self.assertEqual({name: S.retained_file(tree / name) for name in tests}, tests)
        (tree / 'tests/repair-import.test.mjs').write_text("import './does-not-exist.mjs';\n")
        missing = {'tests/repair-import.test.mjs': S.retained_file(tree / 'tests/repair-import.test.mjs')}
        self.assertEqual(S.sandbox(tree, missing, self.root / 'invalid-import.log'), 2)


if __name__ == '__main__':
    unittest.main()
