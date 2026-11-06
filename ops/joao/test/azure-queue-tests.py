"""Exercise the real host binding without credentials, remote services or models."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('lab_azure', HERE / 'azure-queue.py')
QUEUE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUEUE)


class QueueBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.adapter = self.root / 'adapter.py'
        self.adapter.write_text('''import json,sys
from pathlib import Path
args=sys.argv
Path(__file__).with_suffix('.args').write_text(json.dumps(args))
command=args[args.index('--state-dir')+2]
if command == 'list': print('[305]')
elif command == 'capture': print('[307, 302]')
elif command == 'list-retests': print(Path(__file__).with_suffix('.retests').read_text())
elif command == 'show': print(json.dumps({'id':int(args[args.index('--work-item')+1]), 'phase':'doing'}))
else: print('{}')
''')
        self.config = self.root / 'config.json'
        self.save(self.config, {'mode': 'active', 'azure': {'projectId': QUEUE.PROJECT}})
        self.value = dict(version=1, projectId=QUEUE.PROJECT, adapterPath=str(self.adapter),
                          adapterSha256=hashlib.sha256(self.adapter.read_bytes()).hexdigest(),
                          runnerRevision='a' * 40, configPath=str(self.config),
                          queueStateDirectory=str(self.root / 'queue'), campaign=None)
        self.persist()

    def save(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def persist(self):
        self.save(self.root / 'azure-binding.json', self.value)

    def call(self, *args):
        return subprocess.run(['python3', '-B', str(HERE / 'azure-queue.py'), str(self.root), *args],
                              capture_output=True, text=True)

    def mapped(self):
        self.value['campaign'] = dict(historicalId=19, azureWorkItemId=305,
                                     branch='joao/batch-20261016T173531Z-19-19')
        self.persist()
        for name, text in {'campaign.json': '{}', 'batch': '19\n', 'current_issue': '19\n',
                           'branch': self.value['campaign']['branch'], 'session': 'preserved-session',
                           'authorization.json': '{"consumed":2,"remaining":8}'}.items():
            (self.root / name).write_text(text)

    def test_preserved_campaign_maps_to_different_azure_id_without_writes(self):
        self.mapped()
        before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        self.assertEqual(self.call('id', '--item', '19').stdout.strip(), '305')
        self.assertEqual(self.call('campaign', '--item', '19').stdout.strip(), '19')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()})

    def test_numeric_azure_19_does_not_enable_historical_campaign(self):
        result = self.call('campaign', '--item', '19')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), 'none')

    def test_missing_binding_fails_before_adapter(self):
        (self.root / 'azure-binding.json').unlink()
        self.assertEqual(self.call('preflight').returncode, 65)
        self.assertFalse(self.adapter.with_suffix('.args').exists())

    def test_changed_adapter_is_rejected_before_execution(self):
        self.adapter.write_text(self.adapter.read_text() + '\n# changed\n')
        self.assertEqual(self.call('preflight').returncode, 65)

    def test_binding_symlink_or_public_mode_rejected(self):
        path = self.root / 'azure-binding.json'
        path.chmod(0o644)
        self.assertEqual(self.call('id', '--item', '19').returncode, 65)
        path.rename(self.root / 'original.json')
        path.symlink_to(self.root / 'original.json')
        self.assertEqual(self.call('id', '--item', '19').returncode, 65)

    def test_wrong_project_and_simulation_rejected(self):
        self.save(self.config, {'mode': 'active', 'azure': {'projectId': 'other'}})
        self.assertEqual(self.call('preflight').returncode, 65)
        self.save(self.config, {'mode': 'simulation', 'azure': {'projectId': QUEUE.PROJECT}})
        self.assertEqual(self.call('preflight').returncode, 65)

    def test_campaign_requires_explicit_mapping_and_exact_branch(self):
        (self.root / 'campaign.json').write_text('{}')
        self.assertEqual(self.call('campaign', '--item', '19').returncode, 65)
        self.mapped()
        (self.root / 'branch').write_text('joao/batch-20261016T173531Z-305-305')
        self.assertEqual(self.call('id', '--item', '19').returncode, 65)

    def test_cannot_recapture_active_historical_campaign(self):
        self.mapped()
        self.assertEqual(self.call('capture').returncode, 65)
        self.assertFalse(self.adapter.with_suffix('.args').exists())

    def test_adapter_priority_order_preserved(self):
        self.assertEqual(self.call('capture').stdout.strip(), '307\n302')

    def test_state_uses_role_checked_show_and_actual_azure_id(self):
        self.mapped()
        self.assertEqual(self.call('state', '--item', '19').stdout.strip(), 'doing')
        args = json.loads(self.adapter.with_suffix('.args').read_text())
        self.assertIn('show', args)
        self.assertEqual(args[args.index('--work-item') + 1], '305')
        self.assertEqual(args[args.index('--executor') + 1], 'joao')

    def test_transport_failure_is_not_empty_queue_or_leaked_secret(self):
        self.adapter.write_text('import sys; print("synthetic-private-error", file=sys.stderr); sys.exit(1)')
        self.value['adapterSha256'] = hashlib.sha256(self.adapter.read_bytes()).hexdigest()
        self.persist()
        result = self.call('capture')
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('synthetic-private-error', result.stderr)

    def test_finding_report_is_bound_to_actual_current_task(self):
        self.mapped()
        report = self.root / 'finding.json'
        self.save(report, dict(findingKey='case-1', title='Synthetic finding',
                               description='Sanitized reproduction.', priority=1))
        self.assertEqual(self.call('report-finding', '--item', '19', '--report-file', str(report)).returncode, 0)
        args = json.loads(self.adapter.with_suffix('.args').read_text())
        self.assertIn('report-finding', args)
        self.assertEqual(args[args.index('--work-item') + 1], '305')
        self.assertNotIn('--executor', args)
        self.assertNotIn('--origin', args)

    def test_phase_inventory_maps_without_capture(self):
        self.mapped()
        self.assertEqual(self.call('list', '--phase', 'doing').stdout.strip(), '19')
        args = json.loads(self.adapter.with_suffix('.args').read_text())
        self.assertIn('list', args)
        self.assertNotIn('capture', args)

    def retests(self):
        self.mapped()
        self.rows = [dict(id=401, revision=8, deliveryRevision=7, executor='raimundo',
                         origin='joao', priority=1, title='Synthetic retest', report={}, comments=[])]
        self.adapter.with_suffix('.retests').write_text(json.dumps(self.rows))
        result = self.call('list-retests', '--item', '19')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.rows)
        result_file = self.root / 'retest-result.json'
        self.save(result_file, dict(deliveryRevision=7, outcome='passed',
                                    summary='Controlled scenario passed.', evidence=['Synthetic fixture observation.']))
        return result_file

    def test_retest_capture_preserves_campaign_and_maps_source_task(self):
        self.mapped()
        protected = {name: (self.root / name).read_bytes() for name in
                     ['campaign.json', 'authorization.json', 'session', 'batch', 'branch']}
        self.retests()
        self.assertEqual(protected, {name: (self.root / name).read_bytes() for name in protected})
        snapshot = QUEUE.private(self.root / 'current-retests.json')
        self.assertEqual(snapshot['sourceWorkItemId'], 305)
        self.assertEqual(snapshot['findings'], {'401': 7})
        args = json.loads(self.adapter.with_suffix('.args').read_text())
        self.assertEqual(args[args.index('--work-item') + 1], '305')
        self.assertNotIn('--executor', args)

    def test_retest_result_uses_captured_revision_and_replays_without_recapture(self):
        result_file = self.retests()
        for _ in range(2):
            result = self.call('retest-result', '--item', '19', '--finding', '401', '--result-file', str(result_file))
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads(self.adapter.with_suffix('.args').read_text())
            self.assertIn('retest-result', args)
            self.assertEqual(args[args.index('--work-item') + 1], '305')
            self.assertEqual(args[args.index('--finding') + 1], '401')
            self.assertNotIn('--executor', args)

    def test_uncaptured_finding_or_revision_cannot_reach_common_adapter(self):
        result_file = self.retests()
        original = self.adapter.with_suffix('.args').read_bytes()
        self.assertEqual(self.call('retest-result', '--item', '19', '--finding', '402',
                                  '--result-file', str(result_file)).returncode, 65)
        result = json.loads(result_file.read_text())
        result['deliveryRevision'] = 8
        self.save(result_file, result)
        self.assertEqual(self.call('retest-result', '--item', '19', '--finding', '401',
                                  '--result-file', str(result_file)).returncode, 65)
        self.assertEqual(original, self.adapter.with_suffix('.args').read_bytes())

    def test_retest_requires_current_task_and_branch(self):
        result_file = self.retests()
        original = self.adapter.with_suffix('.args').read_bytes()
        (self.root / 'current_issue').write_text('20')
        self.assertEqual(self.call('list-retests', '--item', '19').returncode, 65)
        self.assertEqual(self.call('retest-result', '--item', '19', '--finding', '401',
                                  '--result-file', str(result_file)).returncode, 65)
        (self.root / 'current_issue').write_text('19')
        snapshot = QUEUE.private(self.root / 'current-retests.json')
        snapshot['branch'] = 'joao/batch-20261106T000000Z-305-305'
        self.save(self.root / 'current-retests.json', snapshot)
        self.assertEqual(self.call('retest-result', '--item', '19', '--finding', '401',
                                  '--result-file', str(result_file)).returncode, 65)
        self.assertEqual(original, self.adapter.with_suffix('.args').read_bytes())

    def test_new_finding_does_not_expand_existing_retest_snapshot(self):
        result_file = self.retests()
        self.rows.append(dict(self.rows[0], id=402))
        self.adapter.with_suffix('.retests').write_text(json.dumps(self.rows))
        self.assertEqual(self.call('retest-result', '--item', '19', '--finding', '402',
                                  '--result-file', str(result_file)).returncode, 65)
        self.assertEqual(self.call('list-retests', '--item', '19').returncode, 0)
        self.assertEqual(self.call('retest-result', '--item', '19', '--finding', '402',
                                  '--result-file', str(result_file)).returncode, 0)

    def test_retest_snapshot_transport_error_preserves_previous_evidence(self):
        self.retests()
        before = (self.root / 'current-retests.json').read_bytes()
        self.adapter.with_suffix('.retests').write_text('not-json')
        self.assertEqual(self.call('list-retests', '--item', '19').returncode, 65)
        self.assertEqual(before, (self.root / 'current-retests.json').read_bytes())

    def test_retest_capture_rejects_duplicate_foreign_or_invalid_deliveries(self):
        self.retests()
        for rows in ([self.rows[0], self.rows[0]], [dict(self.rows[0], origin='evener')],
                     [dict(self.rows[0], executor='joao')], [dict(self.rows[0], deliveryRevision=True)]):
            self.adapter.with_suffix('.retests').write_text(json.dumps(rows))
            self.assertEqual(self.call('list-retests', '--item', '19').returncode, 65)


if __name__ == '__main__':
    unittest.main()
