#!/usr/bin/env python3
"""Exercise maintenance state and the actual worker dispatch without live tools."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('maintenance', HERE / 'maintenance.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'run.lock').touch()

    def test_idempotent_hold_release_preserves_gates(self):
        gate = self.root / 'issue-retry'
        gate.write_text('preserved')
        self.assertEqual(M.change(self.root, 'hold'), 'held')
        before = (self.root / 'maintenance.json').read_bytes()
        self.assertEqual(M.change(self.root, 'hold'), 'held')
        self.assertEqual((self.root / 'maintenance.json').read_bytes(), before)
        self.assertEqual(M.change(self.root, 'release'), 'none')
        self.assertEqual(M.change(self.root, 'release'), 'none')
        self.assertEqual(gate.read_text(), 'preserved')

    def test_active_worker_refuses_state_change(self):
        with (self.root / 'run.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError):
                M.change(self.root, 'hold')
        self.assertFalse((self.root / 'maintenance.json').exists())

    def test_symlink_or_invalid_state_fails_closed(self):
        path = self.root / 'maintenance.json'
        path.symlink_to(self.root / 'missing')
        with self.assertRaises(OSError):
            M.status(self.root)
        path.unlink()
        path.write_text('{}')
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            M.status(self.root)

    def test_invalid_hold_blocks_cycle_and_status(self):
        path = self.root / 'maintenance.json'
        path.write_text('{}')
        path.chmod(0o600)
        result = self.cycle(0)
        self.assertEqual(result.returncode, 65)
        self.assertNotIn('PREFLIGHT', result.stdout)
        env = dict(os.environ, JOAO_STATE_ROOT=str(self.root))
        result = subprocess.run(['bash', str(HERE / 'control.sh'), 'status'], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 65)

    def test_hold_does_not_expire(self):
        M.change(self.root, 'hold')
        path = self.root / 'maintenance.json'
        value = json.loads(path.read_text())
        value['createdAt'] = '2000-01-01T00:00:00+00:00'
        path.write_text(json.dumps(value))
        self.assertEqual(M.status(self.root), 'held')

    def cycle(self, publication, preflight=99):
        # Execute real run_cycle. All execution lanes fail visibly if reached.
        script = r'''
set -euo pipefail
source "$1/run.sh"
recovery_flush_notice() { printf 'recovery-notices\n'; }
campaign_review_flush_notice() { printf 'campaign-notices\n'; }
publication_ready() { printf 'publication-check\n'; return "$2"; }
preflight() { printf 'PREFLIGHT\n'; return 99; }
resource_ready() { printf 'RESOURCE_CHECK\n'; return 77; }
run_cycle
'''.replace('return "$2";', 'return ' + str(publication) + ';').replace(
            'return 99;', 'return ' + str(preflight) + ';')
        env = dict(os.environ, JOAO_STATE_ROOT=str(self.root), JOAO_REPOSITORY_PATH=str(HERE.parent.parent))
        (self.root / 'campaign.json').write_text('{}')
        return subprocess.run(['bash', '-c', script, 'fixture', str(HERE)], env=env,
                              capture_output=True, text=True, timeout=10)

    def test_held_cycle_supervises_without_preflight_or_publication(self):
        M.change(self.root, 'hold')
        for _ in range(2):
            result = self.cycle(0)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('campaign-notices', result.stdout)
            self.assertNotIn('PREFLIGHT', result.stdout)
            self.assertNotIn('publication-check', result.stdout)

    def test_unpublished_cycle_supervises_without_execution(self):
        result = self.cycle(1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('campaign-notices', result.stdout)
        self.assertIn('publication-check', result.stdout)
        self.assertNotIn('PREFLIGHT', result.stdout)

    def test_released_published_cycle_still_requires_preflight(self):
        M.change(self.root, 'hold')
        M.change(self.root, 'release')
        result = self.cycle(0)
        self.assertEqual(result.returncode, 99, result.stderr)
        self.assertIn('PREFLIGHT', result.stdout)

    def test_resource_denial_prevents_queue_capture(self):
        result = self.cycle(0, preflight=0)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn('PREFLIGHT', result.stdout)
        self.assertIn('RESOURCE_CHECK', result.stdout)
        self.assertFalse((self.root / 'batch').exists())


if __name__ == '__main__':
    unittest.main()
