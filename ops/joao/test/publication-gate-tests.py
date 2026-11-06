"""Real filesystem/lock tests for the read-only candidate publication condition."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'publication-gate.py'
SPEC = importlib.util.spec_from_file_location('publication_gate', SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class PublicationGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state, self.review, self.publication = [self.root / name for name in ('state', 'review', 'publication')]
        for folder in (self.state, self.review, self.publication):
            folder.mkdir(mode=0o700)
        self.candidate = dict(version='v0.91.0', sha='9' * 40, origin='https://linux-ai2.taile60a95.ts.net:8443')
        self.campaign = dict(schema=1, issue=19, candidate=self.candidate,
                             candidateSha256=hashlib.sha256(json.dumps(self.candidate, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                             executorPasses=174, consumedAtActivation=2)
        self.save(self.state / 'campaign.json', json.dumps(self.campaign))
        self.save(self.state / 'session', 'preserved-session')
        self.save(self.review / 'current', self.candidate['sha'] + '\n')
        self.save(self.review / 'build-version', '0.91.0\n')
        self.lock = self.publication / 'main-integration.lock'
        self.save(self.lock, '')

    def save(self, path, text):
        path.write_text(text)
        path.chmod(0o600)

    def evaluate(self, candidate_file=None):
        return GATE.evaluate(self.state, self.review, self.publication, candidate_file)

    def test_exact_candidate_passes_without_mutation(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(self.evaluate(), 'selected_candidate_published')
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_new_operations_main_does_not_change_selected_candidate(self):
        self.save(self.root / 'unrelated-product-main', 'a' * 40)
        self.assertEqual(self.evaluate(), 'selected_candidate_published')

    def test_publication_reservation_rejects_regular_and_dangling_link(self):
        path = self.publication / 'publication-owner'
        self.save(path, 'pending publication')
        with self.assertRaisesRegex(GATE.GateError, 'publication_reserved'):
            self.evaluate()
        path.unlink()
        path.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(GATE.GateError, 'publication_reserved'):
            self.evaluate()

    def test_concurrent_integration_rejects_without_waiting(self):
        with self.lock.open('r') as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(GATE.GateError, 'integration_in_progress'):
                self.evaluate()
        self.assertEqual(self.evaluate(), 'selected_candidate_published')

    def test_wrong_sha_and_version_reject(self):
        self.save(self.review / 'current', 'b' * 40)
        with self.assertRaisesRegex(GATE.GateError, 'selected_candidate_not_published'):
            self.evaluate()
        self.save(self.review / 'current', self.candidate['sha'])
        self.save(self.review / 'build-version', '0.92.0')
        with self.assertRaisesRegex(GATE.GateError, 'selected_candidate_not_published'):
            self.evaluate()

    def test_missing_marker_rejects(self):
        (self.review / 'current').unlink()
        with self.assertRaises(OSError):
            self.evaluate()

    def test_candidate_hash_change_rejects(self):
        self.campaign['candidateSha256'] = '0' * 64
        self.save(self.state / 'campaign.json', json.dumps(self.campaign))
        with self.assertRaisesRegex(GATE.GateError, 'candidate_binding_changed'):
            self.evaluate()

    def test_public_or_symlink_marker_rejects(self):
        path = self.review / 'current'
        path.chmod(0o644)
        with self.assertRaisesRegex(GATE.GateError, 'invalid_private_input'):
            self.evaluate()
        path.rename(self.review / 'other')
        path.symlink_to(self.review / 'other')
        with self.assertRaises(OSError):
            self.evaluate()

    def test_explicit_candidate_cannot_override_campaign(self):
        path = self.root / 'candidate.json'
        self.save(path, json.dumps(self.candidate))
        with self.assertRaisesRegex(GATE.GateError, 'campaign_candidate_override_forbidden'):
            self.evaluate(path)
        (self.state / 'campaign.json').unlink()
        self.assertEqual(self.evaluate(path), 'selected_candidate_published')

    def test_unexpected_origin_and_oversized_input_reject(self):
        (self.state / 'campaign.json').unlink()
        path = self.root / 'candidate.json'
        self.candidate['origin'] = 'https://unrelated.invalid'
        self.save(path, json.dumps(self.candidate))
        with self.assertRaisesRegex(GATE.GateError, 'invalid_candidate'):
            self.evaluate(path)
        self.save(path, 'x' * 70000)
        with self.assertRaisesRegex(GATE.GateError, 'invalid_private_input'):
            self.evaluate(path)

    def test_cli_returns_closed_sanitized_reason(self):
        command = ['python3', '-B', str(SCRIPT), '--state-root', str(self.state), '--review-state', str(self.review), '--publication-state', str(self.publication)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), 'publication_gate=selected_candidate_published')
        self.save(self.state / 'campaign.json', 'synthetic-private-invalid-json')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), 'publication_gate=precondition_unavailable')
        self.assertNotIn('synthetic-private', result.stdout + result.stderr)

    def test_special_files_are_rejected_without_blocking(self):
        path = self.review / 'current'
        path.unlink()
        os.mkfifo(path, 0o600)
        command = ['python3', '-B', str(SCRIPT), '--state-root', str(self.state), '--review-state', str(self.review), '--publication-state', str(self.publication)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn('invalid_private_input', result.stdout)

    def test_service_uses_only_versioned_readonly_condition(self):
        service = (SCRIPT.parent / 'systemd/joao.service').read_text()
        self.assertIn('ExecCondition=/usr/bin/python3 -B %h/rappor-security-lab/ops/joao/publication-gate.py', service)
        source = SCRIPT.read_text()
        self.assertNotIn('subprocess', source)
        self.assertNotIn('urllib', source)
        self.assertNotIn('gh issue', source)
        self.assertNotIn('gh api', source)


if __name__ == '__main__':
    unittest.main()
