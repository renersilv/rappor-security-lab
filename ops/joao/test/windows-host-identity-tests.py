#!/usr/bin/env python3
"""Fixed host identity checks; offline fixtures never connect to the guest."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('host_identity', Path(__file__).resolve().parent.parent / 'windows-host-identity.py')
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


class HostIdentityTests(unittest.TestCase):
    def setUp(self):
        self.probe = {'__name__': 'fixture'}
        exec(compile(H.PROBE, '<fixture>', 'exec'), self.probe)
        self.uuid = '12345678-1234-1234-1234-123456789abc'
        self.reads = {
            '/proc/42/status': b'Tgid:\t40\n',
            '/proc/40/stat': ('40 (qemu) ' + ' '.join(['0'] * 19 + ['987'])).encode(),
            '/proc/40/cmdline': ('qemu\0-uuid\0' + self.uuid + '\0-netdev\0user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22\0').encode(),
            '/proc/40/net/tcp': b'header\n0: 0100007F:08AE 00000000:0000 0A 0 0 0 0 0 777\n',
        }

    def observe(self, query=None, readlink=None):
        self.probe['query'] = query or (lambda action: self.uuid if action == 'uuid' else '{"return":[{"thread-id":42}]}')
        self.probe['read'] = lambda path: self.reads[str(path)]
        with patch('os.readlink', side_effect=readlink or (lambda path: '/usr/bin/qemu-system-x86_64' if str(path).endswith('/exe') else 'socket:[777]')), \
                patch.object(Path, 'iterdir', return_value=iter([Path('/proc/40/fd/9')])):
            return self.probe['observe']()

    def test_exact_identity_and_loopback_owner_are_bound(self):
        result = self.observe()
        self.assertEqual(result['result'], 'verified')
        self.assertEqual((result['domainUuid'], result['tgid'], result['processStartTicks']), (self.uuid, 40, 987))
        self.assertEqual((result['listenerAddress'], result['listenerPort'], result['guestPort']), ('127.0.0.1', 2222, 22))
        self.assertEqual(result['socketInode'], '777')
        self.assertFalse(result['guestCommandExecuted'])
        self.assertFalse(result['vmMutated'])

    def test_permission_failure_is_sanitized_not_a_verified_identity(self):
        result = self.observe(readlink=lambda _: (_ for _ in ()).throw(PermissionError(13, 'private detail')))
        self.assertEqual(result['result'], 'inconclusive')
        self.assertEqual(result['failedStage'], 'executable_identity')
        self.assertEqual(result['errorNumber'], 13)
        self.assertNotIn('private detail', json.dumps(result))

    def test_wrong_uuid_forward_executable_and_listener_are_rejected(self):
        for path, content in [('/proc/40/cmdline', b'qemu\0-uuid\0wrong\0'),
                              ('/proc/40/net/tcp', b'header\n'),
                              ('/proc/40/cmdline', self.reads['/proc/40/cmdline'].replace(b'127.0.0.1', b'0.0.0.0'))]:
            with self.subTest(path=path), patch.dict(self.reads, {path: content}):
                self.assertEqual(self.observe()['result'], 'inconclusive')
        self.assertEqual(self.observe(readlink=lambda _: '/other/executable')['result'], 'inconclusive')
        self.assertEqual(self.observe(readlink=lambda p: '/usr/bin/qemu-system-x86_64' if str(p).endswith('/exe') else 'socket:[999]')['result'], 'inconclusive')

    def test_changed_process_generation_is_inconclusive(self):
        def link(path):
            if str(path).endswith('/exe'):
                self.reads['/proc/40/stat'] = self.reads['/proc/40/stat'].replace(b'987', b'988')
                return '/usr/bin/qemu-system-x86_64'
            return 'socket:[777]'
        self.assertEqual(self.observe(readlink=link)['result'], 'inconclusive')

    def test_timeout_stops_only_its_transient_unit_and_stays_inconclusive(self):
        with patch.object(sys, 'argv', ['helper']), \
                patch.object(subprocess, 'run', side_effect=[subprocess.TimeoutExpired('fixture', 50), subprocess.CompletedProcess([], 0)]) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(H.main(), 2)
        args = run.call_args_list[1].args[0]
        self.assertEqual(args[:3], ['/usr/bin/systemctl', '--user', 'stop'])
        self.assertEqual('--unit=' + args[3], next(arg for arg in run.call_args_list[0].args[0] if arg.startswith('--unit=')))
        self.assertEqual(json.loads(output.getvalue())['error'], 'host-identity-timeout')

    def test_query_allowlist_has_only_two_fixed_read_only_commands(self):
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as run:
            self.probe['query']('uuid')
            self.probe['query']('cpus')
            with self.assertRaises(KeyError):
                self.probe['query']('start')
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/usr/bin/virsh', '--connect', 'qemu:///session', 'domuuid', 'joao-windows-x64'],
            ['/usr/bin/virsh', '--connect', 'qemu:///session', 'qemu-monitor-command', 'joao-windows-x64', '{"execute":"query-cpus-fast"}']])
        self.assertEqual(run.call_args.kwargs['env']['LIBVIRT_AUTOSTART'], '0')

    def test_service_command_is_fixed_and_resource_bounded(self):
        args = H.command('fixture.service')
        self.assertNotIn('--scope', args)
        for arg in ['--property=MemoryMax=256M', '--property=MemorySwapMax=0', '--property=TasksMax=32',
                    '--property=CPUQuota=100%', '--property=RuntimeMaxSec=40s', '--property=TimeoutStopSec=5s']:
            self.assertIn(arg, args)
        self.assertEqual(args[-6:], ['/usr/bin/python3', '-I', '-c', H.LOADER, H.PROBE, H.PROBE_SHA256])

    def test_source_pin_rejects_modified_payload_before_service_launch(self):
        with patch.object(H, 'PROBE', H.PROBE + '\nraise RuntimeError("changed")'), patch.object(subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'source-pin-mismatch'):
                H.command('fixture.service')
        run.assert_not_called()

    def test_child_loader_checks_retained_bytes_before_execution(self):
        result = subprocess.run([sys.executable, '-I', '-c', H.LOADER, 'print("must-not-run")', H.PROBE_SHA256], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_external_arguments_cannot_select_a_command_or_domain(self):
        with patch.object(sys, 'argv', ['helper', '--domain=other']), patch.object(subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main(), 2)
        run.assert_not_called()

    def test_manager_failure_cannot_be_reported_as_verified(self):
        with patch.object(sys, 'argv', ['helper']), \
                patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'private diagnostics', b'other detail')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(H.main(), 2)
        self.assertEqual(json.loads(output.getvalue()), dict(result='inconclusive', error='host-identity-unavailable'))


if __name__ == '__main__':
    unittest.main()
