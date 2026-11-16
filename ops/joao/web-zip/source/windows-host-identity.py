#!/usr/bin/env python3
"""Observe only the existing Windows domain identity across the worker boundary."""
import hashlib
import json
import subprocess
import sys
import uuid

# This reviewed payload is the complete host-side authority. It accepts no input.
PROBE = r'''
import datetime, json, os, re, subprocess
from pathlib import Path

DOMAIN = 'joao-windows-x64'
EXE = '/usr/bin/qemu-system-x86_64'

def read(path):
    with Path(path).open('rb') as stream:
        data = stream.read(262145)
    if len(data) > 262144:
        raise ValueError('observation-limit')
    return data

def query(action):
    commands = {
        'uuid': ['domuuid', DOMAIN],
        'cpus': ['qemu-monitor-command', DOMAIN, '{"execute":"query-cpus-fast"}'],
    }
    env = {key: os.environ[key] for key in ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS') if key in os.environ}
    env.update(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', LIBVIRT_AUTOSTART='0')
    result = subprocess.run(['/usr/bin/virsh', '--connect', 'qemu:///session', *commands[action]],
                            env=env, capture_output=True, timeout=12)
    if result.returncode or len(result.stdout) > 262144:
        raise ValueError('domain-query-failed')
    return result.stdout.decode().strip()

def observe():
    stage = 'domain_identity'
    receipt = dict(schemaVersion=1, domain=DOMAIN, guestCommandExecuted=False,
                   vmMutated=False, permissionsChanged=False)
    try:
        domain_uuid = query('uuid')
        if not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', domain_uuid):
            raise ValueError('invalid-domain-uuid')
        rows = json.loads(query('cpus'))['return']
        if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
            raise ValueError('invalid-domain-cpus')
        tgids = set()
        stage = 'process_identity'
        for row in rows:
            tid = row['thread-id']
            if type(tid) is not int or tid <= 0:
                raise ValueError('invalid-domain-thread')
            status = read(f'/proc/{tid}/status').decode()
            tgids.add(int(next(line.split(':', 1)[1] for line in status.splitlines() if line.startswith('Tgid:'))))
        if len(tgids) != 1 or min(tgids) <= 0:
            raise ValueError('ambiguous-domain-process')
        tgid = tgids.pop()
        proc = Path('/proc') / str(tgid)
        def generation():
            return int(read(proc / 'stat').decode().rsplit(') ', 1)[1].split()[19])
        before = generation()
        stage = 'executable_identity'
        if os.readlink(proc / 'exe') != EXE:
            raise ValueError('executable-mismatch')
        args = read(proc / 'cmdline').decode().strip('\0').split('\0')
        if args.count('-uuid') != 1 or args[args.index('-uuid') + 1] != domain_uuid:
            raise ValueError('domain-uuid-mismatch')
        if not any(re.search(r'hostfwd=tcp:127\.0\.0\.1:2222-:22(?:,|$)', arg) for arg in args):
            raise ValueError('exact-forward-missing')
        stage = 'listener_identity'
        entries = [line.split() for line in read(proc / 'net/tcp').decode().splitlines()[1:]]
        inodes = {entry[9] for entry in entries if entry[1] == '0100007F:08AE' and entry[3] == '0A'}
        if len(inodes) != 1:
            raise ValueError('ambiguous-loopback-listener')
        inode = next(iter(inodes))
        if not inode.isdigit():
            raise ValueError('invalid-listener-inode')
        owned = False
        for count, fd in enumerate((proc / 'fd').iterdir(), 1):
            if count > 1024:
                raise ValueError('descriptor-limit')
            try:
                if os.readlink(fd) == f'socket:[{inode}]':
                    owned = True
                    break
            except FileNotFoundError:
                pass
        if not owned:
            raise ValueError('listener-not-owned-by-domain-process')
        stage = 'process_generation'
        if generation() != before:
            raise ValueError('process-generation-changed')
        receipt.update(result='verified', domainUuid=domain_uuid, tgid=tgid,
                       processStartTicks=before, executable=EXE, generationStable=True,
                       listenerAddress='127.0.0.1', listenerPort=2222, guestPort=22,
                       socketInode=inode, listenerOwnedByExactDomainProcess=True)
    except (OSError, ValueError, KeyError, IndexError, StopIteration, TypeError, subprocess.SubprocessError) as error:
        receipt.update(result='inconclusive', failedStage=stage,
                       errorType=type(error).__name__, errorNumber=getattr(error, 'errno', None))
    receipt['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return receipt

if __name__ == '__joao_host_identity__':
    receipt = observe()
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(0 if receipt['result'] == 'verified' else 2)
'''
PROBE_SHA256 = '586bb536d9cd18f576839188af71501e0042e04766b99281351e9ed5852041aa'
LOADER = ('import hashlib,sys; source=sys.argv[1]; '
          'assert hashlib.sha256(source.encode()).hexdigest()==sys.argv[2]; '
          'exec(compile(source,"<fixed-windows-host-identity>","exec"),'
          '{"__name__":"__joao_host_identity__"})')


def command(unit):
    if hashlib.sha256(PROBE.encode()).hexdigest() != PROBE_SHA256:
        raise ValueError('host-identity-source-pin-mismatch')
    return ['/usr/bin/systemd-run', '--user', '--wait', '--pipe', '--quiet', '--collect',
            '--service-type=exec', '--unit=' + unit, '--property=MemoryMax=256M',
            '--property=MemorySwapMax=0', '--property=TasksMax=32', '--property=CPUQuota=100%',
            '--property=RuntimeMaxSec=40s', '--property=TimeoutStopSec=5s',
            '/usr/bin/python3', '-I', '-c', LOADER, PROBE, PROBE_SHA256]


def main():
    if len(sys.argv) != 1:
        print(json.dumps(dict(result='inconclusive', error='host-identity-accepts-no-arguments')))
        return 2
    unit = 'joao-windows-host-identity-' + uuid.uuid4().hex + '.service'
    try:
        result = subprocess.run(command(unit), capture_output=True, timeout=50)
        if len(result.stdout) > 4096:
            raise ValueError('host-identity-invalid-receipt')
        receipt = json.loads(result.stdout)
        if (not isinstance(receipt, dict) or receipt.get('domain') != 'joao-windows-x64' or
                receipt.get('result') not in {'verified', 'inconclusive'} or
                result.returncode != (0 if receipt['result'] == 'verified' else 2)):
            raise ValueError('host-identity-invalid-receipt')
        receipt['sourceSha256'] = PROBE_SHA256
        print(json.dumps(receipt, sort_keys=True))
        return result.returncode
    except subprocess.TimeoutExpired:
        try:
            subprocess.run(['/usr/bin/systemctl', '--user', 'stop', unit], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass  # The service RuntimeMaxSec remains the independent final bound.
        error = 'host-identity-timeout'
    except (OSError, ValueError, subprocess.SubprocessError):
        error = 'host-identity-unavailable'
    print(json.dumps(dict(result='inconclusive', error=error)))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
