#!/usr/bin/env python3
"""Bounded candidate-only source proposals and offline Node/Python validation.

snapshot(bundle, destination) returns the copied relative-path/hash map.
validate_proposal(proposal, bundle['sources']) returns (source_edits, new_tests),
where both lists contain only {path, content}. Existing test fixture edits are
limited to makeSnapshots; every byte outside that region remains unchanged.
sandbox(tree, {test_path: test_sha256}, log_path) returns 0 for passing assertions,
1 for a reproduced assertion failure, 2 for invalid setup/collection, or 124 for a
bounded timeout. Use the SAME new-test hash map before and after. These results
are inputs to independent review, not authority to install or resume anything.
unit_for_log(log_path) deterministically binds the service name to its canonical
log path. stop_incomplete(log_path) returns {unit, stopped} only after observing
quiescence, under one ten-second budget; the host must supply its saved run intent.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time

MAX_FILES = 8
MAX_FILE_BYTES = 250000
MAX_PROPOSAL_BYTES = 500000
MAX_SNAPSHOT_FILES = 256
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
HASH = re.compile(r'[a-f0-9]{64}')
NEW_TEST = re.compile(r'tests/repair-[a-z0-9][a-z0-9-]*\.(?:test\.mjs|py)')
SOURCE = re.compile(r'source/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:mjs|js|py|ps1|sh)')
PROTECTED_WORD = re.compile(r'(?:^|[._-])(?:test|tests|verify|verification|check|checks|package|manifest|review|contract|authorization|ledger|checkpoint|sandbox|recovery)(?:[._-]|$)', re.I)
FIXTURE_START = 'const makeSnapshots = '
FIXTURE_END = '\nconst observation = '


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_name(name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,239}', name), 'candidate-path-invalid')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and '..' not in path.parts and
            not any(part.startswith('.') or part in {'node_modules', '__pycache__'} for part in path.parts), 'candidate-path-invalid')
    return name


def source_material(sources):
    require(isinstance(sources, dict) and 1 <= len(sources) <= MAX_SNAPSHOT_FILES, 'candidate-sources-invalid')
    retained, total = {}, 0
    for name, value in sources.items():
        safe_name(name)
        require(isinstance(value, dict) and {'content', 'sha256'} <= set(value) <= {'content', 'sha256', 'omitted'} and
                (value.get('omitted') is None or value['omitted'] is False), 'candidate-source-binding-invalid')
        text = value['content']
        require(isinstance(text, str) and '\x00' not in text and isinstance(value['sha256'], str) and HASH.fullmatch(value['sha256']),
                'candidate-source-binding-invalid')
        raw = text.encode('utf-8')
        require(len(raw) <= MAX_FILE_BYTES and digest(raw) == value['sha256'], 'candidate-source-hash-mismatch')
        total += len(raw)
        require(total <= MAX_SNAPSHOT_BYTES, 'candidate-snapshot-too-large')
        retained[name] = raw
    return retained


def canonical_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'candidate-directory-not-canonical')
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid(), 'candidate-directory-invalid')
    return path


def write_exclusive(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def snapshot(bundle, destination):
    require(isinstance(bundle, dict), 'candidate-bundle-invalid')
    retained = source_material(bundle.get('sources'))
    destination = Path(destination)
    canonical_directory(destination.parent)
    require(destination.is_absolute() and destination.name not in {'', '.', '..'}, 'candidate-snapshot-path-invalid')
    destination.mkdir(mode=0o700, exist_ok=False)
    canonical_directory(destination)
    for name, raw in retained.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        canonical_directory(path.parent)
        write_exclusive(path, raw)
    return {name: digest(raw) for name, raw in retained.items()}


def fixture_edit(original, replacement):
    require(original.count(FIXTURE_START) == replacement.count(FIXTURE_START) == 1 and
            original.count(FIXTURE_END) == replacement.count(FIXTURE_END) == 1, 'candidate-fixture-region-invalid')
    start, end = original.index(FIXTURE_START), original.index(FIXTURE_END)
    new_start, new_end = replacement.index(FIXTURE_START), replacement.index(FIXTURE_END)
    first_test = re.search(r'^test\(', original, re.M)
    require(first_test is not None and start < end < first_test.start() and new_start < new_end,
            'candidate-fixture-region-invalid')
    require(original[:start] == replacement[:new_start] and original[end:] == replacement[new_end:],
            'candidate-existing-test-changed')


def expand_proposal(proposal, original_sources):
    """Materialize bounded exact edits before applying the unchanged safety checks."""
    original = source_material(original_sources)
    require(isinstance(proposal, dict) and set(proposal) == {'disposition', 'diagnosis', 'files'},
            'candidate-proposal-invalid')
    require(len(json.dumps(proposal, ensure_ascii=False).encode()) <= 60000, 'candidate-patch-output-too-large')
    files = proposal['files']
    require(isinstance(files, list) and len(files) <= MAX_FILES, 'candidate-proposal-files-invalid')
    expanded = []
    names = set()
    for item in files:
        require(isinstance(item, dict) and 'path' in item, 'candidate-patch-file-invalid')
        name = safe_name(item['path'])
        require(name not in names, 'candidate-proposal-duplicate')
        names.add(name)
        if NEW_TEST.fullmatch(name):
            require(set(item) == {'path', 'content'} and isinstance(item['content'], str)
                    and len(item['content'].encode()) <= 20000, 'candidate-new-test-content-invalid')
            expanded.append(dict(item))
            continue
        require(set(item) == {'path', 'patches'} and SOURCE.fullmatch(name) and name in original,
                'candidate-patch-source-invalid')
        patches = item['patches']
        require(isinstance(patches, list) and 1 <= len(patches) <= 12, 'candidate-patches-invalid')
        text = original[name].decode('utf-8')
        edits = []
        for patch in patches:
            require(isinstance(patch, dict) and set(patch) == {'before', 'after'}, 'candidate-patch-invalid')
            before, after = patch['before'], patch['after']
            require(isinstance(before, str) and isinstance(after, str) and before and before != after
                    and '\x00' not in before + after and len((before + after).encode()) <= 24000,
                    'candidate-patch-content-invalid')
            start = text.find(before)
            require(start >= 0 and text.find(before, start + 1) == -1, 'candidate-patch-match-not-unique')
            edits.append((start, start + len(before), after))
        edits.sort()
        require(all(left[1] <= right[0] for left, right in zip(edits, edits[1:])), 'candidate-patches-overlap')
        for start, end, after in reversed(edits):
            text = text[:start] + after + text[end:]
        expanded.append(dict(path=name, content=text))
    result = dict(proposal, files=expanded)
    # No patch can bypass source ownership, fixture bounds or immutable test cases.
    validate_proposal(result, original_sources)
    return result


def validate_proposal(proposal, original_sources):
    original = source_material(original_sources)
    require(isinstance(proposal, dict) and set(proposal) == {'disposition', 'diagnosis', 'files'}, 'candidate-proposal-invalid')
    require(proposal['disposition'] in ('repair', 'unrepairable'), 'candidate-disposition-invalid')
    require(isinstance(proposal['diagnosis'], str) and 20 <= len(proposal['diagnosis']) <= 3000 and
            '\x00' not in proposal['diagnosis'], 'candidate-diagnosis-invalid')
    files = proposal['files']
    require(isinstance(files, list) and len(files) <= MAX_FILES, 'candidate-proposal-files-invalid')
    names, edits, tests, total = set(), [], [], 0
    for item in files:
        require(isinstance(item, dict) and set(item) == {'path', 'content'}, 'candidate-proposal-file-invalid')
        name = safe_name(item['path'])
        require(name not in names, 'candidate-proposal-duplicate')
        names.add(name)
        text = item['content']
        require(isinstance(text, str) and '\x00' not in text, 'candidate-proposal-content-invalid')
        raw = text.encode('utf-8')
        require(1 <= len(raw) <= MAX_FILE_BYTES, 'candidate-proposal-content-invalid')
        total += len(raw)
        require(total <= MAX_PROPOSAL_BYTES, 'candidate-proposal-too-large')
        if NEW_TEST.fullmatch(name):
            require(name not in original, 'candidate-existing-test-overwrite')
            tests.append(dict(path=name, content=text))
            continue
        require(SOURCE.fullmatch(name) and name in original, 'candidate-source-outside-allowlist')
        require(raw != original[name], 'candidate-source-unchanged')
        if name.endswith('.test.mjs'):
            fixture_edit(original[name].decode('utf-8'), text)
        else:
            require(not PROTECTED_WORD.search(PurePosixPath(name).name), 'candidate-source-protected')
        edits.append(dict(path=name, content=text))
    if proposal['disposition'] == 'repair':
        require(tests and any(not item['path'].endswith('.test.mjs') for item in edits),
                'candidate-repair-needs-implementation-and-new-test')
    else:
        require(not files, 'candidate-nonrepair-has-files')
    return edits, tests


def retained_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1 and
                before.st_size <= MAX_FILE_BYTES and Path(f'/proc/self/fd/{descriptor}').resolve() == path,
                'candidate-snapshot-file-invalid')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        after, current = os.fstat(descriptor), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, key) == getattr(after, key) == getattr(current, key) for key in fields) and
                len(raw) == before.st_size and Path(f'/proc/self/fd/{descriptor}').resolve() == path,
                'candidate-snapshot-changed')
        return digest(raw)
    finally:
        os.close(descriptor)


def tree_hashes(root):
    root = canonical_directory(root)
    files, total = {}, 0
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        canonical_directory(Path(directory))
        for name in subdirectories:
            safe_name((Path(directory) / name).relative_to(root).as_posix())
            canonical_directory(Path(directory) / name)
        for name in names:
            path = Path(directory) / name
            relative = safe_name(path.relative_to(root).as_posix())
            files[relative] = retained_file(path)
            total += path.stat().st_size
            require(len(files) <= MAX_SNAPSHOT_FILES and total <= MAX_SNAPSHOT_BYTES, 'candidate-snapshot-too-large')
    require(files, 'candidate-snapshot-empty')
    return files


# This driver is host-owned. Candidate stdout is evidence for review, never a command.
DRIVER = r'''
import importlib.util,json,os,pathlib,re,subprocess,sys,time
commands=json.loads(sys.argv[1]); deadline=time.monotonic()+240
print('candidate_checks_started=true',flush=True)
if not commands:
 assert not pathlib.Path('/home').exists() and not pathlib.Path('/run').exists()
 assert os.environ['HOME']=='/tmp' and len(list(pathlib.Path('/proc').glob('[0-9]*')))<=2
 assert len(pathlib.Path('/proc/net/route').read_text().splitlines())==1
 assert 'NoNewPrivs:\t1' in pathlib.Path('/proc/self/status').read_text()
 assert any(line.split()[1]=='/workspace' and 'ro' in line.split()[3].split(',') for line in pathlib.Path('/proc/mounts').read_text().splitlines())
 print('candidate_case_finished=0',flush=True); sys.exit(0)
python_loader = """import importlib.util,json,sys,unittest
spec=importlib.util.spec_from_file_location('candidate_regression',sys.argv[1])
module=importlib.util.module_from_spec(spec)
try:
 spec.loader.exec_module(module)
 suite=unittest.defaultTestLoader.loadTestsFromModule(module)
 result=unittest.TextTestRunner(verbosity=2,stream=sys.stdout).run(suite)
 status=2 if result.errors or result.skipped or not result.testsRun else (1 if result.failures else 0)
 print('candidate_python_result='+json.dumps(dict(status=status,tests=result.testsRun)),flush=True)
 sys.exit(status)
except Exception:
 print('candidate_python_result='+json.dumps(dict(status=2,tests=0)),flush=True);sys.exit(2)
"""
status=0
for name in commands:
 remaining=deadline-time.monotonic()
 if remaining<=0: sys.exit(124)
 path='/workspace/'+name
 argv=['/usr/bin/node','--test','--experimental-test-isolation=none','--test-concurrency=1','--test-reporter=tap',path] if name.endswith('.test.mjs') else ['/usr/bin/python3','-I','-B','-c',python_loader,path]
 try:
  p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=min(60,remaining))
 except subprocess.TimeoutExpired:
  print('candidate_case_finished=124',flush=True);sys.exit(124)
 output=p.stdout.decode('utf-8','replace')
 if len(p.stdout)>1048576: print('candidate_case_finished=2',flush=True);sys.exit(2)
 print(output,end='',flush=True)
 if name.endswith('.test.mjs'):
  counts={key:int(value) for key,value in re.findall(r'^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$',output,re.M)}
  collected=counts.get('tests',0)>0 and not any(counts.get(k,0) for k in ('cancelled','skipped','todo'))
  invalid=bool(re.search(r'ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|SyntaxError:|ReferenceError:|ERR_UNKNOWN_FILE_EXTENSION',output))
  case=0 if p.returncode==0 and collected and not invalid and counts.get('fail')==0 else 1 if p.returncode!=0 and collected and not invalid and "code: 'ERR_ASSERTION'" in output else 2
 else:
  markers=re.findall(r'^candidate_python_result=(.+)$',output,re.M)
  try:
   result=json.loads(markers[-1]);case=result['status'] if result['status'] in (0,1) and result['tests']>0 and p.returncode==result['status'] else 2
  except Exception: case=2
 print('candidate_case_finished='+str(case),flush=True)
 if case==2: sys.exit(2)
 status=max(status,case)
sys.exit(status)
'''


def service_environment():
    environment = {key: os.environ[key] for key in ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS') if key in os.environ}
    environment.update(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C')
    return environment


def unit_for_log(log_path):
    path = Path(log_path)
    canonical_directory(path.parent)
    require(path.is_absolute() and path.resolve(strict=False) == path, 'candidate-log-path-invalid')
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and
                metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600, 'candidate-log-file-invalid')
    return 'joao-candidate-check-' + digest(str(path).encode('utf-8')) + '.service'


def stop_incomplete(log_path):
    """Stop only the deterministic check unit; the caller must hold its saved run intent."""
    unit = unit_for_log(log_path)
    environment = service_environment()
    deadline = time.monotonic() + 10

    def execute(arguments):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'candidate-stop-deadline')
        return subprocess.run(['/usr/bin/systemctl', '--user', *arguments, unit],
                              capture_output=True, text=True, env=environment, timeout=remaining)

    def observe():
        result = execute(['show', '--all', '--no-pager',
                          '--property=LoadState,ActiveState,MainPID,ControlPID,Job'])
        fields = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition('=')
            require(separator and key not in fields, 'candidate-stop-status-invalid')
            fields[key] = value
        require(set(fields) == {'LoadState', 'ActiveState', 'MainPID', 'ControlPID', 'Job'}, 'candidate-stop-status-invalid')
        require(fields['LoadState'] in {'loaded', 'not-found'} and
                (result.returncode == 0 or fields['LoadState'] == 'not-found') and
                fields['ActiveState'] in {'active', 'activating', 'reloading', 'deactivating', 'inactive', 'failed'} and
                fields['MainPID'].isdigit() and fields['ControlPID'].isdigit(), 'candidate-stop-status-invalid')
        quiet = fields['ActiveState'] in {'inactive', 'failed'} and fields['MainPID'] == '0' and fields['ControlPID'] == '0' and fields['Job'] in {'', '0'}
        require(fields['LoadState'] != 'not-found' or quiet, 'candidate-stop-status-invalid')
        return quiet

    if observe():
        return dict(unit=unit, stopped=False)
    stopped = execute(['stop'])
    # A unit can disappear between the observation and stop. Only a fresh structured
    # quiescent observation, never an error-message substring, permits completion.
    require(observe(), 'candidate-stop-not-quiescent')
    require(stopped.returncode in (0, 1, 5), 'candidate-stop-failed')
    return dict(unit=unit, stopped=True)


def sandbox(tree, tests, log_path):
    tree = canonical_directory(tree)
    before = tree_hashes(tree)
    require(isinstance(tests, dict) and len(tests) <= 32, 'candidate-test-bindings-invalid')
    for name, expected in tests.items():
        safe_name(name)
        require(name.endswith(('.test.mjs', '.py')) and isinstance(expected, str) and HASH.fullmatch(expected) and
                before.get(name) == expected, 'candidate-test-binding-mismatch')
    log_path = Path(log_path)
    canonical_directory(log_path.parent)
    require(log_path.is_absolute() and not log_path.is_relative_to(tree), 'candidate-log-path-invalid')
    unit = unit_for_log(log_path)
    args = ['/usr/bin/systemd-run', '--user', '--wait', '--pipe', '--service-type=exec', '--quiet', '--collect', '--unit=' + unit,
            '--property=MemoryMax=1G', '--property=MemorySwapMax=0', '--property=TasksMax=64', '--property=CPUQuota=100%',
            '--property=RuntimeMaxSec=250s', '--property=TimeoutStopSec=5s', '--property=LimitFSIZE=2M',
            '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(tree), '/workspace', '--chdir', '/workspace', '--clearenv',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
            '--setenv', 'JOAO_CANDIDATE_SANDBOX', '1', '/usr/bin/python3', '-I', '-B', '-c', DRIVER, json.dumps(list(tests))]
    environment = service_environment()
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write((json.dumps(dict(schema=1,kind='candidate_validation_snapshot',unit=unit,files=before,tests=tests),sort_keys=True)+'\n').encode())
            output.flush(); os.fsync(output.fileno())
            try:
                result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, env=environment, timeout=260)
                status = result.returncode
            except subprocess.TimeoutExpired:
                stop_incomplete(log_path)
                status = 124
            output.flush(); os.fsync(output.fileno())
        require(log_path.stat().st_size <= MAX_LOG_BYTES, 'candidate-log-limit')
        log = log_path.read_text()
        require(status == 124 or ('candidate_checks_started=true\n' in log and 'candidate_case_finished=' in log),
                'candidate-sandbox-did-not-run-tests')
        require(status in (0,1,2,124), 'candidate-sandbox-execution-failed')
        return status
    finally:
        require(tree_hashes(tree) == before, 'candidate-snapshot-changed')
