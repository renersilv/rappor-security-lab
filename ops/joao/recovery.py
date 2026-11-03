#!/usr/bin/env python3
"""Host-owned bounded automation repair. Models never install or change state."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ALLOWED = {'campaign-review.py', 'campaign.sh', 'stages.sh', 'stage-control.py',
           'objectives.py',
           'campaign-review-result.schema.json', 'review-result.schema.json',
           'CAMPAIGN_REVIEW_PROMPT.md', 'STAGE_REVIEW_PROMPT.md'}
MAX_REPAIRS = 2
TESTS = ['campaign-tests.py', 'campaign-review-tests.py', 'stage-tests.py',
         'objectives-tests.py', 'recovery-tests.py', 'run-tests.sh', 'campaign-review-wrapper-tests.sh']


def data(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def private(path):
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600 or
            meta.st_uid != os.getuid() or meta.st_size > 8 * 1024 * 1024):
        raise ValueError('invalid-recovery-private-file')
    return json.loads(path.read_text())


def save(path, value):
    if path.name == 'recovery.json' and isinstance(value, dict):
        value = dict(value, noticePending=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


# Keep status/notifications bootable even if a repairable module cannot import.
C = SimpleNamespace(private=private, save=save, digest=lambda path: hash_bytes(path.read_bytes()),
                    REVIEW_ROOT=Path.home() / '.config/rappor-security-lab/campaign-reviews')


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60, **kwargs).stdout.strip()


def git(repo, *args):
    return run(['git', '-C', str(repo), *args])


def immutable(path, value):
    encoded = data(value)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != encoded:
            raise ValueError('recovery-artifact-changed')
        return
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def retry(root):
    path = root / 'issue-retry'
    if path.is_symlink() or path.stat().st_mode & 0o777 != 0o600:
        raise ValueError('invalid-retry-file')
    pairs = [line.split('=', 1) for line in path.read_text().splitlines()]
    value = dict(pairs)
    if (len(value) != len(pairs) or value.get('issue') != '19' or
            value.get('suspended') != 'true' or not re.fullmatch('[a-f0-9]{64}', value.get('fingerprint', ''))):
        raise ValueError('invalid-recovery-incident')
    return value


def protected(root):
    spec = importlib.util.spec_from_file_location('recovery_campaign', HERE / 'campaign-control.py')
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    campaign = C.private(root / 'campaign.json')
    controller.bound(root, campaign)
    paths = [root / name for name in ('campaign.json', 'stage.json', 'session', 'batch',
                                     'branch', 'worktree', 'current_issue', 'base_sha') if (root / name).exists()]
    paths.append(Path(campaign['authorizationPath']))
    paths += sorted(Path(campaign['attemptsRoot']).glob('attempt-*/receipt.json'))
    return {str(path): C.digest(path) for path in paths}


def unchanged(binding):
    if any(C.digest(Path(path)) != expected for path, expected in binding.items()):
        raise ValueError('protected-state-changed')


def response(path):
    last = None
    for line in path.read_text().splitlines():
        event = json.loads(line)
        if event.get('type') in {'item.started', 'item.completed'}:
            item = event.get('item', {})
            if item.get('type') not in {'agent_message', 'reasoning'}:
                raise ValueError('recovery-model-attempted-tool-use')
            if event['type'] == 'item.completed' and item['type'] == 'agent_message':
                last = item.get('text')
    return json.loads(last or '')


def validate_proposal(value, repo):
    if not isinstance(value, dict) or set(value) != {'disposition', 'diagnosis', 'files'}:
        raise ValueError('invalid-repair-response')
    if value['disposition'] not in {'repair', 'external_action', 'unrepairable'}:
        raise ValueError('invalid-repair-disposition')
    if not isinstance(value['diagnosis'], str) or not 20 <= len(value['diagnosis']) <= 3000:
        raise ValueError('missing-repair-diagnosis')
    files = value['files']
    if not isinstance(files, list) or len(files) > 6:
        raise ValueError('invalid-repair-files')
    names = set()
    total = 0
    regressions = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {'path', 'content'}:
            raise ValueError('invalid-repair-file')
        name = item['path']
        if not isinstance(name, str) or name in names or not name.startswith('ops/joao/'):
            raise ValueError('invalid-repair-path')
        relative = name.removeprefix('ops/joao/')
        new_test = re.fullmatch(r'test/recovery-regression-[a-z0-9-]+\.(py|sh)', relative)
        if relative not in ALLOWED and not new_test:
            raise ValueError('repair-outside-allowlist')
        path = repo / name
        if path.is_symlink() or path.resolve() != path or (new_test and path.exists()):
            raise ValueError('repair-path-or-existing-test-invalid')
        content = item['content']
        if not isinstance(content, str) or not 1 <= len(content.encode()) <= 80000 or '\x00' in content:
            raise ValueError('invalid-repair-content')
        total += len(content.encode())
        if total > 220000:
            raise ValueError('repair-too-large')
        names.add(name)
        if new_test:
            regressions.append(name)
    if value['disposition'] == 'repair' and (not regressions or len(files) < 2):
        raise ValueError('repair-needs-source-and-regression')
    if value['disposition'] != 'repair' and files:
        raise ValueError('nonrepair-response-has-files')
    return regressions


def sandbox(repo, tests, log_path):
    # No host home, state, network, processes, credentials, Git mutation or VM.
    commands = []
    for name in tests:
        interpreter = ['python3', '-B'] if name.endswith('.py') else ['bash']
        commands.append(interpreter + ['/workspace/ops/joao/test/' + name])
    driver = ('import subprocess,sys\ncommands=' + repr(commands) + '\n'
              'print("recovery_checks_started=true",flush=True)\n'
              'for command in commands:\n'
              ' p=subprocess.run(command)\n'
              ' print("recovery_case_finished="+str(p.returncode),flush=True)\n'
              ' if p.returncode: sys.exit(p.returncode)\n')
    args = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(repo), '/workspace', '--chdir', '/workspace', '--clearenv',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
            '--setenv', 'JOAO_RECOVERY_SANDBOX', '1', 'python3', '-c', driver]
    unit = 'joao-recovery-check-' + uuid.uuid4().hex + '.scope'
    args = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit=' + unit,
            '--property=MemoryMax=1G', '--property=MemorySwapMax=0', '--property=TasksMax=64',
            '--property=CPUQuota=100%', '--property=RuntimeMaxSec=310s', *args]
    with log_path.open('wb') as output:
        os.fchmod(output.fileno(), 0o600)
        try:
            result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=300)
            output.flush()
            log = log_path.read_text()
            if 'recovery_checks_started=true\n' not in log or 'recovery_case_finished=' not in log:
                raise ValueError('recovery-sandbox-did-not-run-tests')
            return result.returncode
        except subprocess.TimeoutExpired:
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=20)
            return 124


def call_model(folder, name, prompt, schema, model, effort):
    prompt_path = folder / (name + '.md')
    prompt_path.write_text(prompt)
    prompt_path.chmod(0o600)
    events = folder / (name + '.jsonl')
    errors = folder / (name + '.log')
    env = {key: value for key, value in os.environ.items() if key not in {'OPENAI_API_KEY', 'CODEX_API_KEY'}}
    args = ['timeout', '--signal=TERM', '--kill-after=15s', '20m', 'codex', 'exec',
            '--ignore-user-config', '-C', str(HERE.parent.parent), '-m', model, '-s', 'read-only',
            '-c', 'approval_policy="never"', '-c', f'model_reasoning_effort="{effort}"',
            '--disable', 'shell_tool', '--disable', 'apps', '--disable', 'plugins',
            '--disable', 'remote_plugin', '--disable', 'multi_agent', '-c', 'web_search="disabled"',
            '--output-schema', str(schema), '--json', '-']
    with prompt_path.open('rb') as source, events.open('wb') as out, errors.open('wb') as err:
        os.fchmod(out.fileno(), 0o600)
        os.fchmod(err.fileno(), 0o600)
        result = subprocess.run(args, stdin=source, stdout=out, stderr=err, env=env, timeout=1220)
    if result.returncode:
        raise ValueError('recovery-model-failed')
    return response(events)


def incident_bundle(root, repo, incident):
    sources = {}
    for name in sorted(ALLOWED):
        sources['ops/joao/' + name] = (repo / 'ops/joao' / name).read_text()
    for name in TESTS:
        path = repo / 'ops/joao/test' / name
        if path.exists():
            sources['ops/joao/test/' + name] = path.read_text()
    matrix = repo / 'ops/joao/objectives.json'
    if matrix.exists():
        sources['ops/joao/objectives.json'] = matrix.read_text()
    diagnostic = {'class': incident.get('error_class'), 'fingerprint': incident['fingerprint']}
    marker = root / 'campaign-auto-review.json'
    if marker.exists():
        spec = importlib.util.spec_from_file_location('incident_review', HERE / 'campaign-review.py')
        review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(review)
        directory, value = review.job(root)
        diagnostic.update(reviewPhase=value['phase'], executorPass=value['executorPass'])
        try:
            answer = review.result(directory / 'events.jsonl', C.private(directory / 'bundle.json'))
            diagnostic['responseValidation'] = 'valid'
            diagnostic['verdict'] = answer['verdict']
        except (ValueError, KeyError, TypeError, OSError) as error:
            reason = str(error)
            diagnostic['responseValidation'] = reason if re.fullmatch('[a-z-]{1,100}', reason) else 'invalid-or-unavailable-response'
        if (directory / 'model-attempts').exists():
            diagnostic['reviewTransports'] = (directory / 'model-attempts').read_text().strip()[:2]
    return dict(incident=diagnostic, sources=sources, base=git(repo, 'rev-parse', 'HEAD'))


def apply_files(worktree, files, *, tests_only=False):
    for item in files:
        if tests_only and '/test/' not in item['path']:
            continue
        path = worktree / item['path']
        path.write_text(item['content'])


def integrate(root, repo, state):
    folder = Path(state['directory'])
    worktree = Path(state['worktree'])
    unchanged(state['protected'])
    marker_path = root / 'campaign-auto-review.json'
    if marker_path.exists() and C.private(marker_path).get('phase') == 'stalled':
        state['phase'] = 'unrepairable'
        C.save(root / 'recovery.json', state)
        immutable(folder / 'failure.json', {'reason': 'objective-stall-requires-diagnostic-replanning'})
        raise ValueError('objective-stall-requires-diagnostic-replanning')
    if C.digest(root / 'issue-retry') != state['retrySha256']:
        raise ValueError('retry-changed-before-integration')
    with (root / 'main-integration.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if git(repo, 'symbolic-ref', '--short', 'HEAD') != 'main' or git(repo, 'status', '--porcelain'):
            raise ValueError('installed-main-not-clean')
        git(repo, 'fetch', '--quiet', 'origin', 'main')
        target = git(worktree, 'rev-parse', 'HEAD')
        if target == state['base']:
            git(worktree, 'add', '--', *state['paths'])
            if git(worktree, 'write-tree') != state['reviewedTree']:
                raise ValueError('reviewed-tree-changed')
            git(worktree, 'commit', '-m', f'fix(joao-recovery): repair {state["fingerprint"][:12]}')
            target = git(worktree, 'rev-parse', 'HEAD')
        if (git(worktree, 'rev-parse', 'HEAD^{tree}') != state['reviewedTree'] or
                git(worktree, 'rev-parse', 'HEAD^') != state['base'] or git(worktree, 'status', '--porcelain')):
            raise ValueError('unreviewed-recovery-commit')
        if git(repo, 'rev-parse', 'HEAD') not in {state['base'], target} or git(repo, 'rev-parse', 'origin/main') not in {state['base'], target}:
            raise ValueError('main-advanced-during-recovery')
        state.update(target=target, phase='publishing')
        C.save(root / 'recovery.json', state)
        git(repo, 'merge', '--ff-only', target)
        git(repo, 'push', 'origin', 'main')
        unchanged(state['protected'])
        # Archive the operational gate, never a campaign/test authorization.
        immutable(folder / 'released-retry.json', dict(sha256=state['retrySha256'], content=(root / 'issue-retry').read_text(), target=target))
        grant_review_window(root, state, folder / 'released-retry.json', repo)
        state['phase'] = 'recovered'
        C.save(root / 'recovery.json', state)
        (root / 'issue-retry').unlink()


def supervise(root, repo, model, effort):
    incident = retry(root)
    old = C.private(root / 'recovery.json') if (root / 'recovery.json').exists() else None
    if old and old['fingerprint'] == incident['fingerprint'] and old['phase'] == 'recovered':
        unchanged(old['protected'])
        receipt = C.private(Path(old['directory']) / 'released-retry.json')
        if C.digest(root / 'issue-retry') != receipt['sha256'] or git(repo, 'rev-parse', 'HEAD') != receipt['target']:
            raise ValueError('recovered-gate-changed')
        (root / 'issue-retry').unlink()
        return
    if old and old['fingerprint'] == incident['fingerprint'] and old['phase'] in {'external_action', 'unrepairable'}:
        return
    if old and old['fingerprint'] == incident['fingerprint'] and old['phase'] in {'ready', 'publishing'}:
        integrate(root, repo, old)
        return
    attempts = old['attempts'] if old and old['fingerprint'] == incident['fingerprint'] else 0
    if attempts >= MAX_REPAIRS:
        raise ValueError('recovery-candidates-exhausted')
    base = git(repo, 'rev-parse', 'HEAD')
    if git(repo, 'status', '--porcelain') or git(repo, 'symbolic-ref', '--short', 'HEAD') != 'main':
        raise ValueError('recovery-requires-clean-main')
    folder = root / 'diagnostics' / 'recovery' / incident['fingerprint'] / str(attempts + 1)
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    if any(folder.iterdir()):
        raise ValueError('unbound-recovery-directory')
    state = dict(fingerprint=incident['fingerprint'], attempts=attempts + 1, phase='diagnosing',
                 directory=str(folder), base=base, retrySha256=C.digest(root / 'issue-retry'))
    try:
        state['protected'] = protected(root)
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, ImportError):
        state['phase'] = 'unrepairable'
        C.save(root / 'recovery.json', state)
        immutable(folder / 'failure.json', {'reason': 'protected-state-unverifiable'})
        return
    C.save(root / 'recovery.json', state)
    try:
        bundle = incident_bundle(root, repo, incident)
        immutable(folder / 'incident.json', bundle)
        prompt = (HERE / 'RECOVERY_PROMPT.md').read_text() + '\nIMMUTABLE INCIDENT DATA:\n' + data(bundle).decode()
        if old and Path(old['directory']).is_dir():
            prior = Path(old['directory'])
            for name in ('repair-checks.log', 'review.json', 'failure.json'):
                path = prior / name
                if path.exists():
                    prompt += '\nPRIOR ISOLATED REPAIR DIAGNOSTIC (data):\n' + path.read_text()[-12000:]
        proposal = call_model(folder, 'diagnosis', prompt, HERE / 'recovery-result.schema.json', model, effort)
        tests = validate_proposal(proposal, repo)
        immutable(folder / 'proposal.json', proposal)
        if proposal['disposition'] != 'repair':
            state['phase'] = 'external_action' if proposal['disposition'] == 'external_action' else 'unrepairable'
            C.save(root / 'recovery.json', state)
            return
        branch = f'joao/recovery-{incident["fingerprint"][:12]}-{attempts + 1}'
        worktree = folder / 'worktree'
        git(repo, 'worktree', 'add', '-b', branch, str(worktree), base)
        state.update(worktree=str(worktree), paths=[item['path'] for item in proposal['files']], phase='checking')
        C.save(root / 'recovery.json', state)
        apply_files(worktree, proposal['files'], tests_only=True)
        failing = sandbox(worktree, [Path(name).name for name in tests], folder / 'baseline-checks.log')
        if failing in {0, 124}:
            raise ValueError('new-regression-does-not-reproduce')
        apply_files(worktree, proposal['files'])
        required = [name for name in TESTS if (worktree / 'ops/joao/test' / name).exists()]
        required += sorted(path.name for path in (worktree / 'ops/joao/test').glob('recovery-regression-*')
                           if path.suffix in {'.py', '.sh'})
        if sandbox(worktree, required, folder / 'repair-checks.log'):
            raise ValueError('recovery-checks-failed')
        git(worktree, 'diff', '--check')
        git(worktree, 'add', '--', *state['paths'])
        diff = git(worktree, 'diff', '--cached', '--no-ext-diff', '--no-textconv')
        state['reviewedTree'] = git(worktree, 'write-tree')
        reviewer = ((HERE / 'RECOVERY_REVIEW_PROMPT.md').read_text() + '\n' + data(bundle).decode() +
                    '\nPROPOSED REPAIR:\n' + data(proposal).decode() + '\nEXACT DIFF:\n' + diff +
                    '\nACTUAL BASELINE REGRESSION FAILURE:\n' + (folder / 'baseline-checks.log').read_text()[-12000:] +
                    '\nREQUIRED ISOLATED CHECK RESULTS:\n' + (folder / 'repair-checks.log').read_text()[-20000:])
        verdict = call_model(folder, 'review', reviewer, HERE / 'review-result.schema.json', model, effort)
        immutable(folder / 'review.json', verdict)
        if verdict != {'verdict': 'pass', 'findings': []}:
            raise ValueError('independent-repair-review-rejected')
        unchanged(state['protected'])
        state['phase'] = 'ready'
        C.save(root / 'recovery.json', state)
        integrate(root, repo, state)
    except (ValueError, OSError, SyntaxError, ImportError, subprocess.SubprocessError) as error:
        # Preserve pending integration for idempotent push retry, without more IA.
        if state['phase'] not in {'ready', 'publishing', 'unrepairable'}:
            state['phase'] = 'failed'
        reason = str(error)
        reason = reason if re.fullmatch('[a-z-]{1,100}', reason) else 'recovery-operation-failed'
        immutable(folder / 'failure.json', {'reason': reason})
        C.save(root / 'recovery.json', state)
        raise


def status(root):
    if not (root / 'recovery.json').exists():
        return dict(phase='none', attempts=0)
    state = C.private(root / 'recovery.json')
    return {key: state[key] for key in ('phase', 'attempts')}


def grant_review_window(root, state, receipt_path, repo):
    marker_path = root / 'campaign-auto-review.json'
    if not marker_path.exists():
        return
    marker = C.private(marker_path)
    directory = Path(marker['directory'])
    if directory != directory.resolve() or directory.parent != C.REVIEW_ROOT:
        raise ValueError('invalid-review-grant-path')
    counter = directory / 'model-attempts'
    if marker['phase'] != 'review_pending' or not counter.exists():
        return
    consumed = int(counter.read_text().strip())
    previous_limit = review_limit(root, repo)
    grant_path = directory / 'recovery-review-window.json'
    receipt = dict(path=str(receipt_path), sha256=C.digest(receipt_path))
    if grant_path.exists():
        previous = C.private(grant_path)
        if previous['target'] == state['target'] and previous['receipt'] == receipt:
            return
    if consumed < previous_limit or previous_limit >= 9:
        return
    grant = dict(target=state['target'], maximum=previous_limit + 3,
                 bundleSha256=marker['bundleSha256'],
                 receipt=receipt)
    C.save(grant_path, grant)


def review_limit(root, repo):
    marker_path = root / 'campaign-auto-review.json'
    if not marker_path.exists():
        return 3
    marker = C.private(marker_path)
    directory = Path(marker['directory'])
    if directory != directory.resolve() or directory.parent != C.REVIEW_ROOT:
        raise ValueError('invalid-review-grant-path')
    path = directory / 'recovery-review-window.json'
    if not path.exists():
        return 3
    grant = C.private(path)
    receipt_path = Path(grant['receipt']['path'])
    if (receipt_path != receipt_path.resolve() or
            not receipt_path.is_relative_to(root / 'diagnostics/recovery') or
            C.digest(receipt_path) != grant['receipt']['sha256'] or
            grant['bundleSha256'] != marker['bundleSha256'] or
            grant['maximum'] not in {6, 9} or not re.fullmatch('[a-f0-9]{40}', grant['target'])):
        raise ValueError('invalid-reviewed-recovery-window')
    receipt = C.private(receipt_path)
    if receipt['target'] != grant['target']:
        raise ValueError('recovery-window-target-mismatch')
    git(repo, 'merge-base', '--is-ancestor', grant['target'], 'HEAD')
    return grant['maximum']


def notice(root):
    value = status(root)
    phase = value['phase']
    messages = {
        'none': 'A recuperação técnica automática está agendada. O serviço investigará a falha antes de pedir intervenção; nenhuma execução de teste foi autorizada por esta etapa.',
        'diagnosing': 'O recuperador está diagnosticando a falha da automação em uma sessão independente.',
        'checking': 'O reparo está sendo testado sem rede, VM, credenciais ou acesso ao estado da campanha.',
        'ready': 'O reparo passou pelos testes e revisão independente; aguarda integração sob o lock existente.',
        'publishing': 'O reparo aguarda concluir o envio do mesmo commit. A retomada não criará outra correção nem repetirá a IA.',
        'recovered': 'O reparo foi validado e instalado. A tarefa original retoma no próximo ciclo de até cinco minutos, preservando sessão, evidência e orçamento.',
        'failed': 'A tentativa de reparo não passou. O diagnóstico foi preservado para a próxima tentativa limitada.',
        'unrepairable': 'A investigação não encontrou reparo seguro dentro do escopo permitido. A tarefa continua incompleta e precisa de investigação assistida específica.',
        'external_action': 'A investigação identificou uma ação externa indispensável. Nenhuma autorização ou credencial foi alterada automaticamente.'}
    text = messages.get(phase, 'O estado da recuperação precisa de investigação; o trabalho foi preservado.')
    if phase in {'failed', 'unrepairable', 'external_action'}:
        if phase == 'failed' and value['attempts'] >= MAX_REPAIRS:
            text = 'As duas tentativas de reparo terminaram sem aprovação. Não haverá outra chamada automática para a mesma falha.'
        state = C.private(root / 'recovery.json')
        path = Path(state['directory']) / 'failure.json'
        if path.exists():
            reason = C.private(path).get('reason', '')
            if re.fullmatch('[a-z-]{1,100}', reason):
                text += ' Motivo técnico: ' + reason + '.'
        if value['attempts'] >= MAX_REPAIRS or phase in {'unrepairable', 'external_action'}:
            text += ' @renersilv, o serviço esgotou o diagnóstico automático disponível; não está apenas aguardando o timer.'
        proposal_path = Path(state['directory']) / 'proposal.json'
        if phase in {'unrepairable', 'external_action'} and proposal_path.exists():
            diagnosis = C.private(proposal_path)['diagnosis']
            # Input is source plus closed diagnostics, never credentials/raw transcripts.
            diagnosis = re.sub(r'(?i)(bearer\s+|(?:password|secret|token)\s*[:=]\s*)\S+', '[redacted]', diagnosis)
            text += '\n\nDetalhes técnicos: ' + diagnosis[:900]
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['supervise', 'status', 'notice', 'review-limit', 'notice-pending', 'notice-done'])
    parser.add_argument('root', type=Path)
    parser.add_argument('--repository', type=Path, default=HERE.parent.parent)
    parser.add_argument('--model', default='gpt-5.6-sol')
    parser.add_argument('--effort', default='xhigh')
    args = parser.parse_args()
    if args.action == 'status':
        print(json.dumps(status(args.root)))
    elif args.action == 'notice':
        print(notice(args.root))
    elif args.action == 'review-limit':
        print(review_limit(args.root, args.repository))
    elif args.action == 'notice-pending':
        path = args.root / 'recovery.json'
        print('yes' if path.exists() and C.private(path).get('noticePending') else 'no')
    elif args.action == 'notice-done':
        path = args.root / 'recovery.json'
        state = C.private(path)
        state['noticePending'] = False
        # Do not schedule another notification while acknowledging this one.
        temporary = path.with_name('recovery-notified.json')
        save(temporary, state)
        os.replace(temporary, path)
    else:
        supervise(args.root, args.repository, args.model, args.effort)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('recovery_error=diagnosis-or-repair-unavailable', file=sys.stderr)
        raise SystemExit(70)
