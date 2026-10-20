#!/usr/bin/env python3
"""Persist bounded preparation reviews without granting experiment authorization."""
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

PHASES = {'implementation', 'review_pending', 'review', 'correction', 'waiting_owner', 'exhausted'}
REASONS = {'none', 'checks_failed', 'changes_requested', 'review_interrupted',
           'source_changed', 'campaign_authorization', 'review_limit', 'external_requirement'}


def private_read(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid():
        raise ValueError('invalid-private-state')
    return json.loads(path.read_text())


def save(path, value):
    fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def git(worktree, *arguments):
    return subprocess.check_output(['git', '-C', str(worktree), *arguments], timeout=20)


def snapshot(worktree):
    digest = hashlib.sha256(git(worktree, 'rev-parse', 'HEAD'))
    paths = git(worktree, 'ls-files', '--cached', '--others', '--exclude-standard', '-z').split(b'\0')
    for raw in sorted(set(filter(None, paths))):
        name = os.fsdecode(raw)
        path = worktree / name
        digest.update(raw + b'\0')
        if not path.exists() and not path.is_symlink():
            digest.update(b'deleted\0')
        elif path.is_symlink():
            digest.update(b'link\0' + os.fsencode(os.readlink(path)))
        else:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('unsupported-source-type')
            digest.update(str(stat.S_IMODE(metadata.st_mode)).encode() + b'\0')
            with path.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
    return digest.hexdigest()


def validate(state):
    if state.get('schema') != 1 or state.get('phase') not in PHASES or state.get('reason') not in REASONS:
        raise ValueError('invalid-stage-state')
    if type(state.get('reviews')) is not int or not 0 <= state['reviews'] <= 3:
        raise ValueError('invalid-review-count')
    if type(state.get('issue')) is not int or state['issue'] <= 0:
        raise ValueError('invalid-issue')
    return state


def transition(state, action, digest=None, verdict=None):
    """Closed transition table; none of these transitions authorizes a live experiment."""
    value = dict(validate(state))
    if action == 'queue-review':
        if value['phase'] not in {'implementation', 'correction'}:
            raise ValueError('queue-review-not-permitted')
        value.update(phase='review_pending', reason='none')
    elif action == 'begin-review':
        if value['phase'] not in {'implementation', 'correction', 'review_pending', 'review'}:
            raise ValueError('review-not-permitted')
        if value['reviews'] >= 3:
            value.update(phase='exhausted', reason='review_limit')
        else:
            value.update(phase='review', reason='none', reviews=value['reviews'] + 1, snapshot=digest)
    elif action == 'checks-failed':
        if value['phase'] != 'review':
            raise ValueError('checks-outside-review')
        value.update(phase='correction', reason='checks_failed')
    elif action == 'finish-review':
        if value['phase'] != 'review' or verdict not in {'pass', 'changes_requested', 'owner_required'}:
            raise ValueError('invalid-review-result')
        if digest != value.get('snapshot'):
            value.update(phase='correction', reason='source_changed')
        elif verdict == 'pass':
            value.update(phase='waiting_owner', reason='campaign_authorization')
        elif verdict == 'owner_required':
            value.update(phase='waiting_owner', reason='external_requirement')
        else:
            value.update(phase='correction', reason='changes_requested')
    elif action == 'reconcile':
        if value['phase'] == 'waiting_owner' and digest != value.get('snapshot'):
            value.update(phase='correction', reason='source_changed')
        if value['phase'] == 'review':
            value.update(phase='correction', reason='review_interrupted')
    else:
        raise ValueError('unsupported-action')
    if value['phase'] == 'correction' and value['reviews'] >= 3:
        value.update(phase='exhausted', reason='review_limit')
    return value


def review_bundle(worktree, base, state_root):
    if not re.fullmatch(r'[0-9a-f]{40}', base):
        raise ValueError('invalid-review-base')
    names = set(filter(None, git(worktree, 'diff', '--name-only', '-z', base).split(b'\0')))
    names.update(filter(None, git(worktree, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')))
    allowed = {'src', 'test', 'schemas', 'scanner-profiles', 'docs', 'ops', 'observations', 'targets'}
    pending = [os.fsdecode(name) for name in names]
    sources = {}
    size = 0
    while pending:
        name = pending.pop()
        if name in sources:
            continue
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or (
                relative.parts[0] not in allowed and name not in {'package.json', 'AGENTS.md', 'README.md'}):
            raise ValueError('source-outside-review-allowlist')
        path = worktree / relative
        if path.is_symlink() or not path.resolve().is_relative_to(worktree):
            raise ValueError('review-source-is-symlink')
        if not path.exists():
            sources[name] = {'deleted': True}
            continue
        if path.suffix not in {'.mjs', '.js', '.ts', '.tsx', '.json', '.py', '.sh', '.md', '.ps1'}:
            raise ValueError('unsupported-review-source')
        content = path.read_text()
        size += len(content.encode())
        if size > 800000:
            raise ValueError('review-bundle-too-large')
        sources[name] = {'sha256': hashlib.sha256(content.encode()).hexdigest(), 'content': content}
        for imported in re.findall(r'from\s+["\'](\.[^"\']+)["\']', content):
            imported_path = (path.parent / imported).resolve()
            if imported_path.is_file() and imported_path.suffix in {'.mjs', '.js', '.ts'}:
                if not imported_path.is_relative_to(worktree):
                    raise ValueError('review-import-outside-worktree')
                pending.append(str(imported_path.relative_to(worktree)))
    log = state_root / 'stage-checks.log'
    check_summary = [line for line in log.read_text().splitlines()
                     if line.startswith(('ℹ tests', 'ℹ pass', 'ℹ fail', 'ℹ skipped', 'ℹ cancelled'))]
    proofs = []
    for path in sorted((state_root / 'tmp').glob('issue19-consent-proof-*/typed-validation-receipt.json')):
        value = private_read(path)
        proof = {key: value.get(key) for key in ('status', 'executionState', 'progress', 'scannerStates',
                 'coverageComplete', 'inferenceStarts', 'turnStarts', 'serverRequests', 'sameExistingOperation')}
        # Retain typed outcome evidence only; never forward operation IDs, paths or raw outputs.
        for key in ('coverageComplete', 'sameExistingOperation'):
            if type(proof[key]) is not bool:
                raise ValueError('invalid-proof-boolean')
        for key in ('inferenceStarts', 'turnStarts', 'serverRequests'):
            if type(proof[key]) is not int or proof[key] != 0:
                raise ValueError('invalid-no-model-proof')
        if proof['status'] != 'completed' or proof['executionState'] != 'completed':
            raise ValueError('invalid-proof-state')
        if proof['progress'] != {'total': 3, 'completed': 3, 'failed': 0, 'pending': 0}:
            raise ValueError('incomplete-scanner-proof')
        if proof['scannerStates'] != {name: 'completed' for name in ('semgrep', 'gitleaks', 'trivy')}:
            raise ValueError('incomplete-scanner-proof')
        proof['receiptSha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        proofs.append(proof)
    return {'sourceSnapshot': snapshot(worktree), 'sources': sources,
            'checkSummary': check_summary, 'typedTechnicalProofs': proofs,
            'reviewLimit': 'Static independent review of supplied exact source and evidence; not a live AI test.'}


def review_result(path):
    last = None
    # Private events may contain tool output. Parse only the final agent message.
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError('invalid-review-events')
    with path.open() as stream:
        for line in stream:
            event = json.loads(line)
            if event.get('type') in {'item.started', 'item.completed'} and event.get('item', {}).get('type') not in {'agent_message', 'reasoning'}:
                raise ValueError('review-attempted-tool-use')
            if event.get('type') == 'item.completed' and event.get('item', {}).get('type') == 'agent_message':
                last = event['item'].get('text')
    value = json.loads(last or '')
    if set(value) != {'verdict', 'findings'} or value['verdict'] not in {'pass', 'changes_requested', 'owner_required'}:
        raise ValueError('invalid-review-result')
    if not isinstance(value['findings'], list) or len(value['findings']) > 8:
        raise ValueError('invalid-review-findings')
    if any(not isinstance(item, str) or not 1 <= len(item) <= 2000 for item in value['findings']):
        raise ValueError('invalid-review-finding')
    if (value['verdict'] == 'pass') != (len(value['findings']) == 0):
        raise ValueError('inconsistent-review-verdict')
    return value


def main():
    action, state_root = sys.argv[1:3]
    state_path = Path(state_root) / 'stage.json'
    if action == 'status':
        if not state_path.exists():
            print('stage=ordinary')
        else:
            state = validate(private_read(state_path))
            print(f"stage={state['phase']}\nstage_reason={state['reason']}\nstage_reviews={state['reviews']}")
        return
    issue, worktree, contract_path = int(sys.argv[3]), Path(sys.argv[4]).resolve(), Path(sys.argv[5])
    contract = json.loads(contract_path.read_text())
    if contract != {'schema': 1, 'issue': issue, 'stage': 'consent-preparation-v1',
                    'contract': 'issue-19.md', 'maxReviews': 3, 'nextGate': 'campaign-authorization',
                    'allowsFinalDelivery': False}:
        raise ValueError('unsupported-contract')
    contract_digest = hashlib.sha256(contract_path.read_bytes() +
                                    (contract_path.parent / contract['contract']).read_bytes()).hexdigest()
    branch = git(worktree, 'symbolic-ref', '--short', 'HEAD').decode().strip()
    if not branch.startswith('joao/batch-'):
        raise ValueError('invalid-stage-branch')
    binding = dict(issue=issue, worktree=str(worktree), branch=branch, contractDigest=contract_digest)
    if state_path.is_symlink():
        raise ValueError('invalid-private-state')
    if state_path.exists():
        state = validate(private_read(state_path))
        if any(state.get(key) != value for key, value in binding.items()):
            raise ValueError('stage-binding-changed')
    else:
        state = dict(schema=1, **binding, phase='implementation', reason='none', reviews=0, snapshot=None)
    if action == 'bundle':
        base = (Path(state_root) / 'issue_base_sha').read_text().strip()
        print(json.dumps(review_bundle(worktree, base, Path(state_root))))
        return
    if action == 'phase':
        state = transition(state, 'reconcile', snapshot(worktree))
    elif action == 'finish-review':
        result = review_result(Path(state_root) / 'stage-review.events.jsonl')
        save(Path(state_root) / 'stage-review.result.json', result)
        state = transition(state, action, snapshot(worktree), result['verdict'])
    elif action == 'begin-review':
        state = transition(state, action, snapshot(worktree))
    elif action in {'checks-failed', 'queue-review'}:
        state = transition(state, action)
    else:
        raise ValueError('unsupported-command')
    save(state_path, state)
    print(state['phase'])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('stage_error=invalid-or-unavailable-evidence', file=sys.stderr)
        sys.exit(65)
