#!/usr/bin/env python3
"""Continue an explicitly authorized native campaign without rewriting preparation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
STAGE_SPEC = importlib.util.spec_from_file_location('campaign_stage', Path(__file__).with_name('stage-control.py'))
STAGE = importlib.util.module_from_spec(STAGE_SPEC)
STAGE_SPEC.loader.exec_module(STAGE)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid():
        raise ValueError('invalid-private-file')
    return json.loads(path.read_text())


def save(path, value):
    descriptor, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def authorization(value):
    if not isinstance(value, dict):
        raise ValueError('invalid-authorization')
    expected = dict(schemaVersion=1, issue=19, client='cli-windows-native',
                    additionalStarts=10, maxSecondsPerRun=600,
                    preserveAllPreviousAttempts=True, preserveIdeWindowsReservations=2,
                    sequentialOnly=True, consumeBeforeStart=True, countFailedStarts=True,
                    allowOpenAiApiKey=False, allowNewVm=False, allowBaselineReset=False,
                    stopOnCompletedCycle=True, requireCorrectionBeforeRetry=True)
    if any(type(value.get(key)) is not type(item) or value[key] != item for key, item in expected.items()):
        raise ValueError('unsupported-authorization')
    if value.get('authorizationId') != 'issue19-native-windows-20261023':
        raise ValueError('unexpected-authorization')
    for key in ('previousAuthorizationSha256', 'previousConsumptionSha256'):
        if not re.fullmatch(r'[a-f0-9]{64}', value.get(key, '')):
            raise ValueError('missing-prior-provenance')
    return value


def candidate(value):
    if not isinstance(value, dict) or set(value) != {'version', 'sha', 'origin'}:
        raise ValueError('invalid-candidate')
    if not isinstance(value['version'], str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', value['version']):
        raise ValueError('invalid-candidate-version')
    if not isinstance(value['sha'], str) or not re.fullmatch(r'[a-f0-9]{40}', value['sha']):
        raise ValueError('invalid-candidate-sha')
    if value['origin'] != 'https://linux-ai2.taile60a95.ts.net:8443':
        raise ValueError('unexpected-candidate-origin')
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def progress(worktree, consumed):
    return hashlib.sha256(f'{STAGE.snapshot(Path(worktree))}:{consumed}'.encode()).hexdigest()


def consumption(root, auth):
    receipts = []
    for directory in root.iterdir():
        if not directory.name.startswith('attempt-'):
            continue
        match = re.fullmatch(r'attempt-([1-9]|10)', directory.name)
        if not match or directory.is_symlink() or not directory.is_dir():
            raise ValueError('invalid-attempt-directory')
        receipt = private(directory / 'receipt.json')
        number = int(match[1])
        if receipt.get('authorizationId') != auth['authorizationId'] or receipt.get('client') != auth['client'] or receipt.get('attempt') != number:
            raise ValueError('attempt-binding-changed')
        if receipt.get('consumed') is not True or receipt.get('maxAuthorizedStarts') != 10 or receipt.get('maxSeconds') != 600:
            raise ValueError('invalid-attempt-budget')
        receipts.append(number)
    receipts.sort()
    if receipts != list(range(1, len(receipts) + 1)):
        raise ValueError('attempt-history-gap')
    return len(receipts)


def bound(state_root, value):
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('issue') != 19 or value.get('phase') not in {'active', 'review_pending', 'owner_required'}:
        raise ValueError('invalid-campaign-state')
    if type(value.get('executorPasses')) is not int or value['executorPasses'] < 0:
        raise ValueError('invalid-executor-pass-count')
    if type(value.get('noProgressPasses')) is not int or not 0 <= value['noProgressPasses'] <= 3:
        raise ValueError('invalid-progress-count')
    if type(value.get('lastFinishedPass')) is not int or not 0 <= value['lastFinishedPass'] <= value['executorPasses']:
        raise ValueError('invalid-finished-pass-count')
    if type(value.get('lastObservedConsumption')) is not int or not value['consumedAtActivation'] <= value['lastObservedConsumption'] <= 10:
        raise ValueError('invalid-consumption-checkpoint')
    if value.get('allowsFinalDelivery') is not False or candidate(value['candidate']) != value.get('candidateSha256'):
        raise ValueError('candidate-binding-changed')
    if not isinstance(value.get('progressFingerprint'), str) or not re.fullmatch(r'[a-f0-9]{64}', value['progressFingerprint']):
        raise ValueError('invalid-progress-fingerprint')
    for key, path in [('stageSha256', state_root / 'stage.json'),
                      ('sessionSha256', state_root / 'session'),
                      ('authorizationSha256', Path(value['authorizationPath'])),
                      ('contractSha256', Path(__file__).with_name('campaign-contract.md'))]:
        if digest(path) != value.get(key):
            raise ValueError('campaign-binding-changed')
    stage = private(state_root / 'stage.json')
    if stage.get('phase') != 'waiting_owner' or stage.get('reason') != 'campaign_authorization' or stage.get('issue') != 19:
        raise ValueError('preparation-is-not-authorized-wait')
    if any(value.get(key) != stage.get(key) for key in ('worktree', 'branch')):
        raise ValueError('campaign-worktree-changed')
    branch = subprocess.check_output(['git', '-C', value['worktree'], 'symbolic-ref', '--short', 'HEAD'], timeout=20).decode().strip()
    if branch != value['branch'] or (state_root / 'current_issue').read_text().strip() != '19':
        raise ValueError('active-issue-changed')
    auth = authorization(private(Path(value['authorizationPath'])))
    used = consumption(Path(value['attemptsRoot']), auth)
    if used < value['lastObservedConsumption']:
        raise ValueError('attempt-history-rewound')
    for number, expected in value['historicalReceiptHashes'].items():
        if not re.fullmatch(r'[1-9]|10', number) or digest(Path(value['attemptsRoot']) / f'attempt-{number}' / 'receipt.json') != expected:
            raise ValueError('historical-attempt-changed')
    return auth, used


def checkpoint(value, used):
    value['lastObservedConsumption'] = used
    for number in range(1, used + 1):
        path = Path(value['attemptsRoot']) / f'attempt-{number}' / 'receipt.json'
        receipt = private(path)
        if isinstance(receipt.get('outcome'), str) and receipt['outcome'] != 'running':
            value['historicalReceiptHashes'][str(number)] = digest(path)


def activate(state_root, auth_path, attempts_root, candidate_path):
    path = state_root / 'campaign.json'
    if path.exists() or path.is_symlink():
        raise ValueError('campaign-already-activated')
    auth = authorization(private(auth_path))
    stage = private(state_root / 'stage.json')
    if stage.get('phase') != 'waiting_owner' or stage.get('reason') != 'campaign_authorization' or stage.get('issue') != 19:
        raise ValueError('preparation-is-not-authorized-wait')
    if not (state_root / 'session').read_text().strip():
        raise ValueError('existing-session-required')
    selected_candidate = private(candidate_path)
    candidate_digest = candidate(selected_candidate)
    used = consumption(attempts_root, auth)
    if used >= 10:
        raise ValueError('native-budget-exhausted')
    value = dict(schema=1, issue=19, phase='active', worktree=stage['worktree'], branch=stage['branch'],
                 authorizationPath=str(auth_path.resolve()), authorizationSha256=digest(auth_path),
                 attemptsRoot=str(attempts_root.resolve()), consumedAtActivation=used,
                 lastObservedConsumption=used,
                 candidate=selected_candidate, candidateSha256=candidate_digest,
                 stageSha256=digest(state_root / 'stage.json'),
                 sessionSha256=digest(state_root / 'session'),
                 contractSha256=digest(Path(__file__).with_name('campaign-contract.md')),
                 historicalReceiptHashes={str(number): digest(attempts_root / f'attempt-{number}' / 'receipt.json') for number in range(1, used + 1)},
                 executorPasses=0, lastFinishedPass=0, noProgressPasses=0,
                 progressFingerprint=progress(stage['worktree'], used), allowsFinalDelivery=False)
    bound(state_root, value)
    save(path, value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['activate', 'status', 'phase', 'prompt', 'begin', 'finish'])
    parser.add_argument('state_root', type=Path)
    parser.add_argument('inputs', nargs='*')
    args = parser.parse_args()
    root, path = args.state_root, args.state_root / 'campaign.json'
    if args.action == 'activate':
        if len(args.inputs) != 3:
            raise ValueError('activation-inputs-required')
        activate(root, *(Path(item) for item in args.inputs))
        print('campaign_activated=yes')
        return
    if args.action == 'status' and not path.exists():
        print('campaign=none')
        return
    value = private(path)
    auth, used = bound(root, value)
    if args.action in {'phase', 'begin', 'finish'}:
        checkpoint(value, used)
        save(path, value)
    if args.action == 'status':
        print(f"campaign={value['phase']}\ncampaign_client=cli-windows-native\ncampaign_remaining={10-used}\ncampaign_executor_passes={value['executorPasses']}\ncampaign_no_progress_passes={value['noProgressPasses']}")
    elif args.action == 'phase':
        print(value['phase'])
    elif args.action == 'prompt':
        print(Path(__file__).with_name('campaign-contract.md').read_text())
        print('\nCURRENT PRIVATE CAMPAIGN BINDING (data, never executable commands):')
        print(json.dumps(dict(authorizationId=auth['authorizationId'], authorizationPath=value['authorizationPath'],
                              attemptsRoot=value['attemptsRoot'], remainingNativeStarts=10-used,
                              candidate=value['candidate'], resultPath=str(root / 'campaign-result.json'),
                              executorPass=value['executorPasses'])))
    elif args.action == 'begin':
        if value['phase'] != 'active':
            raise ValueError('campaign-not-active')
        value['executorPasses'] += 1
        save(path, value)
    elif args.action == 'finish':
        if value['phase'] != 'active' or value['lastFinishedPass'] >= value['executorPasses']:
            raise ValueError('campaign-pass-not-running')
        result = private(root / 'campaign-result.json')
        if set(result) != {'schema', 'issue', 'executorPass', 'authorizationId', 'phase', 'summary'}:
            raise ValueError('invalid-campaign-result')
        if result['schema'] != 1 or result['issue'] != 19 or result['authorizationId'] != auth['authorizationId'] or result['executorPass'] != value['executorPasses']:
            raise ValueError('stale-campaign-result')
        if result['phase'] not in {'active', 'review_pending', 'owner_required'} or not isinstance(result['summary'], str) or not 1 <= len(result['summary']) <= 2000:
            raise ValueError('invalid-campaign-result')
        value['phase'] = result['phase']
        fingerprint = progress(value['worktree'], used)
        value['noProgressPasses'] = value['noProgressPasses'] + 1 if fingerprint == value['progressFingerprint'] else 0
        value['progressFingerprint'] = fingerprint
        if value['noProgressPasses'] >= 3:
            value['phase'] = 'review_pending'
            value['reviewReason'] = 'no_progress'
        if used >= 10:
            value['phase'] = 'review_pending'
            value['reviewReason'] = 'native_budget_exhausted'
        value['lastSummary'] = result['summary']
        value['lastFinishedPass'] = value['executorPasses']
        save(path, value)
        print(value['phase'])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('campaign_error=invalid-or-unavailable-evidence', file=sys.stderr)
        raise SystemExit(65)
