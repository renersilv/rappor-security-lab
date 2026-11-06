#!/usr/bin/env python3
"""Pinned host boundary for the common Azure queue and historical campaign mapping."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

PROJECT = '5d25148a-14fb-4bc8-8f5b-29441281d84e'


def private(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('invalid-private-binding')
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('invalid-private-binding-permissions')
    return json.loads(path.read_text())


def binding(root):
    value = private(root / 'azure-binding.json')
    if set(value) != {'version', 'projectId', 'adapterPath', 'adapterSha256',
                     'runnerRevision', 'configPath', 'queueStateDirectory', 'campaign'}:
        raise ValueError('invalid-azure-binding-fields')
    if value['version'] != 1 or value['projectId'] != PROJECT:
        raise ValueError('invalid-azure-project-binding')
    adapter = Path(value['adapterPath'])
    if not adapter.is_absolute() or adapter.is_symlink() or not adapter.is_file():
        raise ValueError('invalid-common-adapter')
    if not re.fullmatch('[a-f0-9]{64}', value['adapterSha256']) or hashlib.sha256(adapter.read_bytes()).hexdigest() != value['adapterSha256']:
        raise ValueError('common-adapter-digest-mismatch')
    if not re.fullmatch('[a-f0-9]{40}', value['runnerRevision']):
        raise ValueError('invalid-common-runner-revision')
    config = private(value['configPath'])
    if config.get('azure', {}).get('projectId') != PROJECT or config.get('mode') != 'active':
        raise ValueError('azure-configuration-project-mismatch')
    if not Path(value['queueStateDirectory']).is_absolute():
        raise ValueError('invalid-common-state-directory')
    campaign = value['campaign']
    if campaign is not None:
        if (set(campaign) != {'historicalId', 'azureWorkItemId', 'branch'} or
                campaign['historicalId'] != 19 or type(campaign['azureWorkItemId']) is not int or
                campaign['azureWorkItemId'] <= 0 or
                not re.fullmatch(r'joao/batch-[0-9TZ-]+-19-19', campaign['branch'])):
            raise ValueError('invalid-campaign-mapping')
    return value


def active_mapping(root, value):
    campaign = value['campaign']
    if campaign is None:
        if (root / 'campaign.json').exists():
            raise ValueError('campaign-mapping-required')
        return None
    branch = root / 'branch'
    if not branch.exists() or branch.read_text().strip() != campaign['branch']:
        if (root / 'campaign.json').exists():
            raise ValueError('campaign-branch-mismatch')
        return None
    if not (root / 'campaign.json').is_file() or (root / 'batch').read_text().strip() != '19':
        raise ValueError('preserved-campaign-state-mismatch')
    return campaign


def operational_id(root, value, historical):
    mapping = active_mapping(root, value)
    if mapping:
        if historical != 19:
            raise ValueError('item-outside-preserved-campaign')
        return mapping['azureWorkItemId']
    return historical


def invoke(value, args):
    environment = dict(os.environ, RAIMUNDO_RUNNER_REVISION=value['runnerRevision'])
    result = subprocess.run([sys.executable, value['adapterPath'], '--config', value['configPath'],
                             '--state-dir', value['queueStateDirectory'], *args], env=environment,
                            text=True, capture_output=True, timeout=90)
    if result.returncode:
        # Avoid leaking a helper/provider diagnostic into model or journal output.
        raise ValueError('azure-operation-failed')
    return result.stdout.strip()


def current_task(root, item):
    if (root / 'current_issue').read_text().strip() != str(item):
        raise ValueError('retest-source-is-not-current-task')
    branch = (root / 'branch').read_text().strip()
    if not re.fullmatch(r'joao/batch-[0-9TZ-]+-[0-9]+-[0-9]+', branch):
        raise ValueError('invalid-retest-task-branch')
    return branch


def capture_retests(root, work_id, branch, output):
    rows = json.loads(output)
    if not isinstance(rows, list):
        raise ValueError('invalid-retest-list')
    captured = {}
    for row in rows:
        if (not isinstance(row, dict) or type(row.get('id')) is not int or row['id'] <= 0 or
                type(row.get('deliveryRevision')) is not int or row['deliveryRevision'] <= 0 or
                row.get('origin') != 'joao' or row.get('executor') not in {'raimundo', 'zeca'} or
                str(row['id']) in captured):
            raise ValueError('invalid-retest-entry')
        captured[str(row['id'])] = row['deliveryRevision']
    path = root / 'current-retests.json'
    if path.is_symlink():
        raise ValueError('invalid-retest-snapshot')
    snapshot = dict(version=1, sourceWorkItemId=work_id, branch=branch, findings=captured)
    with tempfile.NamedTemporaryFile(mode='w', dir=root, prefix='.retests-', delete=False) as out:
        temporary = Path(out.name)
        os.fchmod(out.fileno(), 0o600)
        json.dump(snapshot, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    return output


def validate_retest_result(root, work_id, branch, finding, result_file):
    if type(finding) is not int or finding <= 0:
        raise ValueError('invalid-retest-finding')
    snapshot = private(root / 'current-retests.json')
    result = private(result_file)
    if (set(snapshot) != {'version', 'sourceWorkItemId', 'branch', 'findings'} or
            snapshot['version'] != 1 or snapshot['sourceWorkItemId'] != work_id or
            snapshot['branch'] != branch or not isinstance(snapshot['findings'], dict)):
        raise ValueError('retest-snapshot-mismatch')
    if (set(result) != {'deliveryRevision', 'outcome', 'summary', 'evidence'} or
            type(result['deliveryRevision']) is not int or result['deliveryRevision'] <= 0 or
            snapshot['findings'].get(str(finding)) != result['deliveryRevision'] or
            result['outcome'] not in {'passed', 'failed'}):
        raise ValueError('retest-result-outside-captured-delivery')
    # Common adapter validates sanitized evidence and current delivery revision.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('command', choices=['preflight', 'capture', 'list', 'show', 'state', 'phase', 'comment', 'id', 'campaign', 'report-finding', 'list-retests', 'retest-result'])
    parser.add_argument('--item', type=int)
    parser.add_argument('--phase')
    parser.add_argument('--body-file')
    parser.add_argument('--marker')
    parser.add_argument('--report-file')
    parser.add_argument('--finding', type=int)
    parser.add_argument('--result-file')
    args = parser.parse_args()
    try:
        value = binding(args.root)
        mapping = active_mapping(args.root, value)
        if args.command in {'id', 'campaign', 'show', 'state', 'phase', 'comment', 'report-finding', 'list-retests', 'retest-result'}:
            if args.item is None or args.item <= 0:
                raise ValueError('invalid-work-item')
            work_id = operational_id(args.root, value, args.item)
        if args.command == 'campaign':
            print('19' if mapping and args.item == 19 else 'none')
        elif args.command == 'id':
            print(work_id)
        elif args.command == 'preflight':
            print(invoke(value, ['preflight']))
        elif args.command == 'capture':
            if mapping:
                raise ValueError('cannot-recapture-preserved-campaign')
            ids = json.loads(invoke(value, ['capture', '--executor', 'joao', '--limit', '100']))
            print('\n'.join(str(item) for item in ids))
        elif args.command == 'list':
            ids = json.loads(invoke(value, ['list', '--executor', 'joao', '--phase', args.phase]))
            if mapping:
                if mapping['azureWorkItemId'] != 19 and 19 in ids:
                    raise ValueError('ambiguous-preserved-campaign-number')
                ids = [19 if item == mapping['azureWorkItemId'] else item for item in ids]
            print('\n'.join(str(item) for item in ids))
        elif args.command in {'list-retests', 'retest-result'}:
            branch = current_task(args.root, args.item)
            arguments = [args.command, '--work-item', str(work_id)]
            if args.command == 'list-retests':
                print(capture_retests(args.root, work_id, branch, invoke(value, arguments)))
            else:
                validate_retest_result(args.root, work_id, branch, args.finding, args.result_file)
                arguments += ['--finding', str(args.finding), '--result-file', args.result_file]
                print(invoke(value, arguments))
        else:
            command = {'phase': 'set-phase', 'state': 'show'}.get(args.command, args.command)
            arguments = [command, '--work-item', str(work_id)]
            if command not in {'state', 'report-finding'}:
                arguments += ['--executor', 'joao']
            if command == 'set-phase':
                arguments += ['--phase', args.phase]
            if command == 'report-finding':
                arguments += ['--report-file', args.report_file]
            if command == 'comment':
                arguments += ['--body-file', args.body_file, '--marker', args.marker]
            output = invoke(value, arguments)
            print(json.loads(output)['phase'] if args.command == 'state' else output)
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        print('Azure queue binding or operation failed; preserve the task and inspect host configuration.', file=sys.stderr)
        return 65


if __name__ == '__main__':
    sys.exit(main())
