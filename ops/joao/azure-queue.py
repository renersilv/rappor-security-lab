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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('command', choices=['preflight', 'capture', 'list', 'show', 'state', 'phase', 'comment', 'id', 'campaign', 'report-finding'])
    parser.add_argument('--item', type=int)
    parser.add_argument('--phase')
    parser.add_argument('--body-file')
    parser.add_argument('--marker')
    parser.add_argument('--report-file')
    args = parser.parse_args()
    try:
        value = binding(args.root)
        mapping = active_mapping(args.root, value)
        if args.command in {'id', 'campaign', 'show', 'state', 'phase', 'comment', 'report-finding'}:
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
