#!/usr/bin/env python3
"""Closed evidence contract for one already-authorized operational settlement."""
import hashlib
import json
import os
import stat
from pathlib import Path
import re

HASH = re.compile(r'[a-f0-9]{64}')
SOURCE_NAMES = ('src/windows-resource-settlement.mjs', 'src/windows-resource-settlement.ps1',
                'src/windows-settlement-transport.mjs', 'src/powershell-stdin-transport.mjs',
                'src/protected-inputs.mjs', 'ops/joao/windows-host-identity.py')
SOURCE_ROOT = Path(__file__).resolve().parents[2]
FLAGS = ('inferenceStarted', 'mcpToolCallIssued', 'ideLaunched', 'appServerLaunched', 'scanStarted',
         'reauthenticationStarted', 'configurationChanged', 'ledgerChanged')
PLAN_KEYS = {'schema', 'kind', 'issue', 'authorizationId', 'candidate', 'executorPass', 'originPass',
             'incident', 'originManifest', 'originRuntimeReceipt', 'taskName', 'guestRoot',
             'ownershipFiles', 'maxDurationMs', 'sourceHashes'}
CONTEXT = ('issue', 'authorizationId', 'candidate', 'executorPass', 'originPass', 'incident',
           'taskName', 'guestRoot', 'sourceHashes')
RECEIPT_KEYS = set(CONTEXT) | set(FLAGS) | {'schema', 'kind', 'planSha256', 'outcome', 'taskAbsent',
    'rootAbsent', 'ownershipVerified', 'remainingOwnedProcesses', 'transportProbeVerified', 'elapsedMs',
    'checkpointSha256', 'intentSha256'}


def require(value, code='invalid-settlement-contract'):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source(bundle, name):
    require(isinstance(name, str) and name in bundle['sources'])
    value = bundle['sources'][name]
    require(isinstance(value, dict) and not value.get('omitted') and isinstance(value.get('content'), str))
    raw = value['content'].encode()
    require(digest(raw) == value.get('sha256'), 'settlement-evidence-hash-mismatch')
    return raw


def reference(bundle, value, keys):
    require(isinstance(value, dict) and set(value) == keys)
    raw = source(bundle, value['file'])
    require(value['sha256'] == digest(raw), 'settlement-evidence-hash-mismatch')
    return json.loads(raw)


def installed_bytes(path, *, private=False, allow_empty=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and (0 if allow_empty else 1) <= before.st_size <= 300000)
        require(not private or stat.S_IMODE(before.st_mode) == 0o600)
        descriptor_path = Path(f'/proc/self/fd/{descriptor}')
        require(descriptor_path.resolve() == path, 'settlement-installed-source-mismatch')
        with os.fdopen(descriptor, 'rb', closefd=False) as source_file:
            raw = source_file.read(300001)
        after = os.fstat(descriptor)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, field) == getattr(after, field) for field in stable)
                and descriptor_path.resolve() == path and len(raw) == before.st_size,
                'settlement-installed-source-mismatch')
        return raw
    finally:
        os.close(descriptor)


def plan(bundle, name, incident, *, installed_root=None, trusted_origins=None, pending_origin=None):
    raw = source(bundle, name)
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == PLAN_KEYS)
    require(type(value['schema']) is int and value['schema'] == 1 and value['kind'] == 'windows_task_settlement')
    require(value['issue'] == 19 and type(value['issue']) is int and
            value['authorizationId'] == 'issue19-native-windows-20261023')
    require(value['candidate'] == bundle['candidate'] and type(value['executorPass']) is int and
            value['executorPass'] == bundle['executorPass'] + 1)
    require(isinstance(incident, str) and HASH.fullmatch(incident) and value['incident'] == incident)
    origin = value['originPass']
    require(type(origin) is int and 1 <= origin < value['executorPass'])
    require(value['taskName'] == f'RapporLab-Pass{origin}-IdeReadiness' and
            value['guestRoot'] == f'C:\\RapporLab\\runtime\\pass{origin}-ide-readiness' and
            value['ownershipFiles'] == ['owned-processes.json', 'observer-ownership.json'])
    require(type(value['maxDurationMs']) is int and value['maxDurationMs'] == 55000)
    require(isinstance(value['originManifest'], dict))
    pending = bundle.get('settlementCleanupOrigin') if pending_origin is None else pending_origin
    require(pending == dict(executorPass=origin, manifestSha256=value['originManifest'].get('sha256')),
            'settlement-origin-not-pending')
    origins = bundle.get('settlementOrigins', {}) if trusted_origins is None else trusted_origins
    require(origins.get(str(origin)) == value['originManifest'].get('sha256'), 'settlement-origin-not-protected')
    manifest = reference(bundle, value['originManifest'], {'file', 'sha256'})
    original = reference(bundle, value['originRuntimeReceipt'], {'file', 'sha256', 'manifestName'})
    for artifact in (manifest, original):
        require(isinstance(artifact, dict) and type(artifact.get('executorPass')) is int
                and type(artifact.get('issue')) is int and artifact.get('executorPass') == origin and
                artifact.get('candidate') == value['candidate'] and artifact.get('issue') == 19 and
                artifact.get('authorizationId') == value['authorizationId'])
    require(manifest.get('files', {}).get(value['originRuntimeReceipt']['manifestName']) ==
            value['originRuntimeReceipt']['sha256'])
    for name in ('runtime/interactive.ps1', 'runtime/observe.ps1'):
        fingerprint = original.get('artifacts', {}).get(name)
        require(isinstance(fingerprint, str) and HASH.fullmatch(fingerprint))
    require(isinstance(value['sourceHashes'], dict) and set(value['sourceHashes']) == set(SOURCE_NAMES))
    installed_root = installed_root or SOURCE_ROOT
    for name, fingerprint in value['sourceHashes'].items():
        material = source(bundle, name)
        installed = installed_root / name
        require(digest(installed_bytes(installed)) == fingerprint == digest(material), 'settlement-installed-source-mismatch')
    return value, digest(raw)


def receipt(bundle, name, expected_plan, plan_sha):
    value = json.loads(source(bundle, name))
    require(isinstance(value, dict) and set(value) == RECEIPT_KEYS)
    require(type(value['schema']) is int and value['schema'] == 1 and value['kind'] == 'windows_task_settlement_result')
    require(value['planSha256'] == plan_sha and value['outcome'] == 'settled')
    require(all(isinstance(value[key], str) and HASH.fullmatch(value[key])
                for key in ('checkpointSha256', 'intentSha256')))
    require(all(value[key] == expected_plan[key] and type(value[key]) is type(expected_plan[key]) for key in CONTEXT))
    require(value['executorPass'] == bundle['executorPass'] and value['candidate'] == bundle['candidate'])
    require(all(value[key] is False for key in FLAGS))
    require(all(value[key] is True for key in ('taskAbsent', 'rootAbsent', 'ownershipVerified', 'transportProbeVerified')))
    require(type(value['remainingOwnedProcesses']) is int and value['remainingOwnedProcesses'] == 0)
    require(type(value['elapsedMs']) in (int, float) and 0 <= value['elapsedMs'] <= expected_plan['maxDurationMs'])
    return value


def unresolved(raw, plan_sha, checkpoint_sha, intent_sha):
    value = json.loads(raw)
    stages = {'host_identity', 'credential_open', 'credential_validation', 'transport_probe', 'resource_cleanup',
              'credential_close', 'source_validation', 'result_publication'}
    reasons = {'host_identity_rejected', 'credential_unavailable', 'credential_changed', 'probe_failed',
               'cleanup_failed', 'credential_close_failed', 'source_changed', 'result_publication_failed',
               'deadline_exhausted', 'transport_timeout', 'transport_output_limit', 'transport_pipe_failure',
               'transport_exit_255', 'transport_nonzero_exit', 'transport_start_failed', 'transport_interrupted'}
    require(isinstance(value, dict) and set(value) == {'schema', 'kind', 'planSha256', 'checkpointSha256',
            'intentSha256', 'outcome', 'failedStage', 'reasonCode', 'elapsedMs'})
    require(type(value['schema']) is int and value['schema'] == 1 and
            value['kind'] == 'windows_task_settlement_unresolved' and value['outcome'] == 'unresolved')
    require(value['planSha256'] == plan_sha and value['checkpointSha256'] == checkpoint_sha and
            value['intentSha256'] == intent_sha)
    require(value['failedStage'] in stages and value['reasonCode'] in reasons)
    require(type(value['elapsedMs']) in (int, float) and 0 <= value['elapsedMs'] <= 10800000)
    return value
