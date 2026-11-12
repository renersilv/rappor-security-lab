#!/usr/bin/env python3
"""Deterministic host-owned settlement; never launch a model or replay guest work."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


def control(C, action, root):
    original = sys.argv
    try:
        sys.argv = [str(Path(C.__file__)), action, str(root)]
        with contextlib.redirect_stdout(io.StringIO()):
            C.main()
    finally:
        sys.argv = original


def private_directory(path, root):
    if path != path.resolve() or root != root.resolve() or not path.is_relative_to(root):
        raise ValueError('unsafe-settlement-output-directory')
    current = root
    for part in (None, *path.relative_to(root).parts):
        if part is not None:
            current = current / part
            current.mkdir(mode=0o700, exist_ok=True)
        metadata = current.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700 or current.resolve() != current):
            raise ValueError('unsafe-settlement-output-directory')
    return path


def checkpoint(R, root):
    value = R.C.private(root / 'campaign.json')
    R.C.bound(root, value)
    if value.get('reviewCheckpoint') is None:
        return None
    receipt = R.C.artifact(value['reviewCheckpoint'], protected=True)
    try:
        correction = R.C.artifact(receipt['correction'], protected=True)
    except json.JSONDecodeError:
        return None
    if not isinstance(correction, dict) or correction.get('scope') != 'settlement_only':
        return None
    diagnosis = R.C.artifact(receipt['diagnosis'], protected=True)
    before = R.C.artifact(receipt['beforeState'], protected=True)
    plan = R.validate_settlement_checkpoint(correction, diagnosis, before)
    return value, receipt, correction, plan


def mode(R, root):
    bound = checkpoint(R, root)
    if bound is None or bound[0]['phase'] != 'active':
        return 'none'
    value, _, _, plan = bound
    if value['executorPasses'] not in (plan['executorPass'] - 1, plan['executorPass']):
        raise ValueError('settlement-pass-outside-checkpoint')
    return 'pending'


def invoke(command):
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=53)
        if time.monotonic() - started > 55:
            return 124, stdout[:1024 * 1024], stderr[:1024 * 1024]
        return process.returncode, stdout[:1024 * 1024], stderr[:1024 * 1024]
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.output or b'', error.stderr or b''
        for termination in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, termination)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired as pending:
                stdout, stderr = pending.output or stdout, pending.stderr or stderr
        else:
            for pipe in (process.stdout, process.stderr):
                pipe.close()
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
        return 124, stdout[:1024 * 1024], stderr[:1024 * 1024]


def execute(R, root):
    C, S = R.C, R.SETTLEMENT
    bound = checkpoint(R, root)
    if bound is None:
        raise ValueError('settlement-checkpoint-required')
    value, _, correction, plan = bound
    if value['phase'] != 'active':
        raise ValueError('settlement-campaign-not-active')
    if value['executorPasses'] == plan['executorPass'] - 1:
        control(C, 'begin', root)
        value = C.private(root / 'campaign.json')
    if value['executorPasses'] != plan['executorPass'] or value['lastFinishedPass'] >= plan['executorPass']:
        raise ValueError('settlement-pass-outside-checkpoint')
    directory = Path(value['reviewCheckpoint']['path']).parent
    plan_reference = correction['technicalRoute']['settlementPlan']
    request_reference = R.write_settlement_request(root, value['reviewCheckpoint'], plan_reference)
    request = C.artifact(request_reference, protected=True)
    output = Path(request['outputDirectory'])
    private_directory(output.parent, root)
    packet = private_directory(output.parent / f'host-settlement-pass{plan["executorPass"]}', root)
    intent = directory / 'settlement-host-intent.json'
    completion = directory / 'settlement-host-result.json'
    expected = dict(schema=1, executorPass=plan['executorPass'], candidate=plan['candidate'],
                    checkpoint=value['reviewCheckpoint'], plan=plan_reference, request=request_reference)
    if completion.exists():
        result = C.artifact(R.reference(completion), protected=True)
        if result.get('binding') != expected:
            raise ValueError('settlement-host-result-changed')
    else:
        if intent.exists():
            if C.artifact(R.reference(intent), protected=True) != expected:
                raise ValueError('settlement-host-intent-changed')
            exit_code, stdout, stderr = 125, b'', b'Interrupted host execution; guest operation will not be repeated.\n'
        else:
            R.put(intent, R.encoded(expected))
            entrypoint = S.SOURCE_ROOT / 'src/windows-resource-settlement.mjs'
            exit_code, stdout, stderr = invoke(['node', str(entrypoint), request_reference['path'],
                                              request_reference['sha256'], str(C.REVIEW_ROOT)])
        def log_reference(name, raw):
            path = directory / name
            if path.exists():
                # A crash may leave a partial log. Preserve it, never replay the guest.
                S.installed_bytes(path, private=True, allow_empty=True)
                return R.reference(path)
            return R.put(path, raw[:65536] or b'No output.\n')
        stdout_ref = log_reference('settlement-host-stdout.txt', stdout)
        stderr_ref = log_reference('settlement-host-stderr.txt', stderr)
        result = dict(schema=1, binding=expected, exitCode=exit_code, outcome='unresolved',
                      stdout=stdout_ref, stderr=stderr_ref, receipt=None, executionIntent=None,
                      unresolvedDiagnostic=None, diagnosticStatus='unavailable')
        if exit_code == 0:
            summary = json.loads(stdout)
            receipt_path = output / 'settlement-result.json'
            intent_path = directory / f'settlement-{plan_reference["sha256"]}.intent.json'
            if summary.get('receiptPath') != str(receipt_path) or summary.get('intentPath') != str(intent_path):
                raise ValueError('settlement-output-path-changed')
            # Snapshot material only after the fixed entrypoint exited successfully.
            raw = S.installed_bytes(receipt_path, private=True)
            if R.sha(raw) != summary.get('receiptSha256'):
                raise ValueError('settlement-output-hash-changed')
            guest_intent = C.artifact(dict(path=str(intent_path), sha256=summary.get('intentSha256')), protected=True)
            intent_raw = S.installed_bytes(intent_path, private=True)
            if guest_intent != dict(schema=1, requestSha256=request_reference['sha256'],
                                    planSha256=plan_reference['sha256'], checkpoint=value['reviewCheckpoint'],
                                    outputDirectory=str(output)) or R.sha(intent_raw) != summary['intentSha256']:
                raise ValueError('settlement-execution-binding-changed')
            checked = dict(executorPass=plan['executorPass'], candidate=plan['candidate'],
                           sources={'receipt.json': dict(content=raw.decode(), sha256=R.sha(raw))})
            validated = S.receipt(checked, 'receipt.json', plan, plan_reference['sha256'])
            if (validated['checkpointSha256'] != value['reviewCheckpoint']['sha256']
                    or validated['intentSha256'] != summary['intentSha256']):
                raise ValueError('settlement-execution-binding-changed')
            result.update(outcome='settled', receipt=R.put(directory / 'settlement-host-receipt.json', raw),
                          executionIntent=R.put(directory / 'settlement-entrypoint-intent.json', intent_raw))
        if exit_code != 0 and (output / 'settlement-unresolved.json').exists():
            try:
                unresolved_raw = S.installed_bytes(output / 'settlement-unresolved.json', private=True)
                intent_raw = S.installed_bytes(directory / f'settlement-{plan_reference["sha256"]}.intent.json', private=True)
                intent_value = json.loads(intent_raw)
                if intent_value != dict(schema=1, requestSha256=request_reference['sha256'], planSha256=plan_reference['sha256'],
                                        checkpoint=value['reviewCheckpoint'], outputDirectory=str(output)):
                    raise ValueError('settlement-execution-binding-changed')
                S.unresolved(unresolved_raw, plan_reference['sha256'], value['reviewCheckpoint']['sha256'], R.sha(intent_raw))
                result.update(unresolvedDiagnostic=R.put(directory / 'settlement-host-unresolved.json', unresolved_raw),
                              diagnosticStatus='validated')
            except (OSError, ValueError, TypeError, KeyError):
                result['diagnosticStatus'] = 'invalid'
        R.put(completion, R.encoded(result))
    if result['outcome'] == 'settled':
        C.artifact(result['receipt'], protected=True)
    # Build an immutable review packet from host-protected outputs, not model claims.
    private_directory(packet, root)
    files = {}
    def retain(name, raw):
        path = packet / name
        private_directory(path.parent, root)
        files[name] = R.put(path, raw)['sha256']
    retain('settlement-host-result.json', completion.read_bytes())
    retain('settlement-plan.json', S.source(C.artifact(correction['settlementBundle'], protected=True)['bundle'],
                                         C.artifact(correction['settlementBundle'], protected=True)['planName']))
    for name in S.SOURCE_NAMES:
        retain(name, S.installed_bytes(S.SOURCE_ROOT / name))
    if result.get('unresolvedDiagnostic'):
        C.artifact(result['unresolvedDiagnostic'], protected=True)
        retain('settlement-unresolved.json', Path(result['unresolvedDiagnostic']['path']).read_bytes())
    if result['receipt']:
        retain('settlement-result.json', Path(result['receipt']['path']).read_bytes())
    retain('settlement-host-stdout.txt', Path(result['stdout']['path']).read_bytes())
    retain('settlement-host-stderr.txt', Path(result['stderr']['path']).read_bytes())
    R.put(packet / f'manifest-pass{plan["executorPass"]}.json', R.encoded(dict(issue=19,
        executorPass=plan['executorPass'], authorizationId=plan['authorizationId'], candidate=plan['candidate'],
        newLiveActivity=False, files=files)))
    C.save(root / 'campaign-result.json', dict(schema=1, issue=19, executorPass=plan['executorPass'],
        authorizationId=plan['authorizationId'], phase='review_pending',
        summary='Host settlement finished with protected operational evidence; no model or product acceptance.'))
    control(C, 'finish', root)
