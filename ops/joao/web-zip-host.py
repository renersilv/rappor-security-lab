"""Fixed host dispatch for the reviewed Web ZIP runtime; no model or quota writer."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

SOURCE_ROOT = Path(__file__).resolve().with_name('web-zip') / 'source'
CANDIDATE = dict(origin='https://linux-ai2.taile60a95.ts.net:8443',
                 sha='3105b01067ac415786d9c041cc922195c00c9cc4', version='v0.92.0')
SOURCE_NAMES = ('web-zip-runner.mjs', 'web-zip-orchestrator.mjs', 'web-zip-result.mjs',
                'web-zip-windows-orchestrator.ps1', 'protected-inputs.mjs',
                'windows-settlement-transport.mjs', 'powershell-stdin-transport.mjs', 'windows-host-identity.py')


def put(R, path, raw):
    def existing():
        actual = R.SETTLEMENT.installed_bytes(path, private=True, allow_empty=True)
        if actual != raw:
            raise ValueError('immutable-web-zip-artifact-changed')
        return R.reference(path)
    if path.exists() or path.is_symlink():
        return existing()
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError('web-zip-artifact-write-failed')
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            return existing()
        return R.reference(path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def checkpoint(R, root):
    C = R.C
    value = C.private(root / 'campaign.json')
    C.bound(root, value)
    if value.get('reviewCheckpoint') is None:
        return None
    C.reviewed_checkpoint(value)
    # Reject an incomplete retry before the optional dispatch branch can fall back.
    R.WORK.history(value, C.artifact)
    receipt = C.artifact(value['reviewCheckpoint'], protected=True)
    try:
        correction = C.artifact(receipt['correction'], protected=True)
    except json.JSONDecodeError:
        return None
    if not isinstance(correction, dict) or 'webZipRequest' not in correction:
        return None
    directory = Path(value['reviewCheckpoint']['path']).parent
    request_ref = correction['webZipRequest']
    request = C.artifact(request_ref, protected=True)
    if (request_ref['path'] != str(directory / 'web-zip-request.json')
            or set(request) != {'schema', 'kind', 'issue', 'authorizationId', 'candidate', 'executorPass',
                                'fixtureRoot', 'sourceHashes', 'desktop', 'product', 'previousReview'}
            or type(request['schema']) is not int or request['schema'] != 1
            or request['kind'] != 'web_zip_execution_request' or request['issue'] != 19
            or request['authorizationId'] != 'issue19-native-windows-20261023'
            or request['candidate'] != value['candidate'] or request['candidate'] != CANDIDATE
            or type(request['executorPass']) is not int or request['executorPass'] <= 237
            or request['executorPass'] != receipt['reviewedThroughPass'] + 1
            or request['previousReview'] != receipt['previousReview']):
        raise ValueError('invalid-web-zip-request-binding')
    C.artifact(request['previousReview'], protected=True)
    grant = R.WORK.active(value, C.artifact)
    diagnosis = C.artifact(receipt['diagnosis'], protected=True)
    if (grant != correction.get('workContinuation') or not grant
            or grant['targetObjectiveId'] != 'web-entries' or grant['phase'] != 'runtime'
            or grant['scope'] != 'bounded_no_model' or grant['nextPass'] != request['executorPass']
            or not 1 <= grant['runtimeCheckpoints'] <= 4 or correction.get('scope') != 'bounded_no_model'
            or diagnosis.get('verdict') != 'pass' or diagnosis.get('scope') != 'bounded_no_model'
            or diagnosis.get('cleanupAssessment') != 'verified' or diagnosis.get('ownerRequest') is not None
            or diagnosis.get('workContinuation') != {'targetObjectiveId': 'web-entries'}):
        raise ValueError('web-zip-runtime-not-authorized')
    desktop, product = request['desktop'], request['product']
    if (not isinstance(desktop, dict) or set(desktop) != {'account', 'sid', 'sessionId'}
            or desktop['account'] != 'joao' or not isinstance(desktop['sid'], str)
            or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', desktop['sid'])
            or type(desktop['sessionId']) is not int or desktop['sessionId'] <= 0
            or not isinstance(product, dict) or set(product) != {'productId', 'analysisName', 'environment'}
            or not isinstance(product['productId'], str)
            or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', product['productId'])
            or not isinstance(product['analysisName'], str)
            or not re.fullmatch(r'Rappor Lab Web ZIP [A-Za-z0-9][A-Za-z0-9 ._-]{0,79}', product['analysisName'])
            or product['environment'] != 'Development'):
        raise ValueError('web-zip-runtime-input-missing')
    manifest = C.artifact(correction['manifest'])
    sources = request['sourceHashes']
    if not isinstance(sources, dict) or set(sources) != set(SOURCE_NAMES):
        raise ValueError('web-zip-source-inventory-mismatch')
    for name in SOURCE_NAMES:
        raw = R.SETTLEMENT.installed_bytes(SOURCE_ROOT / name)
        if R.sha(raw) != sources[name] or manifest['files'].get('source/' + name) != sources[name]:
            raise ValueError('web-zip-installed-source-mismatch')
    return value, receipt, correction, request


def mode(R, root):
    checked = checkpoint(R, root)
    if checked is None or checked[0]['phase'] != 'active':
        return 'none'
    value, _, _, request = checked
    if value['executorPasses'] not in (request['executorPass'] - 1, request['executorPass']):
        raise ValueError('web-zip-pass-outside-checkpoint')
    return 'pending'


def invoke(command):
    # The entrypoint owns the original 600-second absolute runtime budget. This
    # outer fuse never retries guest work, including uncertain transport timeout.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=600)
        return process.returncode, stdout[:65536], stderr[:65536]
    except subprocess.TimeoutExpired:
        for termination in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, termination)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pass
        return 124, b'', b''


def execute(R, root, *, resume_only=False):
    checked = checkpoint(R, root)
    allowed = {'active', 'review_pending'} if resume_only else {'active'}
    if checked is None or checked[0]['phase'] not in allowed:
        raise ValueError('web-zip-checkpoint-required')
    value, _, correction, request = checked
    number = request['executorPass']
    directory = Path(value['reviewCheckpoint']['path']).parent
    packet = root / 'tmp/issue19-native-windows-20261023/candidates' / f'host-web-zip-pass{number}'
    R.HOST.private_directory(packet, root)
    if resume_only and value['executorPasses'] != number:
        raise ValueError('web-zip-reconciliation-not-consumed')
    if value['executorPasses'] == number - 1:
        R.HOST.control(R.C, 'begin', root)
        value = R.C.private(root / 'campaign.json')
    if value['executorPasses'] != number or value['lastFinishedPass'] >= number:
        raise ValueError('web-zip-pass-outside-checkpoint')
    directory = Path(value['reviewCheckpoint']['path']).parent
    output = directory / f'web-zip-output-pass{number}'
    packet = root / 'tmp/issue19-native-windows-20261023/candidates' / f'host-web-zip-pass{number}'
    intent, completion = directory / 'web-zip-host-intent.json', directory / 'web-zip-host-result.json'
    expected = dict(schema=1, executorPass=number, candidate=value['candidate'], checkpoint=value['reviewCheckpoint'],
                    request=correction['webZipRequest'], sourceHashes=request['sourceHashes'])
    if completion.exists():
        result = R.C.artifact(R.reference(completion), protected=True)
        if result.get('binding') != expected:
            raise ValueError('web-zip-host-result-changed')
    else:
        if intent.exists() or resume_only:
            if not intent.exists():
                put(R, intent, R.encoded(expected))
            if R.C.artifact(R.reference(intent), protected=True) != expected:
                raise ValueError('web-zip-host-intent-changed')
            exit_code, stdout, stderr = 125, b'', b''
        else:
            put(R, intent, R.encoded(expected))
            command = ['node', str(SOURCE_ROOT / 'web-zip-runner.mjs'), 'run', '--request',
                       correction['webZipRequest']['path'], '--sha256', correction['webZipRequest']['sha256'],
                       '--output', str(output)]
            exit_code, stdout, stderr = invoke(command)
            # Installed bytes must remain pinned across the host invocation.
            checkpoint(R, root)
        result = dict(schema=1, binding=expected, exitCode=exit_code, outcome='unresolved',
                      stdoutSha256=R.sha(stdout), stdoutBytes=len(stdout), stderrSha256=R.sha(stderr), stderrBytes=len(stderr),
                      primary=None, cleanup=None, instruction=None, executionIntent=None, screenshots={}, invalidOutputs={}, invalidEntryIntent=None)
        # Capture exact host-private files; output text alone never proves success.
        for name in ('primary', 'cleanup', 'instruction'):
            path = output / (name + '.json')
            if path.exists():
                raw = R.SETTLEMENT.installed_bytes(path, private=True, allow_empty=True)
                try:
                    json.loads(raw)
                except (ValueError, UnicodeError):
                    result['invalidOutputs'][name] = dict(sha256=R.sha(raw), bytes=len(raw))
                    continue
                result[name] = put(R, directory / f'web-zip-host-{name}.json', raw)
        entry_intent = directory / f'web-zip-pass{number}.intent.json'
        if entry_intent.exists():
            raw = R.SETTLEMENT.installed_bytes(entry_intent, private=True, allow_empty=True)
            try:
                actual = json.loads(raw)
            except (ValueError, UnicodeError):
                actual = None
            if actual == dict(schema=1, requestSha256=expected['request']['sha256'], sourceHashes=request['sourceHashes']):
                result['executionIntent'] = dict(path=str(entry_intent), sha256=R.sha(raw))
            else:
                # The host intent already consumed the operation. A partial Node
                # intent cannot authorize success or cause another guest launch.
                result['invalidEntryIntent'] = dict(sha256=R.sha(raw), bytes=len(raw))
        if exit_code == 0 and not stderr:
            summary = json.loads(stdout)
            if summary != dict(outcome='completed', outputDirectory=str(output)):
                raise ValueError('web-zip-entrypoint-summary-invalid')
            primary = R.C.artifact(result['primary'], protected=True)
            cleanup = R.C.artifact(result['cleanup'], protected=True)
            instruction = R.C.artifact(result['instruction'], protected=True)
            if (not result['executionIntent'] or primary.get('outcome') != 'completed'
                    or primary.get('requestSha256') != expected['request']['sha256']
                    or primary.get('sourceHashes') != request['sourceHashes']
                    or primary.get('candidate') != value['candidate']
                    or instruction.get('executorPass') != number or instruction.get('candidate') != value['candidate']
                    or instruction.get('product') != request['product']
                    or not first_upload_matches(primary, request['product'])
                    or cleanup.get('requestSha256') != expected['request']['sha256']
                    or cleanup.get('sourceHashes') != request['sourceHashes']
                    or cleanup.get('instructionSha256') != result['instruction']['sha256']
                    or cleanup.get('failureCode') is not None or cleanup.get('credentialClosed') is not True
                    or cleanup.get('remoteQuiescenceObserved') is not True
                    or type(cleanup.get('elapsedMs')) not in (int, float) or not 0 <= cleanup['elapsedMs'] <= 600000
                    or any(cleanup.get('cleanup', {}).get(key) is not True
                           for key in ('verified', 'runtimeRootAbsent', 'loginMaterialAbsent'))):
                raise ValueError('web-zip-runtime-receipt-invalid')
            hashes = {'confirmation.png': primary['confirmationScreenshotSha256'],
                      'execution.png': primary['rendered']['executionScreenshotSha256'],
                      'history.png': primary['rendered']['historyScreenshotSha256']}
            for name, digest in hashes.items():
                raw = R.SETTLEMENT.installed_bytes(output / name, private=True)
                if not 100 <= len(raw) <= 524288 or R.sha(raw) != digest:
                    raise ValueError('web-zip-screenshot-changed')
                result['screenshots'][name] = dict(path=str(output / name), sha256=digest)
            result['outcome'] = 'completed'
        put(R, completion, R.encoded(result))
    retain_packet(R, root, value, request, packet, completion, result)
    R.C.save(root / 'campaign-result.json', dict(schema=1, issue=19, executorPass=number,
        authorizationId=request['authorizationId'], phase='review_pending',
        summary='Host Web ZIP execution finished with protected evidence for independent review; no model or acceptance.'))
    if value['phase'] == 'active':
        R.HOST.control(R.C, 'finish', root)
    # phase may already have moved to review_pending after an interrupted launch.
    # Preserve that consumed launch and its counters; only finish evidence here.


def reconcile(R, root):
    checked = checkpoint(R, root)
    if checked is None:
        return
    value, _, _, request = checked
    if (value['phase'] in {'active', 'review_pending'}
            and value['executorPasses'] == request['executorPass']
            and value['lastFinishedPass'] < request['executorPass']):
        execute(R, root, resume_only=True)


def first_upload_matches(primary, product):
    execution, rendered = primary.get('execution', {}), primary.get('rendered', {})
    if not isinstance(execution, dict) or not isinstance(rendered, dict):
        return False
    if any(not isinstance(execution.get(key), str)
           or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', execution[key])
           for key in ('id', 'analysisDefinitionId', 'revisionId', 'idempotencyKey')):
        return False
    return (execution.get('productId') == product['productId']
            and execution.get('analysisName') == product['analysisName']
            and execution.get('environment') == product['environment']
            and execution.get('uploadPath') == '/api/products/' + product['productId'] + '/analysis-definitions/uploaded-code'
            and rendered.get('executionId') == execution['id']
            and rendered.get('historyExecutionId') == execution['id']
            and rendered.get('analysisDefinitionId') == execution['analysisDefinitionId']
            and rendered.get('revisionId') == execution['revisionId']
            and rendered.get('productId') == product['productId'])


def retain_packet(R, root, value, request, packet, completion, result):
    R.HOST.private_directory(packet, root)
    files = {}
    def retain(name, raw):
        path = packet / name
        R.HOST.private_directory(path.parent, root)
        files[name] = put(R, path, raw)['sha256']
    retain('web-zip-host-result.json', R.SETTLEMENT.installed_bytes(completion, private=True))
    for name in SOURCE_NAMES:
        retain('source/' + name, R.SETTLEMENT.installed_bytes(SOURCE_ROOT / name))
    for name in ('primary', 'cleanup', 'instruction'):
        if result.get(name):
            R.C.artifact(result[name], protected=True)
            retain(name + '.json', R.SETTLEMENT.installed_bytes(Path(result[name]['path']), private=True))
    if result['outcome'] == 'completed':
        for reference in result['screenshots'].values():
            raw = R.SETTLEMENT.installed_bytes(Path(reference['path']), private=True)
            if R.sha(raw) != reference['sha256']:
                raise ValueError('web-zip-screenshot-changed')
        primary = R.C.artifact(result['primary'], protected=True)
        artifact = dict(schema=1, executorPass=request['executorPass'], candidate=value['candidate'],
                        observationType='rendered_web', executionFingerprint=R.sha(R.encoded(primary['execution'])),
                        requestSha256=result['binding']['request']['sha256'], primary=result['primary'],
                        cleanup=result['cleanup'], screenshots=result['screenshots'])
        retain('web-zip-runtime.json', R.encoded(artifact))
        retain('live-web-zip.json', R.encoded(dict(schema=1, objectiveId='web-entries',
               executorPass=request['executorPass'], candidate=value['candidate'], observationType='rendered_web',
               artifacts={'web-zip-runtime.json': files['web-zip-runtime.json']})))
    manifest = put(R, packet / f'manifest-pass{request["executorPass"]}.json', R.encoded(dict(issue=19,
        executorPass=request['executorPass'], authorizationId=request['authorizationId'], candidate=value['candidate'],
        newLiveActivity=result['outcome'] == 'completed', files=files)))
    put(R, Path(value['reviewCheckpoint']['path']).parent / 'web-zip-host-packet.json', R.encoded(dict(
        schema=1, checkpoint=value['reviewCheckpoint'], result=R.reference(completion), manifest=manifest)))


def execution_snapshot(R, value, selected):
    if value.get('reviewCheckpoint') is None:
        return None
    receipt = R.C.artifact(value['reviewCheckpoint'], protected=True)
    try:
        correction = R.C.artifact(receipt['correction'], protected=True)
    except json.JSONDecodeError:
        return None
    if not isinstance(correction, dict) or 'webZipRequest' not in correction:
        return None
    directory = Path(value['reviewCheckpoint']['path']).parent
    marker = directory / 'web-zip-host-packet.json'
    if not marker.exists():
        raise ValueError('web-zip-host-evidence-missing')
    binding = R.C.artifact(R.reference(marker), protected=True)
    if binding.get('checkpoint') != value['reviewCheckpoint'] or binding.get('manifest') != selected['manifest']:
        raise ValueError('web-zip-review-packet-changed')
    result = R.C.artifact(binding['result'], protected=True)
    if result['binding']['executorPass'] != value['executorPasses']:
        raise ValueError('web-zip-review-pass-changed')
    return result
