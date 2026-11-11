#!/usr/bin/env python3
"""Objective evidence accounting, independent of harness edits and acceptance."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import sys


LEVELS = ('preparation', 'runtime_observation', 'acceptance_candidate')
OBSERVATIONS = ('official_runtime', 'public_contract', 'rendered_web')
HASH = re.compile(r'[a-f0-9]{64}')
MAX_BYTES = 16 * 1024 * 1024
REPLAN = ('Replan the current objective diagnostically: identify the missing observable, '
          'read the existing failure evidence, and choose one bounded discriminating check. '
          'Do not repeat harness preparation or an accepted cycle. Continue independent authorized work; '
          'do not request chat review, renew quota or reset data; test inference requires the exact current protected owner activation.')


def _encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True) + '\n').encode()


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _matrix():
    return json.loads(Path(__file__).with_name('objectives.json').read_text())


def _private(path):
    path = Path(path)
    if path != path.resolve() or path.is_symlink():
        raise ValueError('unsafe-objective-path')
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_size > MAX_BYTES):
        raise ValueError('invalid-objective-private-file')
    return path.read_bytes()


def _json(path):
    return json.loads(_private(path))


def _directory(path):
    path = Path(path)
    if path != path.resolve() or path.is_symlink():
        raise ValueError('unsafe-objective-directory')
    meta = path.stat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o700:
        raise ValueError('invalid-objective-directory')
    return path


def _history(root):
    directory = Path(root) / 'objectives-history'
    if not directory.exists() and not directory.is_symlink():
        return []
    _directory(directory)
    records = []
    previous = None
    ids = {item['id'] for item in _matrix()['objectives']} | {'unclassified'}
    for path in sorted(directory.glob('*.json')):
        raw = _private(path)
        item = json.loads(raw)
        if (not isinstance(item, dict) or item.get('schemaVersion') != 1
                or item.get('objectiveId') not in ids or item.get('acceptanceChanged') is not False
                or item.get('validatedEvidenceLevel') not in LEVELS
                or item.get('requestedEvidenceLevel') not in LEVELS
                or type(item.get('materialProgress')) is not bool
                or type(item.get('preparationStreak')) is not int or item['preparationStreak'] < 0
                or type(item.get('executorPass')) is not int or item['executorPass'] < 1
                or any(not isinstance(item.get(key), str) or not HASH.fullmatch(item[key])
                       for key in ('reviewKey', 'manifestSha256', 'bundleSha256', 'verdictSha256', 'candidateSha256', 'nextActionSha256'))
                or any(not isinstance(item.get(key), list) or any(not isinstance(value, str) or not HASH.fullmatch(value)
                       for value in item[key]) for key in ('runtimeEvidenceHashes', 'runtimeIdentityHashes'))):
            raise ValueError('objective-history-record-invalid')
        if (item.get('sequence') != len(records) + 1 or item.get('previousSha256') != previous
                or path.name != f'{item["sequence"]:08d}-{item["reviewKey"]}.json'):
            raise ValueError('objective-history-chain-invalid')
        records.append(item)
        previous = _hash(raw)
    return records


def _view(root):
    matrix = _matrix()
    history = _history(root)
    last = history[-1] if history else None
    current = last['objectiveId'] if last and last['objectiveId'] != 'unclassified' else matrix['defaultObjectiveId']
    if current == 'windows-cli-local':
        current = matrix['defaultObjectiveId']
    return matrix, history, current


def status(root):
    """Return fixed English labels and validated counters, never review prose or paths."""
    matrix, history, current = _view(root)
    result = []
    for objective in matrix['objectives']:
        records = [item for item in history if item['objectiveId'] == objective['id']]
        result.append(dict(objectiveId=objective['id'], title=objective['title'],
                           acceptanceState=objective['baseline'], source=objective['source'],
                           current=objective['id'] == current,
                           evidenceLevel=records[-1]['validatedEvidenceLevel'] if records else 'baseline',
                           materialObservations=sum(item['materialProgress'] for item in records),
                           preparationStreak=history[-1]['preparationStreak'] if objective['id'] == current and history else 0))
    return result


def public_status(root):
    """Owner-facing Portuguese summary; accepted count is not a completion percentage."""
    labels = {'managed-technical': 'verificações técnicas gerenciadas', 'web-entries': 'entradas e resultados Web',
              'negative-consent-cleanup': 'negativas, consentimento e limpeza', 'ide-mcp': 'preparação IDE/MCP',
              'managed-ai': 'preparação da jornada de IA gerenciada', 'linux-cli-local': 'limites da evidência Linux',
              'final-gate': 'pendências do aceite final'}
    rows = status(root)
    current = next(item for item in rows if item['current'])
    text = (f'Atividade atual: {labels[current["objectiveId"]]}. '
            'CLI Windows tem aceite documentado; Linux tem observação técnica com relato autônomo reprovado. '
            'IDE/MCP e IA gerenciada não comprovados; Web, negativas e limpeza têm cobertura parcial. '
            '#19/#17 não concluídas.')
    if current['preparationStreak'] >= 3:
        text += ' Replanejamento diagnóstico requerido, sem nova autorização de quota.'
    return text


def review_context(root):
    matrix, history, current = _view(root)
    return dict(schemaVersion=1, currentObjectiveId=current, objectives=status(root),
                acceptancePolicy=matrix['acceptancePolicy'],
                preparationStreak=history[-1]['preparationStreak'] if history else 0,
                diagnosticReplanning=bool(history and history[-1]['preparationStreak'] >= 3),
                replanningInstruction=REPLAN if history and history[-1]['preparationStreak'] >= 3 else None,
                reviewerFields=dict(objectiveId=[item['id'] for item in matrix['objectives']],
                                    evidenceLevel=list(LEVELS), nextAction='Use the existing concrete nextAction field.'),
                runtimeCandidateContract=(
                    'Cite a live-*.json receipt bound to objectiveId, executorPass and exact candidate; '
                    'observationType is official_runtime, public_contract or rendered_web. '
                    'Its artifacts map relative manifest filenames to SHA-256. Each artifact must match '
                    'the actual file and bundle hash, and contain current-pass/candidate runtime identity '
                    '(executionFingerprint, operationFingerprint or screenshotSha256). '
                    'Notes, mocks, source edits and model pass claims are not runtime evidence. '
                    'Validation records an evidence candidate only and never changes documented acceptance.'))


def prompt(root):
    matrix, history, current = _view(root)
    lines = ['OBJECTIVES #19/#17: preserve the current contract and all budgets; no acceptance by model flag.']
    for item in matrix['objectives']:
        lines.append(f'{item["id"]}: {item["baseline"]}. Required: {item["acceptance"]}')
    selected = next(item for item in matrix['objectives'] if item['id'] == current)
    lines += [f'Current objective: {current}. {selected["nextAction"]}',
              'Harness edits, mocks and notes are preparation. Cite current-pass immutable runtime artifacts for progress.']
    if history and history[-1]['preparationStreak'] >= 3:
        lines.append(REPLAN)
    return '\n'.join(lines)


def _bound_sources(root, directory, bundle):
    campaign = _json(Path(root) / 'campaign.json')
    before = _json(directory / 'before.json')
    if (bundle.get('executorPass') != campaign.get('executorPasses')
            or bundle.get('candidate') != campaign.get('candidate')
            or before.get('executorPasses') != campaign.get('executorPasses')
            or before.get('candidate') != campaign.get('candidate')):
        raise ValueError('objective-current-pass-candidate-mismatch')
    reference = bundle['manifest']
    path = Path(reference['path'])
    roots = [Path(campaign['attemptsRoot']) / 'candidates',
             Path(root) / 'tmp/issue19-native-windows-20261023/candidates']
    if not any(path.is_relative_to(base) for base in roots) or path.name != f'manifest-pass{bundle["executorPass"]}.json':
        raise ValueError('objective-manifest-outside-campaign')
    raw = _private(path)
    if _hash(raw) != reference['sha256']:
        raise ValueError('objective-manifest-changed')
    manifest = json.loads(raw)
    if (manifest.get('issue') != 19 or manifest.get('executorPass') != bundle['executorPass']
            or manifest.get('candidate') != bundle['candidate']
            or manifest.get('authorizationId') != 'issue19-native-windows-20261023'
            or not isinstance(manifest.get('files'), dict) or not 1 <= len(manifest['files']) <= 150):
        raise ValueError('objective-manifest-binding-mismatch')
    sources = bundle['sources']
    if sources['manifest'].get('sha256') != _hash(raw) or sources['manifest'].get('content') != raw.decode():
        raise ValueError('objective-manifest-snapshot-mismatch')
    actual = {}
    for name, digest in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name or not HASH.fullmatch(digest):
            raise ValueError('objective-invalid-evidence-reference')
        data = _private(path.parent / relative)
        source = sources.get(name, {})
        if (_hash(data) != digest or source.get('sha256') != digest
                or (not source.get('omitted') and source.get('content') != data.decode())):
            raise ValueError('objective-evidence-changed')
        actual[name] = data
    return manifest, actual


def _public_runtime_sources(bundle, manifest, actual, verdict):
    """Bind the current public observer's nested packet before accounting evidence."""
    raw = actual.get('runtime-manifest.json')
    if raw is None or ('newLiveActivity' in manifest and manifest['newLiveActivity'] is not True):
        return None
    try:
        runtime = json.loads(raw)
        context = dict(issue=19, executorPass=bundle['executorPass'], candidate=bundle['candidate'],
                       authorizationId=manifest['authorizationId'], objectiveId=verdict['objectiveId'])
        if (not isinstance(runtime, dict) or type(runtime.get('schema')) is not int or runtime['schema'] != 1
                or any(runtime.get(key) != value for key, value in context.items())
                or runtime.get('objectiveId') != 'ide-mcp'
                or runtime.get('observationType') != 'public_contract'
                or runtime.get('newLiveActivity') is not True
                or any(runtime.get(key) is not False for key in ('inferenceStarted', 'windowsAccessed', 'scanStarted'))
                or runtime.get('maxDurationMs') != 15000):
            return None
        live = f'live-pass{bundle["executorPass"]}-public-descriptor.json'
        names = {'public-descriptor.json', 'public-observation.json', live}
        files = runtime.get('files')
        if (not isinstance(files, dict) or set(files) != names
                or any(name not in actual or files[name] != manifest['files'].get(name)
                       or files[name] != _hash(actual[name]) for name in names)):
            return None
        # Both links must refer to the materialized files, not nested hash claims.
        operation = json.loads(actual['public-observation.json'])
        receipt = json.loads(actual[live])
        identity = operation.get('operationFingerprint') if isinstance(operation, dict) else None
        if not isinstance(identity, str) or not HASH.fullmatch(identity):
            return None
        for artifact, links in ((operation, {'public-descriptor.json': files['public-descriptor.json']}),
                                (receipt, {'public-observation.json': files['public-observation.json']})):
            if (not isinstance(artifact, dict)
                    or any(artifact.get(key) != value for key, value in context.items())
                    or artifact.get('observationType') != 'public_contract'
                    or artifact.get('operationFingerprint') != identity
                    or artifact.get('artifacts') != links
                    or any(artifact.get(key) is not False for key in ('inferenceStarted', 'windowsAccessed'))
                    or any(artifact.get(key) is True for key in ('mock', 'simulated', 'preparationOnly'))):
                return None
        return runtime, {name: actual[name] for name in names}
    except (ValueError, UnicodeError, KeyError, TypeError):
        return None


def _runtime_artifacts(bundle, manifest, actual, verdict):
    hashes = set()
    identities_seen = set()
    if verdict['evidenceLevel'] == 'preparation':
        return hashes, identities_seen
    if 'runtime-manifest.json' in actual:
        nested = _public_runtime_sources(bundle, manifest, actual, verdict)
        if nested is None:
            return hashes, identities_seen
        manifest, actual = nested
    if manifest.get('newLiveActivity') is not True:
        return hashes, identities_seen
    for name in verdict.get('evidence', []):
        if name not in actual or not Path(name).name.startswith('live-') or not name.endswith('.json'):
            continue
        try:
            receipt = json.loads(actual[name])
        except (ValueError, UnicodeError):
            continue
        if (not isinstance(receipt, dict) or receipt.get('objectiveId') != verdict['objectiveId']
                or receipt.get('executorPass') != bundle['executorPass'] or receipt.get('candidate') != bundle['candidate']
                or receipt.get('observationType') not in OBSERVATIONS
                or any(receipt.get(key) is True for key in ('mock', 'simulated', 'preparationOnly'))):
            continue
        artifacts = receipt.get('artifacts')
        if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 12:
            continue
        validated = set()
        artifact_hashes = set()
        for filename, digest in artifacts.items():
            if filename == name or filename not in actual or _hash(actual[filename]) != digest or not filename.endswith('.json'):
                break
            try:
                artifact = json.loads(actual[filename])
            except (ValueError, UnicodeError):
                break
            if (not isinstance(artifact, dict) or artifact.get('executorPass') != bundle['executorPass']
                    or artifact.get('candidate') != bundle['candidate']
                    or artifact.get('observationType') != receipt['observationType']
                    or any(artifact.get(key) is True for key in ('mock', 'simulated', 'preparationOnly'))):
                break
            identities = [artifact.get(key) for key in ('executionFingerprint', 'operationFingerprint', 'screenshotSha256')]
            if not any(isinstance(item, str) and HASH.fullmatch(item) for item in identities):
                break
            # Identity hashes, rather than changing pass metadata or notes, determine novelty.
            validated.update(item for item in identities if isinstance(item, str) and HASH.fullmatch(item))
            artifact_hashes.add(digest)
        else:
            hashes.update(artifact_hashes)
            identities_seen.update(validated)
    return hashes, identities_seen


def record_review(root, directory, verdict):
    """Append a validated evidence candidate; never change campaign or acceptance state."""
    root, directory = _directory(Path(root)), _directory(Path(directory))
    bundle_raw = _private(directory / 'bundle.json')
    bundle = json.loads(bundle_raw)
    normalized = dict(verdict)
    if 'objectiveId' not in verdict and 'evidenceLevel' not in verdict:
        normalized.update(objectiveId='unclassified', evidenceLevel='preparation')
    ids = {item['id'] for item in _matrix()['objectives']} | {'unclassified'}
    if normalized.get('objectiveId') not in ids or normalized.get('evidenceLevel') not in LEVELS:
        raise ValueError('invalid-objective-review-fields')
    if normalized['objectiveId'] == 'unclassified' and normalized['evidenceLevel'] != 'preparation':
        raise ValueError('unclassified-review-cannot-progress')
    key = _hash(_encoded([str(directory), bundle['manifest']['sha256']]))
    verdict_hash = _hash(_encoded(normalized))
    lock_path = root / 'objectives-history.lock'
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _private(lock_path)
        history = _history(root)
        for item in history:
            if item['reviewKey'] == key or item['manifestSha256'] == bundle['manifest']['sha256']:
                if item['verdictSha256'] != verdict_hash or item['bundleSha256'] != _hash(bundle_raw):
                    raise ValueError('objective-review-replay-changed')
                return item
        marker_path = root / 'campaign-auto-review.json'
        if marker_path.exists() or marker_path.is_symlink():
            marker = _json(marker_path)
            if (marker.get('directory') != str(directory) or marker.get('bundleSha256') != _hash(bundle_raw)
                    or marker.get('manifest') != bundle['manifest']):
                raise ValueError('objective-review-job-mismatch')
        manifest, actual = _bound_sources(root, directory, bundle)
        runtime, identities = _runtime_artifacts(bundle, manifest, actual, normalized)
        seen = {digest for item in history for digest in item['runtimeEvidenceHashes']}
        seen_identities = {digest for item in history for digest in item['runtimeIdentityHashes']}
        material = bool(runtime - seen) and bool(identities - seen_identities) and normalized['objectiveId'] != 'windows-cli-local'
        streak = 0 if material else (history[-1]['preparationStreak'] if history else 0) + 1
        previous = _hash(_encoded(history[-1])) if history else None
        record = dict(schemaVersion=1, sequence=len(history) + 1, previousSha256=previous,
                      reviewKey=key, bundleSha256=_hash(bundle_raw), manifestSha256=bundle['manifest']['sha256'],
                      verdictSha256=verdict_hash, executorPass=bundle['executorPass'],
                      candidateSha256=_hash(_encoded(bundle['candidate'])), objectiveId=normalized['objectiveId'],
                      requestedEvidenceLevel=normalized['evidenceLevel'],
                      validatedEvidenceLevel=normalized['evidenceLevel'] if runtime else 'preparation',
                      runtimeEvidenceHashes=sorted(runtime), runtimeIdentityHashes=sorted(identities), materialProgress=material,
                      acceptanceChanged=False, preparationStreak=streak,
                      diagnosticReplanning=streak >= 3,
                      nextActionCode='diagnostic_replanning' if streak >= 3 else 'continue_current_objective',
                      nextActionSha256=_hash(str(normalized.get('nextAction', '')).encode()))
        target = root / 'objectives-history'
        target.mkdir(mode=0o700, exist_ok=True)
        _directory(target)
        descriptor_tmp, temporary = tempfile.mkstemp(prefix='.pending-', dir=target)
        try:
            with os.fdopen(descriptor_tmp, 'wb') as output:
                output.write(_encoded(record))
                output.flush()
                os.fsync(output.fileno())
            os.link(temporary, target / f'{record["sequence"]:08d}-{key}.json')
            sync = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(sync)
            finally:
                os.close(sync)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return record
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        action, root = sys.argv[1:3]
        if action == 'public':
            print(public_status(Path(root)))
        elif action == 'prompt':
            print(prompt(Path(root)))
        elif action == 'status':
            print(json.dumps({'objectives': status(Path(root))}))
        else:
            raise ValueError('invalid-objective-action')
    except (OSError, ValueError, KeyError, TypeError):
        print('objectives_error=invalid-or-unavailable-evidence', file=sys.stderr)
        raise SystemExit(65)
