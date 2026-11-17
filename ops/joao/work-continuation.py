"""Bounded independent work grants, derived only from protected review history."""
import json
import hashlib
from pathlib import Path

TARGETS = ('web-entries', 'managed-technical', 'negative-consent-cleanup')


def runtime_limit(target):
    return 4 if target == 'web-entries' else 1


def runtime_retry(previous_ref, previous, current, verdict, artifact):
    """Verify one corrected Web ZIP retry against its exact consumed predecessor."""
    if (previous['targetObjectiveId'] != 'web-entries' or previous['phase'] != 'runtime'
            or previous['scope'] != 'bounded_no_model' or current['scope'] != 'bounded_no_model'
            or current['reviewPass'] != previous['nextPass']
            or current['sourceFingerprint'] == previous['sourceFingerprint']
            or verdict.get('verdict') != 'pass' or verdict.get('findings') != []
            or verdict.get('scope') != 'bounded_no_model' or verdict.get('cleanupAssessment') != 'verified'
            or verdict.get('ownerRequest') is not None
            or verdict.get('workContinuation') != {'targetObjectiveId': 'web-entries'}):
        raise ValueError('unapproved-web-zip-runtime-retry')
    receipt = artifact(previous_ref, protected=True)
    correction = artifact(receipt['correction'], protected=True)
    request_ref = correction.get('webZipRequest')
    request = artifact(request_ref, protected=True)
    if (request.get('kind') != 'web_zip_execution_request' or request.get('executorPass') != previous['nextPass']
            or request.get('previousReview') != receipt['previousReview']):
        raise ValueError('invalid-web-zip-retry-predecessor')
    proof = verdict.get('technicalCorrection')
    if (not isinstance(proof, dict) or set(proof) != {'incident', 'regressionBefore', 'regressionAfter'}
            or proof['incident'] != previous_ref['sha256'] or proof['regressionBefore'] == proof['regressionAfter']):
        raise ValueError('missing-web-zip-retry-regression')
    manifest = artifact(current['manifest'])
    prior_sources = request.get('sourceHashes')
    if (not isinstance(prior_sources, dict) or not prior_sources
            or any('source/' + name not in manifest['files'] for name in prior_sources)
            or all(manifest['files']['source/' + name] == digest for name, digest in prior_sources.items())):
        raise ValueError('unchanged-web-zip-runtime-source')
    def evidence(name, *, text=False):
        path = Path(name) if isinstance(name, str) else None
        if (path is None or path.is_absolute() or '..' in path.parts or str(path) != name
                or name not in manifest['files']):
            raise ValueError('invalid-web-zip-retry-evidence')
        return artifact(dict(path=str(Path(current['manifest']['path']).parent / path),
                             sha256=manifest['files'][name]), text=text)
    code = {'.mjs', '.js', '.ts', '.tsx', '.ps1', '.py', '.sh', '.c'}
    fingerprints = []
    for grant in (previous, current):
        inventory = artifact(grant['manifest'])['files']
        executable = sorted(digest for name, digest in inventory.items()
                            if Path(name).suffix in code and '.test.' not in name
                            and not name.startswith(('verify-', 'parse-')))
        fingerprint = hashlib.sha256((json.dumps(executable, sort_keys=True, ensure_ascii=True) + '\n').encode()).hexdigest()
        if fingerprint != grant['sourceFingerprint']:
            raise ValueError('web-zip-retry-source-fingerprint-mismatch')
        fingerprints.append(fingerprint)
    checks = []
    for name, fingerprint, outcome in zip((proof['regressionBefore'], proof['regressionAfter']),
                                        fingerprints, ('failed', 'passed')):
        if name not in verdict.get('evidence', []):
            raise ValueError('uncited-web-zip-retry-regression')
        check = evidence(name)
        expected = {'schema', 'kind', 'requestSha256', 'sourceFingerprint', 'command', 'outcome',
                    'passed', 'failed', 'skipped', 'regression', 'regressionSha256', 'log'}
        if (not isinstance(check, dict) or set(check) != expected or check['schema'] != 1
                or check['kind'] != 'web_zip_runtime_retry_regression'
                or check['requestSha256'] != request_ref['sha256'] or check['sourceFingerprint'] != fingerprint
                or check['outcome'] != outcome or not isinstance(check['command'], str)
                or not check['command'].strip() or len(check['command']) > 4096
                or any(type(check[key]) is not int or check[key] < 0 for key in ('passed', 'failed', 'skipped'))
                or check['skipped'] != 0 or (outcome == 'failed' and check['failed'] == 0)
                or (outcome == 'passed' and (check['failed'] != 0 or check['passed'] == 0))
                or manifest['files'].get(check['regression']) != check['regressionSha256']
                or not isinstance(check['log'], dict) or set(check['log']) != {'name', 'sha256'}
                or manifest['files'].get(check['log']['name']) != check['log']['sha256']):
            raise ValueError('invalid-web-zip-retry-regression')
        evidence(check['regression'], text=True)
        evidence(check['log']['name'], text=True)
        checks.append(check)
    before, after = checks
    if (any(before[key] != after[key] for key in ('command', 'regression', 'regressionSha256'))
            or before['passed'] + before['failed'] != after['passed']
            or before['log']['sha256'] == after['log']['sha256']):
        raise ValueError('noncomparable-web-zip-retry-regression')


def selection(verdict):
    value = verdict.get('workContinuation')
    if value is not None and (not isinstance(value, dict) or set(value) != {'targetObjectiveId'}
                              or value['targetObjectiveId'] not in TARGETS):
        raise ValueError('invalid-work-continuation-selection')
    return value


def history(value, artifact):
    rows, records, seen = [], [], set()
    reference = value.get('reviewCheckpoint')
    while reference is not None:
        if len(seen) >= 256 or reference['sha256'] in seen:
            raise ValueError('invalid-work-continuation-chain')
        seen.add(reference['sha256'])
        receipt = artifact(reference, protected=True)
        raw = artifact(receipt['correction'], protected=True, text=True)
        try:
            correction = json.loads(raw)
        except json.JSONDecodeError:
            correction = None
        grant = correction.get('workContinuation') if isinstance(correction, dict) else None
        if grant is not None:
            expected = {'schema', 'targetObjectiveId', 'originObjectiveId', 'entryReviewPass', 'reviewPass',
                        'nextPass', 'phase', 'scope', 'offlineCheckpoints', 'runtimeCheckpoints',
                        'manifest', 'sourceFingerprint'}
            if (not isinstance(grant, dict) or set(grant) != expected or grant['schema'] != 1
                    or grant['targetObjectiveId'] not in TARGETS
                    or grant['reviewPass'] != receipt['reviewedThroughPass']
                    or grant['nextPass'] != grant['reviewPass'] + 1
                    or grant['manifest'] != correction.get('manifest')
                    or grant['sourceFingerprint'] != correction.get('sourceFingerprint')
                    or grant['scope'] != correction.get('scope')
                    or grant['phase'] != ('offline' if grant['scope'] == 'offline' else 'runtime')
                    or grant['scope'] not in {'offline', 'read_only_preflight', 'bounded_no_model'}
                    or type(grant['offlineCheckpoints']) is not int or not 1 <= grant['offlineCheckpoints'] <= 2
                    or type(grant['runtimeCheckpoints']) is not int
                    or not 0 <= grant['runtimeCheckpoints'] <= runtime_limit(grant['targetObjectiveId'])):
                raise ValueError('invalid-work-continuation-grant')
            rows.append(grant)
            records.append((reference, receipt, grant))
        reference = receipt['previousReview']
    counts = {}
    previous_records = {}
    for reference, receipt, grant in reversed(records):
        target = grant['targetObjectiveId']
        old = counts.get(target)
        offline, runtime = old if old else (0, 0)
        offline += grant['phase'] == 'offline'
        runtime += grant['phase'] == 'runtime'
        if (offline, runtime) != (grant['offlineCheckpoints'], grant['runtimeCheckpoints']):
            raise ValueError('work-continuation-budget-mismatch')
        if grant['phase'] == 'runtime' and runtime > 1:
            previous_ref, previous = previous_records[target]
            before = artifact(receipt['beforeState'], protected=True)
            if receipt['previousReview'] != previous_ref or before.get('lastFinishedPass') != grant['reviewPass']:
                raise ValueError('web-zip-retry-predecessor-mismatch')
            runtime_retry(previous_ref, previous, grant, artifact(receipt['diagnosis'], protected=True), artifact)
            current_correction = artifact(receipt['correction'], protected=True)
            request = artifact(current_correction.get('webZipRequest'), protected=True)
            manifest = artifact(grant['manifest'])
            if (request.get('kind') != 'web_zip_execution_request' or request.get('issue') != 19
                    or request.get('authorizationId') != 'issue19-native-windows-20261023'
                    or request.get('candidate') != value['candidate'] or request.get('executorPass') != grant['nextPass']
                    or request.get('previousReview') != previous_ref or not isinstance(request.get('sourceHashes'), dict)
                    or not request['sourceHashes']
                    or any(manifest['files'].get('source/' + name) != digest for name, digest in request['sourceHashes'].items())):
                raise ValueError('invalid-web-zip-retry-request')
        counts[target] = offline, runtime
        previous_records[target] = reference, grant
    return rows


def active(value, artifact):
    rows = history(value, artifact)
    if not rows or not value.get('reviewCheckpoint'):
        return None
    receipt = artifact(value['reviewCheckpoint'], protected=True)
    try:
        correction = json.loads(artifact(receipt['correction'], protected=True, text=True))
    except json.JSONDecodeError:
        return None
    return rows[0] if isinstance(correction, dict) and correction.get('workContinuation') == rows[0] else None


def select(value, verdict, selected, artifact):
    choice = selection(verdict)
    rows = history(value, artifact)
    previous = active(value, artifact)
    if choice is None:
        # A typed rejection can consume the remaining offline correction of its
        # immediate active target; it cannot select another target or runtime.
        if (not previous or previous['phase'] != 'offline'
                or previous['offlineCheckpoints'] != 1 or previous['runtimeCheckpoints'] != 0
                or value['executorPasses'] != previous['nextPass']
                or verdict.get('objectiveId') != previous['targetObjectiveId']
                or verdict['verdict'] != 'changes_requested' or not verdict.get('findings')
                or verdict.get('ownerRequest') is not None or verdict['scope'] != 'offline'
                or verdict['cleanupAssessment'] not in {'verified', 'not_required'}):
            return None
        choice = dict(targetObjectiveId=previous['targetObjectiveId'])
    target = choice['targetObjectiveId']
    same = previous and previous['targetObjectiveId'] == target
    if (verdict['verdict'] == 'owner_required' or verdict['cleanupAssessment'] not in {'verified', 'not_required'}
            or verdict['scope'] not in {'offline', 'read_only_preflight', 'bounded_no_model'}
            or not verdict.get('objectiveId')):
        raise ValueError('unsafe-work-continuation')
    if same:
        if verdict['objectiveId'] != target or value['executorPasses'] != previous['nextPass']:
            raise ValueError('work-continuation-predecessor-mismatch')
        offline, runtime = previous['offlineCheckpoints'], previous['runtimeCheckpoints']
        origin, entry = previous['originObjectiveId'], previous['entryReviewPass']
    else:
        if (any(g['targetObjectiveId'] == target for g in rows) or verdict['objectiveId'] == target
                or verdict['verdict'] != 'pass' or verdict['scope'] != 'offline'):
            raise ValueError('work-continuation-target-not-enterable')
        offline, runtime = 0, 0
        origin, entry = verdict['objectiveId'], value['executorPasses']
    code = ('.mjs', '.js', '.ts', '.tsx', '.ps1', '.py', '.sh', '.c')
    if not any(name.endswith(code) and not any(part in name.lower() for part in ('test', 'verify', 'check'))
               for name in verdict['evidence']):
        raise ValueError('work-continuation-source-citation-required')
    phase = 'offline' if verdict['scope'] == 'offline' else 'runtime'
    if phase == 'runtime' and verdict['verdict'] != 'pass':
        raise ValueError('unapproved-work-runtime')
    offline += phase == 'offline'
    runtime += phase == 'runtime'
    if offline > 2 or runtime > runtime_limit(target) or (phase == 'offline' and runtime):
        raise ValueError('work-continuation-budget-exhausted')
    grant = dict(schema=1, targetObjectiveId=target, originObjectiveId=origin, entryReviewPass=entry,
                reviewPass=value['executorPasses'], nextPass=value['executorPasses'] + 1,
                phase=phase, scope=verdict['scope'], offlineCheckpoints=offline,
                runtimeCheckpoints=runtime, manifest=selected['manifest'],
                sourceFingerprint=selected['sourceFingerprint'])
    if phase == 'runtime' and runtime > 1:
        if value.get('lastFinishedPass') != value['executorPasses']:
            raise ValueError('unfinished-web-zip-retry-predecessor')
        runtime_retry(value['reviewCheckpoint'], previous, grant, verdict, artifact)
    return grant


def status(value, artifact):
    rows = history(value, artifact)
    grant = active(value, artifact)
    return dict(activeTarget=grant['targetObjectiveId'] if grant else None,
                nextPass=grant['nextPass'] if grant else None,
                phase=grant['phase'] if grant else None,
                visitedTargets=sorted({row['targetObjectiveId'] for row in rows}),
                offlineCheckpoints=grant['offlineCheckpoints'] if grant else 0,
                runtimeCheckpoints=grant['runtimeCheckpoints'] if grant else 0)
