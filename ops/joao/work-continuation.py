"""Bounded independent work grants, derived only from protected review history."""
import json

TARGETS = ('web-entries', 'managed-technical', 'negative-consent-cleanup')


def selection(verdict):
    value = verdict.get('workContinuation')
    if value is not None and (not isinstance(value, dict) or set(value) != {'targetObjectiveId'}
                              or value['targetObjectiveId'] not in TARGETS):
        raise ValueError('invalid-work-continuation-selection')
    return value


def history(value, artifact):
    rows, seen = [], set()
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
                    or type(grant['runtimeCheckpoints']) is not int or not 0 <= grant['runtimeCheckpoints'] <= 1):
                raise ValueError('invalid-work-continuation-grant')
            rows.append(grant)
        reference = receipt['previousReview']
    counts = {}
    for grant in reversed(rows):
        target = grant['targetObjectiveId']
        old = counts.get(target)
        offline, runtime = old if old else (0, 0)
        offline += grant['phase'] == 'offline'
        runtime += grant['phase'] == 'runtime'
        if (offline, runtime) != (grant['offlineCheckpoints'], grant['runtimeCheckpoints']):
            raise ValueError('work-continuation-budget-mismatch')
        counts[target] = offline, runtime
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
    if choice is None:
        return None
    rows = history(value, artifact)
    previous = active(value, artifact)
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
    if offline > 2 or runtime > 1 or (phase == 'offline' and runtime):
        raise ValueError('work-continuation-budget-exhausted')
    return dict(schema=1, targetObjectiveId=target, originObjectiveId=origin, entryReviewPass=entry,
                reviewPass=value['executorPasses'], nextPass=value['executorPasses'] + 1,
                phase=phase, scope=verdict['scope'], offlineCheckpoints=offline,
                runtimeCheckpoints=runtime, manifest=selected['manifest'],
                sourceFingerprint=selected['sourceFingerprint'])


def status(value, artifact):
    rows = history(value, artifact)
    grant = active(value, artifact)
    return dict(activeTarget=grant['targetObjectiveId'] if grant else None,
                nextPass=grant['nextPass'] if grant else None,
                phase=grant['phase'] if grant else None,
                visitedTargets=sorted({row['targetObjectiveId'] for row in rows}),
                offlineCheckpoints=grant['offlineCheckpoints'] if grant else 0,
                runtimeCheckpoints=grant['runtimeCheckpoints'] if grant else 0)
