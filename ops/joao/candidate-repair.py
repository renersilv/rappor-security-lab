#!/usr/bin/env python3
"""Host-owned offline candidate repair; never execute candidate code on the host."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


R = module('candidate_review', 'campaign-review.py')
C = R.C
RECOVERY = module('candidate_recovery', 'recovery.py')


def sandbox_module():
    return module('candidate_sandbox', 'candidate-repair-sandbox.py')


def directory(path):
    if path.resolve() != path:
        raise ValueError('unsafe-candidate-repair-directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
        raise ValueError('unsafe-candidate-repair-directory')
    return path


def persist(path, value):
    return atomic_put(path, R.encoded(value))


def atomic_put(path, raw):
    """Publish an immutable complete file; never replace an existing artifact."""
    directory(path.parent)
    if path.exists() or path.is_symlink():
        if R.read_source(path, path.parent) != raw:
            raise ValueError('immutable-candidate-repair-artifact-changed')
        return R.reference(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.candidate-pending-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if R.read_source(path, path.parent) != raw:
                raise ValueError('immutable-candidate-repair-artifact-changed')
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return R.reference(path)


def context(root):
    """A valid rejected review is a repair request, not a transport failure."""
    if not (root / 'campaign-auto-review.json').exists():
        return None
    job, marker = R.job(root)
    if marker['phase'] != 'stalled':
        return None
    value = C.private(root / 'campaign.json')
    C.bound(root, value)
    if (value['phase'] != 'review_pending' or value['lastFinishedPass'] != value['executorPasses']
            or marker['executorPass'] != value['executorPasses']
            or C.digest(root / 'campaign.json') != marker['beforeSha256']
            or C.digest(job / 'bundle.json') != marker['bundleSha256']
            or C.digest(job / 'prompt.md') != marker['promptSha256']):
        raise ValueError('candidate-repair-stale-review')
    bundle = C.private(job / 'bundle.json')
    verdict = R.result(job / 'events.jsonl', bundle)
    if C.private(job / 'result.json') != verdict:
        raise ValueError('candidate-repair-result-changed')
    packet = R.packet(value, root)
    if packet['manifest'] != marker['manifest'] or packet['sourceFingerprint'] != marker['sourceFingerprint']:
        raise ValueError('candidate-repair-source-changed')
    routes = R.technical_history(value)
    if (verdict['verdict'] != 'changes_requested' or verdict['scope'] != 'offline'
            or verdict['ownerRequest'] is not None or not routes
            or routes[0]['phase'] != 'correction' or routes[0]['attempt'] != 2):
        return None
    return dict(incident=routes[0]['incident'], route=routes[0], campaign=value,
                marker=marker, packet=packet, verdict=verdict,
                review=R.reference(job / 'result.json'), job=str(job))


def paths(root, ctx):
    folder = C.REVIEW_ROOT / ('candidate-repair-' + ctx['incident'])
    return folder, folder / 'state.json'


def save(root, path, state):
    previous = C.private(path) if path.exists() else {}
    keys = ('phase', 'attempts', 'reason')
    state['noticePending'] = previous.get('noticePending', False) or any(
        previous.get(key) != state.get(key) for key in keys)
    C.save(path, state)
    C.save(root / 'candidate-repair.json', dict(incident=state['incident'],
                                             phase=state['phase'], attempts=state['attempts']))


def pointed_state(root):
    pointer = C.private(root / 'candidate-repair.json')
    incident = pointer.get('incident')
    if not isinstance(incident, str) or not re.fullmatch('[a-f0-9]{64}', incident):
        raise ValueError('invalid-candidate-repair-pointer')
    folder = C.REVIEW_ROOT / ('candidate-repair-' + incident)
    directory(folder)
    state = C.private(folder / 'state.json')
    if state['incident'] != incident:
        raise ValueError('candidate-repair-pointer-mismatch')
    # The private state is authoritative. A crash between the two atomic saves
    # cannot turn an otherwise valid transition into a hash-mismatch dead end.
    return folder, state


def eligible(root):
    if (root / 'candidate-repair.json').exists():
        _folder, previous = pointed_state(root)
        if previous['phase'] == 'adopting':
            after = C.artifact(previous['after'], protected=True)
            now = C.private(root / 'campaign.json')
            verify_bindings(previous, after=now == after)
            if now != after and C.digest(root / 'campaign.json') != previous['protected'][str(root / 'campaign.json')]:
                raise ValueError('candidate-repair-adoption-state-changed')
            marker = C.private(root / 'campaign-auto-review.json')
            R.operator_checkpoint(root, marker, after, replay=marker['phase'] == 'operator_reviewed')
            return True
        if previous['phase'] == 'completed' and previous.get('noticePending'):
            return True
    return context(root) is not None


def retry_binding(root):
    path = root / 'issue-retry'
    if not path.exists():
        return None
    raw = R.read_source(path, root)
    pairs = [line.split('=', 1) for line in raw.decode().splitlines()]
    fields = dict(pairs)
    branch = (root / 'branch').read_text().strip()
    base = (root / 'base_sha').read_text().strip()
    expected = R.sha(f'v1:{base}:{branch}:19:codex_exit:{R.incident_key(root)}'.encode())
    if (len(pairs) != len(fields) or fields.get('issue') != '19'
            or fields.get('branch') != branch or fields.get('error_class') != 'codex_exit'
            or fields.get('fingerprint') != expected):
        raise ValueError('candidate-repair-unrelated-retry')
    return dict(sha256=R.sha(raw), content=raw.decode())


def fixed_bindings(root):
    result = RECOVERY.protected(root)
    for name in ('tmp/issue-19-ai-consumption.json', 'campaign-result.json'):
        path = root / name
        if path.exists():
            result[str(path)] = C.digest(path)
    return result


def verify_bindings(state, *, after=False):
    for path, expected in state['protected'].items():
        if after and Path(path).name == 'campaign.json':
            continue
        if C.digest(Path(path)) != expected:
            raise ValueError('candidate-repair-protected-state-changed')


def model_call(folder, label, prompt, schema, model, effort):
    """Resume transport of the same proposal; never overwrite a failed response."""
    output = folder / (label + '.json')
    if output.exists():
        return C.private(output)
    used = folder / (label + '-calls.json')
    count = C.private(used)['count'] if used.exists() else 0
    if count >= 3:
        raise ValueError('candidate-repair-model-transports-exhausted')
    C.save(used, dict(count=count + 1))
    call = directory(folder / f'{label}-call-{count + 1}')
    result = RECOVERY.call_model(call, label, prompt, schema, model, effort)
    persist(output, result)
    return result


def packet_sources(ctx):
    sources = copy.deepcopy(ctx['packet']['sources'])
    sources.pop('manifest', None)
    # Full canonical helper source closes review gaps; this copy is not editable.
    support = C.installed_support()
    for entry in support['files']:
        if entry['relativePath'] == 'ops/joao/windows-host-identity.py':
            raw = Path(entry['path']).read_bytes()
            if R.sha(raw) != entry['sha256']:
                raise ValueError('candidate-repair-installed-support-changed')
            sources['support/windows-host-identity.py'] = dict(content=raw.decode(), sha256=entry['sha256'])
    return sources


def checked_run(B, attempt, label, tree, tests):
    """Retry an interrupted isolated process, never a proposal or a real test."""
    outcome = attempt / (label + '-result.json')
    if outcome.exists():
        saved = C.private(outcome)
        if saved['tests'] != tests or saved['tree'] != B.tree_hashes(tree):
            raise ValueError('candidate-repair-check-input-changed')
        C.artifact(saved['log'], protected=True, text=True)
        return saved['status'], saved['log']
    for number in (1, 2):
        intent = attempt / f'{label}-run-{number}.json'
        log = attempt / f'{label}-run-{number}.txt'
        expected = dict(tests=tests, tree=B.tree_hashes(tree), logPath=str(log))
        if intent.exists():
            if C.private(intent) != expected:
                raise ValueError('candidate-repair-check-input-changed')
            # Only this fixed sandbox service can outlive an interrupted worker.
            B.stop_incomplete(log)
            continue
        persist(intent, expected)
        status = B.sandbox(tree, tests, log)
        saved = dict(tests=tests, tree=expected['tree'], status=status, log=R.reference(log))
        persist(outcome, saved)
        return status, saved['log']
    raise ValueError('candidate-repair-validation-restarts-exhausted')


def adoption(root, folder, state, ctx, attempt, sources, tests, review):
    """Emit only an offline checkpoint; the normal reviewer still controls runtime."""
    verify_bindings(state)
    if review != dict(verdict='pass', findings=[]):
        raise ValueError('candidate-repair-review-not-approved')
    checkpoint_dir = directory(C.REVIEW_ROOT / ('candidate-adoption-' + ctx['incident']))
    persist(checkpoint_dir / 'automatic-marker-before.json', ctx['marker'])
    before_raw = R.read_source(root / 'campaign.json', root)
    if R.sha(before_raw) != state['protected'][str(root / 'campaign.json')]:
        raise ValueError('candidate-repair-before-state-changed')
    before_ref = atomic_put(checkpoint_dir / 'before.json', before_raw)
    repaired = persist(attempt / 'approved-sources.json', sources)
    proof = persist(checkpoint_dir / 'repair-proof.json', dict(
        schema=1, incident=ctx['incident'], rejectedReview=ctx['review'],
        proposal=R.reference(attempt / 'proposal.json'), sourcePacket=repaired,
        baseline=R.reference(attempt / 'baseline.txt'), checks=R.reference(attempt / 'checks.txt'),
        review=R.reference(attempt / 'review.json'), tests=tests,
        limitation='Offline repair only; no runtime activity or product acceptance.'))
    route = dict(ctx['route'], sourceFingerprint=ctx['packet']['sourceFingerprint'],
                 reviewPass=ctx['campaign']['executorPasses'])
    diagnosis = dict(verdict='pass', findings=[], scope='offline', ownerRequest=None,
                     incident=ctx['incident'], repairProof=proof)
    handoff = (
        'Independent offline candidate repair approved. Scope: offline only.\n'
        'Adopt the exact approved source packet below into a NEW current-pass candidate. '
        'Do not rerun the old candidate or edit any historical artifact. '
        'Retain all original rejection findings and the actual before/after logs. '
        'Run the retained offline tests and include relevant source, installed helper source, '
        'regression logs and this proof in the fresh manifest. The normal independent reviewer '
        'must approve the same incident before any runtime observation. '
        'No Windows, SSH, IDE, MCP, scan, inference, login, cleanup, configuration change, '
        'deadline extension or budget renewal is authorized. '
        'The executor correction counter remains two; this incident cannot reopen repair.\n'
        + R.encoded(dict(sourcePacket=repaired, repairProof=proof, technicalRoute=route,
                         unresolvedProductJourney=True)).decode())
    receipt = dict(schema=1, issue=24, targetIssue=19,
                   reviewedThroughPass=ctx['campaign']['executorPasses'],
                   previousReview=ctx['campaign']['reviewCheckpoint'], beforeState=before_ref,
                   handoff=atomic_put(checkpoint_dir / 'handoff.md', handoff.encode()),
                   diagnosis=persist(checkpoint_dir / 'diagnosis.json', diagnosis),
                   correction=persist(checkpoint_dir / 'correction.json', dict(
                       scope='offline', technicalRoute=route, repairProof=proof,
                       manifest=ctx['packet']['manifest'], sourceFingerprint=ctx['packet']['sourceFingerprint'])),
                   cleanup=persist(checkpoint_dir / 'cleanup.json', dict(
                       scope='offline', assessment=ctx['verdict']['cleanupAssessment'],
                       limitation='No host or guest operation executed by the repair.')),
                   failureFingerprint=R.sha(R.encoded(ctx['verdict']['findings'])))
    for key in ('authorizationSha256', 'stageSha256', 'sessionSha256', 'candidateSha256', 'contractSha256'):
        receipt[key] = ctx['campaign'][key]
    checkpoint = persist(checkpoint_dir / 'review.json', receipt)
    after = dict(ctx['campaign'], phase='active', reviewCheckpoint=checkpoint)
    R.operator_checkpoint(root, ctx['marker'], after)
    persist(checkpoint_dir / 'after.json', after)
    state.update(phase='adopting', checkpoint=checkpoint, after=R.reference(checkpoint_dir / 'after.json'))
    save(root, folder / 'state.json', state)
    complete_adoption(root, folder, state)


def complete_adoption(root, folder, state):
    after = C.artifact(state['after'], protected=True)
    now = C.private(root / 'campaign.json')
    verify_bindings(state, after=now == after)
    if now != after:
        if C.digest(root / 'campaign.json') != state['protected'][str(root / 'campaign.json')]:
            raise ValueError('candidate-repair-adoption-state-changed')
        R.operator_checkpoint(root, C.private(root / 'campaign-auto-review.json'), after)
        C.save(root / 'campaign.json', after)
    R.reconcile(root)
    R.operator_checkpoint(root, C.private(root / 'campaign-auto-review.json'), after, replay=True)
    retry = root / 'issue-retry'
    if retry.exists():
        expected = state['retry']
        if expected is None or C.digest(retry) != expected['sha256']:
            raise ValueError('candidate-repair-retry-changed')
        persist(folder / 'released-retry.json', expected)
        retry.unlink()
    state['phase'] = 'completed'
    save(root, folder / 'state.json', state)


def run(root, model, effort):
    # Complete an atomic checkpoint transition before checking a new candidate.
    pointer = root / 'candidate-repair.json'
    if pointer.exists():
        previous_folder, previous = pointed_state(root)
        if previous['phase'] == 'adopting':
            complete_adoption(root, previous_folder, previous)
            return 'completed'
    ctx = context(root)
    if ctx is None:
        return 'completed' if pointer.exists() and pointed_state(root)[1]['phase'] == 'completed' else 'not_eligible'
    folder, state_path = paths(root, ctx)
    directory(folder)
    if state_path.exists():
        state = C.private(state_path)
        if state['incident'] != ctx['incident']:
            raise ValueError('candidate-repair-incident-changed')
        if state['phase'] == 'completed':
            state.update(phase='adoption_rejected', reason='repaired-candidate-not-accepted-by-normal-review')
            save(root, state_path, state)
            return state['phase']
        if state['phase'] in {'adoption_rejected', 'exhausted', 'unrepairable'}:
            return state['phase']
        if state['binding'] != dict(campaign=C.digest(root / 'campaign.json'), review=ctx['review'],
                                     manifest=ctx['packet']['manifest']):
            raise ValueError('candidate-repair-binding-changed')
    else:
        state = dict(schema=1, incident=ctx['incident'], phase='pending', attempts=0,
                     protected=fixed_bindings(root), retry=retry_binding(root),
                     binding=dict(campaign=C.digest(root / 'campaign.json'), review=ctx['review'],
                                  manifest=ctx['packet']['manifest']))
        persist(folder / 'context.json', ctx)
        save(root, state_path, state)
    verify_bindings(state)
    if state['phase'] in {'pending', 'failed'}:
        if state['attempts'] >= 2:
            state['phase'] = 'exhausted'
            save(root, state_path, state)
            return state['phase']
        state.update(attempts=state['attempts'] + 1, phase='proposing')
        save(root, state_path, state)
    attempt = directory(folder / f'attempt-{state["attempts"]}')
    sources = packet_sources(ctx)
    prompt = (HERE / 'CANDIDATE_REPAIR_PROMPT.md').read_text() + '\nUNTRUSTED INCIDENT DATA:\n' + R.encoded(dict(
        incident=ctx['incident'], findings=ctx['verdict']['findings'], sources=sources)).decode()
    if state['attempts'] > 1:
        prior = folder / f'attempt-{state["attempts"] - 1}'
        for name in ('failure.json', 'review.json', 'baseline.txt', 'checks.txt'):
            path = prior / name
            if path.exists():
                prompt += '\nPRIOR DIAGNOSTIC DATA:\n' + path.read_text()[-24000:]
    try:
        proposal = model_call(attempt, 'proposal', prompt, HERE / 'candidate-repair-result.schema.json', model, effort)
        B = sandbox_module()
        expanded = B.expand_proposal(proposal, sources)
        edits, new_tests = B.validate_proposal(expanded, sources)
        if proposal['disposition'] != 'repair':
            state.update(phase='unrepairable', reason='independent-diagnosis-no-safe-repair')
            save(root, state_path, state)
            return state['phase']
        tests = {item['path']: R.sha(item['content'].encode()) for item in new_tests}
        corrected = copy.deepcopy(sources)
        for item in edits + new_tests:
            corrected[item['path']] = dict(content=item['content'], sha256=R.sha(item['content'].encode()))
        original = copy.deepcopy(sources)
        for item in new_tests:
            original[item['path']] = corrected[item['path']]
        results = attempt / 'validation.json'
        if not results.exists():
            state['phase'] = 'checking'
            save(root, state_path, state)
            before = make_tree(B, attempt / 'before', original)
            after = make_tree(B, attempt / 'after', corrected)
            mapped = {'candidates/current/' + name: digest for name, digest in tests.items()}
            baseline, before_log = checked_run(B, attempt, 'baseline', before, mapped)
            atomic_put(attempt / 'baseline.txt', C.artifact(before_log, protected=True, text=True).encode())
            if baseline != 1:
                raise ValueError('candidate-repair-regression-did-not-reproduce')
            retained = dict(mapped)
            for name, source in corrected.items():
                if ((name.startswith('source/') and name.endswith('.test.mjs'))
                        or re.fullmatch(r'tests/repair-[a-z0-9][a-z0-9-]*\.(?:test\.mjs|py)', name)):
                    retained['candidates/current/' + name] = source['sha256']
            passed, after_log = checked_run(B, attempt, 'checks', after, retained)
            atomic_put(attempt / 'checks.txt', C.artifact(after_log, protected=True, text=True).encode())
            if passed != 0:
                raise ValueError('candidate-repair-checks-failed')
            persist(results, dict(before=baseline, after=passed,
                baseline=R.reference(attempt / 'baseline.txt'), checks=R.reference(attempt / 'checks.txt'),
                sources={name: source['sha256'] for name, source in corrected.items()}, tests=tests))
        validation = C.private(results)
        if (validation['after'] != 0 or validation['before'] != 1
                or validation['sources'] != {name: source['sha256'] for name, source in corrected.items()}
                or validation['tests'] != tests):
            raise ValueError('candidate-repair-validation-changed')
        for name in ('baseline', 'checks'):
            C.artifact(validation[name], protected=True, text=True)
        state['phase'] = 'reviewing'
        save(root, state_path, state)
        review_prompt = (HERE / 'CANDIDATE_REPAIR_REVIEW_PROMPT.md').read_text() + '\nUNTRUSTED DATA:\n' + R.encoded(dict(
            original=sources, corrected=corrected, findings=ctx['verdict']['findings'], proposal=proposal,
            baseline=(attempt / 'baseline.txt').read_text(), checks=(attempt / 'checks.txt').read_text())).decode()
        review = model_call(attempt, 'review', review_prompt, HERE / 'review-result.schema.json', model, effort)
        if review != dict(verdict='pass', findings=[]):
            raise ValueError('candidate-repair-independent-review-rejected')
        adoption(root, folder, state, ctx, attempt, corrected, tests, review)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        reason = str(error)
        reason = reason if re.fullmatch('[a-z-]{1,100}', reason) else 'candidate-repair-operation-failed'
        if state['phase'] not in {'adopting', 'completed'}:
            # Transport failure resumes the same proposal until its closed call limit.
            state['phase'] = 'proposing' if reason == 'recovery-model-failed' else 'failed'
            state['reason'] = reason
            save(root, state_path, state)
            if state['phase'] == 'failed':
                persist(attempt / 'failure.json', dict(reason=reason))
        return state['phase']
    return state['phase']


def make_tree(B, target, sources):
    """Retain original relative imports with closed, verified support copies."""
    expected = {'candidates/current/' + name: source['sha256'] for name, source in sources.items()}
    for name in ('powershell-stdin-transport.mjs', 'windows-settlement-transport.mjs'):
        source = sources.get('installed/' + name)
        if source:
            expected['src/' + name] = source['sha256']
    if target.exists() or target.is_symlink():
        if B.tree_hashes(target) != expected:
            raise ValueError('candidate-repair-snapshot-changed')
        return target
    directory(target.parent)
    staging = Path(tempfile.mkdtemp(prefix='.candidate-tree-', dir=target.parent))
    try:
        directory(staging / 'candidates')
        B.snapshot(dict(sources=sources), staging / 'candidates/current')
        directory(staging / 'src')
        for name in ('powershell-stdin-transport.mjs', 'windows-settlement-transport.mjs'):
            source = sources.get('installed/' + name)
            if source:
                R.put(staging / 'src' / name, source['content'].encode())
        if B.tree_hashes(staging) != expected:
            raise ValueError('candidate-repair-snapshot-changed')
        # Only a complete tree is visible under the immutable validation name.
        os.rename(staging, target)
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['eligible', 'run', 'status', 'notice', 'notice-done'])
    parser.add_argument('root', type=Path)
    parser.add_argument('--model')
    parser.add_argument('--effort')
    args = parser.parse_args()
    if args.action == 'eligible':
        print('yes' if eligible(args.root) else 'no')
    elif args.action == 'run':
        if not args.model or not args.effort:
            raise ValueError('candidate-repair-explicit-model-required')
        print(run(args.root, args.model, args.effort))
    else:
        path = args.root / 'candidate-repair.json'
        if path.exists():
            folder, state = pointed_state(args.root)
            if args.action == 'notice':
                if not state.get('noticePending'):
                    print('none')
                else:
                    messages = {
                        'pending': 'O reparo independente do laboratório está preparado.',
                        'proposing': 'O executor independente está preparando a correção offline dos achados da revisão.',
                        'checking': 'A correção está passando pelos testes isolados antes e depois da mudança.',
                        'reviewing': 'A correção e os testes estão em revisão independente.',
                        'adopting': 'A correção aprovada está sendo encaminhada ao João para adoção offline.',
                        'completed': 'A correção aprovada foi encaminhada ao João automaticamente. O fluxo da plataforma ainda precisa de reteste.',
                        'failed': 'O reparo não passou; o diagnóstico foi preservado para a próxima proposta limitada.',
                        'exhausted': 'As propostas independentes se esgotaram sem aprovação. A tarefa permanece incompleta; não há retomada autorizada por este reparo.',
                        'unrepairable': 'O diagnóstico independente não identificou uma correção segura no escopo permitido. A tarefa permanece incompleta.',
                        'adoption_rejected': 'A revisão normal reprovou a adoção do reparo. O mesmo incidente permanece parado, sem renovar tentativas ou declarar sucesso.',
                    }
                    print(messages[state['phase']] + '\n\nIsso não altera o orçamento de testes reais nem comprova o ciclo IDE/MCP.')
            elif args.action == 'notice-done':
                state['noticePending'] = False
                C.save(folder / 'state.json', state)
            else:
                print(json.dumps(dict(candidate_repair=state['phase'], attempts=state['attempts'],
                                      reason=state.get('reason'))))
        else:
            print('none' if args.action == 'notice' else 'candidate_repair=none')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        print('candidate_repair_error=invalid-or-unavailable-evidence', file=sys.stderr)
        sys.exit(65)
