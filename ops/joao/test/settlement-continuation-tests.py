#!/usr/bin/env python3
"""Closed settlement checkpoints through real protected campaign transitions."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('technical_tests', HERE / 'technical-continuation-tests.py')
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
R, C, S = T.R, T.C, T.R.SETTLEMENT


class SettlementTests(T.TechnicalTests):
    def setUp(self):
        super().setUp()
        self.installed = self.root / 'synthetic-installed-settlement'
        self.source_patch = mock.patch.object(S, 'SOURCE_ROOT', self.installed)
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        for name in S.SOURCE_NAMES:
            target = self.installed / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('// Synthetic source binding fixture: ' + name + '\n')

        initial = C.private(self.state / 'campaign.json')
        original = dict(schema=1, issue=19, executorPass=1, authorizationId=self.auth['authorizationId'],
                        candidate=initial['candidate'], artifacts={'runtime/interactive.ps1': 'a' * 64,
                                                                  'runtime/observe.ps1': 'b' * 64})
        self.add_sources({'live-pass1-ide-mcp-discovery.json': R.encoded(original)})
        self.initial_manifest = self.manifest

    def add_sources(self, files):
        for name, raw in files.items():
            target = self.candidate_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            R.put(target, raw)
        manifest = C.private(self.manifest)
        manifest['files'].update({name: R.sha(raw) for name, raw in files.items()})
        C.save(self.manifest, manifest)

    def add_plan(self, incident, number=2):
        state = C.private(self.state / 'campaign.json')
        original_raw = (self.initial_manifest.parent / 'live-pass1-ide-mcp-discovery.json').read_bytes()
        origin_raw = self.initial_manifest.read_bytes()
        source_bytes = {name: (self.installed / name).read_bytes() for name in S.SOURCE_NAMES}
        plan = dict(schema=1, kind='windows_task_settlement', issue=19,
                    authorizationId=self.auth['authorizationId'], candidate=state['candidate'],
                    executorPass=number + 1, originPass=1, incident=incident,
                    originManifest=dict(file='origin-manifest.json', sha256=R.sha(origin_raw)),
                    originRuntimeReceipt=dict(file='origin-runtime.json', sha256=R.sha(original_raw), manifestName='live-pass1-ide-mcp-discovery.json'),
                    taskName='RapporLab-Pass1-IdeReadiness', guestRoot='C:\\RapporLab\\runtime\\pass1-ide-readiness',
                    ownershipFiles=['owned-processes.json', 'observer-ownership.json'], maxDurationMs=55000,
                    sourceHashes={name: R.sha(raw) for name, raw in source_bytes.items()})
        self.add_sources(dict(source_bytes, **{'origin-manifest.json': origin_raw,
                         'origin-runtime.json': original_raw, 'settlement-plan.json': R.encoded(plan)}))
        return plan

    def open_settlement(self):
        marker = self.early_rejection()
        self.next_packet(2)
        plan = self.add_plan(marker['technicalRoute']['incident'])
        self.repair_response(scope='settlement_only', cleanupAssessment='unresolved',
                             settlementPlan='settlement-plan.json', settlementEvidence=None,
                             evidence=['worker.ps1', 'regression-before.json', 'regression-after.json', 'settlement-plan.json'])
        self.finish()
        return plan

    def receipt(self, plan, plan_sha):
        return dict({key: plan[key] for key in S.CONTEXT}, schema=1, kind='windows_task_settlement_result',
                    planSha256=plan_sha, outcome='settled', taskAbsent=True, rootAbsent=True,
                    ownershipVerified=True, remainingOwnedProcesses=0, transportProbeVerified=True,
                    elapsedMs=100, checkpointSha256=C.private(self.state / 'campaign.json')['reviewCheckpoint']['sha256'],
                    intentSha256=R.sha(R.encoded(dict(fixtureOnly=True))), **{key: False for key in S.FLAGS})

    def host_proof(self, raw):
        state = C.private(self.state / 'campaign.json')
        checkpoint = state['reviewCheckpoint']
        directory = Path(checkpoint['path']).parent
        plan = R.technical_history(state)[0]['settlementPlan']
        R.put(directory / 'settlement-host-result.json', R.encoded(dict(
            schema=1, binding=dict(checkpoint=checkpoint, plan=plan), exitCode=0, outcome='settled',
            receipt=R.put(directory / 'host-receipt-fixture.json', raw),
            executionIntent=R.put(directory / 'host-intent-fixture.json', R.encoded(dict(fixtureOnly=True))))))

    def test_exact_plan_opens_one_settlement_then_bound_receipt_permits_observation(self):
        self.ledger = self.state / 'synthetic-ledger.json'
        C.save(self.ledger, dict(sequence=22, active=False))
        protected = {p: p.read_bytes() for p in [self.auth_path, self.ledger, self.state / 'session']}
        plan = self.open_settlement()
        marker = R.job(self.state)[1]
        route = marker['technicalRoute']
        self.assertEqual(route['phase'], 'settlement')
        self.assertEqual(route['attempt'], 1)
        self.assertEqual(marker['unchangedReviews'], 2)
        self.assertEqual(C.artifact(route['settlementPlan'], protected=True), plan)
        state = C.private(self.state / 'campaign.json')
        receipt = C.artifact(state['reviewCheckpoint'], protected=True)
        correction = C.artifact(receipt['correction'], protected=True)
        self.assertEqual(R.validate_settlement_checkpoint(correction, C.artifact(receipt['diagnosis'], protected=True),
                                                        C.artifact(receipt['beforeState'], protected=True)), plan)
        before = (self.state / 'campaign.json').read_bytes()
        R.reconcile(self.state); self.finish()
        self.assertEqual((self.state / 'campaign.json').read_bytes(), before)
        state['executorPasses'] += 1
        C.enforce_review_limit(state, 2)
        self.assertEqual(state['phase'], 'review_pending')
        raw = R.encoded(self.receipt(plan, route['settlementPlan']['sha256']))
        self.host_proof(raw)
        self.next_packet(3)
        self.add_sources({'settlement-receipt.json': raw})
        self.response(verdict='pass', findings=[], scope='read_only_preflight', cleanupAssessment='verified',
                      technicalCorrection=None, objectiveId='ide-mcp', evidenceLevel='preparation',
                      settlementPlan=None, settlementEvidence='settlement-receipt.json', evidence=['settlement-receipt.json'])
        self.finish(); R.reconcile(self.state)
        self.assertEqual(R.job(self.state)[1]['technicalRoute']['phase'], 'observation')
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 3)
        self.assertFalse(R.OBJECTIVES._history(self.state)[-1]['materialProgress'])
        for path, raw in protected.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_plan_rejects_other_resources_extra_actions_deadline_and_missing_origin(self):
        route = self.early_rejection()['technicalRoute']
        self.next_packet(2)
        plan = self.add_plan(route['incident'])
        bundle = dict(R.packet(C.private(self.state / 'campaign.json'), self.state),
                      executorPass=2, candidate=plan['candidate'],
                      settlementOrigins=R.settlement_origins(C.private(self.state / 'campaign.json')),
                      settlementCleanupOrigin=route['cleanupOrigin'])
        for changes in [dict(taskName='AnotherTask'), dict(guestRoot='C:\\'), dict(originPass=2),
                        dict(maxDurationMs=55001), dict(command='Start-Process Code'),
                        dict(ownershipFiles=[]), dict(guestRoot=plan['guestRoot'].replace(chr(92), chr(92) * 2)), dict(executorPass=4), dict(incident='f' * 64),
                        dict(sourceHashes={}), dict(originManifest=dict(file='missing.json', sha256='f' * 64))]:
            with self.subTest(changes=changes):
                altered = copy.deepcopy(bundle)
                raw = R.encoded(dict(plan, **changes))
                altered['sources']['settlement-plan.json'] = dict(content=raw.decode(), sha256=R.sha(raw))
                with self.assertRaises(ValueError):
                    S.plan(altered, 'settlement-plan.json', route['incident'])

    def test_missing_uncertain_or_replayed_settlement_receipt_cannot_release_observation(self):
        plan = self.open_settlement()
        route = R.job(self.state)[1]['technicalRoute']
        self.host_proof(R.encoded(self.receipt(plan, route['settlementPlan']['sha256'])))
        self.next_packet(3)
        self.response(verdict='pass', findings=[], scope='read_only_preflight', cleanupAssessment='verified',
                      technicalCorrection=None, objectiveId='ide-mcp', evidenceLevel='preparation')
        with self.assertRaisesRegex(ValueError, 'missing-bound-settlement-evidence'):
            self.finish()
        original = self.receipt(plan, route['settlementPlan']['sha256'])
        for change in [dict(planSha256='f' * 64), dict(executorPass=2), dict(taskAbsent=False), dict(rootAbsent=False),
                       dict(ownershipVerified=False), dict(remainingOwnedProcesses=1), dict(remainingOwnedProcesses=False),
                       dict(transportProbeVerified=False), dict(elapsedMs=55001), dict(ideLaunched=True),
                       dict(mcpToolCallIssued=True), dict(inferenceStarted=True), dict(taskName='Other')]:
            with self.subTest(change=change):
                raw = R.encoded(dict(original, **change))
                bundle = dict(executorPass=3, candidate=plan['candidate'],
                              sources={'receipt.json': dict(content=raw.decode(), sha256=R.sha(raw))})
                with self.assertRaises(ValueError):
                    S.receipt(bundle, 'receipt.json', plan, route['settlementPlan']['sha256'])

    def test_installed_source_descriptor_rejects_rename_and_closes_fd(self):
        target = self.installed / S.SOURCE_NAMES[0]
        moved = target.with_name('moved-source.mjs')
        opened = []
        original = S.os.open
        def swap(path, flags):
            descriptor = original(path, flags)
            if path == target:
                opened.append(descriptor)
                target.rename(moved)
                target.write_text('// Replacement source.\n')
            return descriptor
        with mock.patch.object(S.os, 'open', side_effect=swap):
            with self.assertRaisesRegex(ValueError, 'settlement-installed-source-mismatch'):
                S.installed_bytes(target)
        with self.assertRaises(OSError):
            S.os.fstat(opened[0])

    def test_executor_green_receipt_without_host_execution_cannot_enter_review(self):
        self.open_settlement()
        self.next_packet(3)
        self.add_sources({'settlement-result.json': R.encoded(dict(outcome='settled'))})
        with self.assertRaises(FileNotFoundError):
            self.prepare()

    def test_host_interruption_preserves_partial_logs_and_does_not_reexecute(self):
        plan = self.open_settlement()
        value = C.private(self.state / 'campaign.json')
        checkpoint = value['reviewCheckpoint']
        directory = Path(checkpoint['path']).parent
        route = R.technical_history(value)[0]
        request = R.write_settlement_request(self.state, checkpoint, route['settlementPlan'])
        intent = dict(schema=1, executorPass=plan['executorPass'], candidate=plan['candidate'],
                      checkpoint=checkpoint, plan=route['settlementPlan'], request=request)
        R.put(directory / 'settlement-host-intent.json', R.encoded(intent))
        partial = b'Preserved partial output before interruption.\n'
        R.put(directory / 'settlement-host-stdout.txt', partial)
        with mock.patch.object(R.HOST, 'invoke', side_effect=AssertionError('guest-must-not-repeat')):
            R.HOST.execute(R, self.state)
        self.assertEqual((directory / 'settlement-host-stdout.txt').read_bytes(), partial)
        completion = C.private(directory / 'settlement-host-result.json')
        self.assertEqual(completion['exitCode'], 125)
        self.assertEqual(completion['outcome'], 'unresolved')
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 3)
        self.assertEqual(C.private(self.state / 'campaign.json')['phase'], 'review_pending')
        self.assertEqual(R.HOST.mode(R, self.state), 'none')

    def test_host_rejects_packet_and_source_directory_symlinks_without_outside_writes(self):
        plan = self.open_settlement()
        state = C.private(self.state / 'campaign.json')
        route = R.technical_history(state)[0]
        request_ref = R.write_settlement_request(self.state, state['reviewCheckpoint'], route['settlementPlan'])
        output = Path(C.artifact(request_ref, protected=True)['outputDirectory'])
        R.HOST.private_directory(output.parent, self.state)
        outside = self.root / 'outside-host-packet'; outside.mkdir(mode=0o700)
        packet = output.parent / f'host-settlement-pass{plan["executorPass"]}'
        packet.symlink_to(outside, target_is_directory=True)
        with mock.patch.object(R.HOST, 'invoke', side_effect=AssertionError('guest-must-not-start')):
            with self.assertRaisesRegex(ValueError, 'unsafe-settlement-output-directory'):
                R.HOST.execute(R, self.state)
        self.assertEqual(list(outside.iterdir()), [])
        packet.unlink(); packet.mkdir(mode=0o700)
        (packet / 'src').symlink_to(outside, target_is_directory=True)
        directory = Path(state['reviewCheckpoint']['path']).parent
        intent = dict(schema=1, executorPass=plan['executorPass'], candidate=plan['candidate'],
                      checkpoint=state['reviewCheckpoint'], plan=route['settlementPlan'], request=request_ref)
        R.put(directory / 'settlement-host-intent.json', R.encoded(intent))
        with mock.patch.object(R.HOST, 'invoke', side_effect=AssertionError('guest-must-not-repeat')):
            with self.assertRaisesRegex(ValueError, 'unsafe-settlement-output-directory'):
                R.HOST.execute(R, self.state)
        self.assertEqual(list(outside.iterdir()), [])

    def test_host_retains_only_bound_sanitized_failure_diagnostic(self):
        plan = self.open_settlement()
        state = C.private(self.state / 'campaign.json')
        checkpoint = state['reviewCheckpoint']; directory = Path(checkpoint['path']).parent
        route = R.technical_history(state)[0]
        request_ref = R.write_settlement_request(self.state, checkpoint, route['settlementPlan'])
        request = C.artifact(request_ref, protected=True)
        def failed_entrypoint(command):
            output = Path(request['outputDirectory']); output.mkdir(mode=0o700)
            intent = dict(schema=1, requestSha256=request_ref['sha256'], planSha256=route['settlementPlan']['sha256'],
                          checkpoint=checkpoint, outputDirectory=str(output))
            intent_ref = R.put(directory / f'settlement-{route["settlementPlan"]["sha256"]}.intent.json', R.encoded(intent))
            diagnostic = dict(schema=1,kind='windows_task_settlement_unresolved',outcome='unresolved',
                planSha256=route['settlementPlan']['sha256'],checkpointSha256=checkpoint['sha256'],
                intentSha256=intent_ref['sha256'],failedStage='transport_probe',reasonCode='probe_failed',elapsedMs=100)
            R.put(output / 'settlement-unresolved.json', R.encoded(diagnostic))
            return 1,b'',b'Windows resource settlement failed.\n'
        with mock.patch.object(R.HOST, 'invoke', side_effect=failed_entrypoint):
            R.HOST.execute(R, self.state)
        result=C.private(directory / 'settlement-host-result.json')
        self.assertEqual(result['diagnosticStatus'],'validated')
        diagnostic=C.artifact(result['unresolvedDiagnostic'],protected=True)
        self.assertEqual(diagnostic['failedStage'],'transport_probe')
        packet=Path(request['outputDirectory']).parent / 'host-settlement-pass3'
        manifest=C.private(packet / 'manifest-pass3.json')
        self.assertEqual(manifest['files']['settlement-unresolved.json'],result['unresolvedDiagnostic']['sha256'])

    def test_rejected_settlement_uses_only_remaining_offline_correction_then_stops(self):
        self.open_settlement()
        first = R.technical_history(C.private(self.state / 'campaign.json'))[0]
        for attempt in (1, 2):
            with mock.patch.object(R.HOST, 'invoke', return_value=(1, b'', b'Bounded transport failed.\n')):
                R.HOST.execute(R, self.state)
            current = C.private(self.state / 'campaign.json')['executorPasses']
            self.response(verdict='changes_requested', scope='offline', findings=['Fix the bounded transport failure.'],
                cleanupAssessment='unresolved', technicalCorrection=None, settlementPlan=None, settlementEvidence=None,
                evidence=['settlement-host-result.json'], objectiveId='ide-mcp', evidenceLevel='preparation')
            self.finish()
            marker = R.job(self.state)[1]
            if attempt == 2:
                self.assertEqual(marker['phase'], 'stalled')
                self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], 5)
                break
            self.assertEqual(marker['phase'], 'continued')
            route = marker['technicalRoute']
            self.assertEqual((route['phase'], route['attempt']), ('correction', 2))
            self.assertEqual(route['incident'], first['incident'])
            self.assertEqual(route['cleanupOrigin'], first['cleanupOrigin'])
            self.assertNotIn('settlementPlan', route)
            self.assertEqual(R.HOST.mode(R, self.state), 'none')
            self.next_packet(current + 1)
            self.add_plan(route['incident'], number=current + 1)
            self.repair_response(scope='settlement_only', cleanupAssessment='unresolved',
                settlementPlan='settlement-plan.json', settlementEvidence=None,
                evidence=['worker.ps1', 'regression-before.json', 'regression-after.json', 'settlement-plan.json'])
            self.finish()
            self.assertEqual(R.job(self.state)[1]['technicalRoute']['attempt'], 2)

    def test_real_shell_host_entrypoint_receipt_review_and_read_only_resume(self):
        repository = HERE.parents[2]
        self.installed = repository
        S.SOURCE_ROOT = repository
        self.open_settlement()
        self.run_shell_settlement(repository, expected_reviews=3)

    def run_shell_settlement(self, repository, expected_reviews):
        initial = C.private(self.state / 'campaign.json')
        expected_pass = initial['executorPasses'] + 2
        protected = {path: path.read_bytes() for path in (self.auth_path, self.state / 'session')}
        scripts = self.root / 'installed-wrapper'
        shutil.copytree(HERE.parent, scripts)
        for filename in ('campaign-control.py', 'recovery.py'):
            controller = scripts / filename
            controller.write_text(controller.read_text().replace(
                "Path.home() / '.config/rappor-security-lab/campaign-reviews'", f'Path({str(self.operator)!r})'))
        contract = scripts / 'settlement-contract.py'
        contract.write_text(contract.read_text().replace(
            'SOURCE_ROOT = Path(__file__).resolve().parents[2]', f'SOURCE_ROOT = Path({str(repository)!r})'))
        fake_bin = self.root / 'fixture-bin'; fake_bin.mkdir()
        real_node = shutil.which('node')
        observed = self.root / 'entrypoint-observed.json'
        driver = self.root / 'entrypoint-fixture.mjs'
        driver.write_text('''import { pathToFileURL } from "node:url";
import { writeFile, rm } from "node:fs/promises";
const { settlementFixture } = await import(__FACTORY__);
const [entrypoint,requestPath,requestSha256,protectedRoot] = process.argv.slice(2);
const { settleWindowsResources } = await import(pathToFileURL(entrypoint).href);
const fixture = await settlementFixture();
try {
  const dependencies={...fixture.dependencies,protectedRoot,stateRoot:__STATE__};
  const result=await settleWindowsResources({requestPath,requestSha256,protectedRoot},dependencies);
  await writeFile(__OBSERVED__,JSON.stringify({calls:fixture.calls,closed:fixture.closed,result}));
  process.stdout.write(JSON.stringify(result)+"\\n");
} finally { await rm(fixture.root,{recursive:true,force:true}); }
'''.replace('__FACTORY__', json.dumps((repository / 'test/support-settlement-fixture.mjs').as_uri()))
            .replace('__STATE__', json.dumps(str(self.state))).replace('__OBSERVED__', json.dumps(str(observed))))
        node = fake_bin / 'node'
        node.write_text('#!' + shutil.which('python3') + '\nimport os,sys\nos.execv(' + repr(real_node) + ', [' +
                        repr(real_node) + ', ' + repr(str(driver)) + ', *sys.argv[1:]])\n')
        node.chmod(0o700)
        approved = dict(verdict='pass', findings=[], scope='read_only_preflight',
                        nextAction='Continue only the separately authorized read-only observation; no model or scan.',
                        evidence=['settlement-result.json'], cleanupAssessment='verified', progress='none',
                        ownerRequest=None, objectiveId='ide-mcp', evidenceLevel='preparation',
                        technicalCorrection=None, settlementPlan=None, settlementEvidence='settlement-result.json')
        reviewer = self.root / 'reviewer.py'
        reviewer.write_text('#!' + shutil.which('python3') + '\nimport json,sys\n'
            'assert "read-only" in sys.argv and "--disable" in sys.argv\n'
            'assert "settlementExecutionSnapshot" in sys.stdin.read()\n'
            'print(' + repr(json.dumps(dict(type='item.completed', item=dict(type='agent_message', text=json.dumps(approved))))) + ')\n')
        reviewer.chmod(0o700)
        shell = r'''
set -euo pipefail
umask 077
SCRIPT_DIR=$1 STATE_ROOT=$2 CODEX_BIN=$3
TIMEOUT_BIN=timeout MODEL=fixture REASONING_EFFORT=xhigh
source "$SCRIPT_DIR/campaign.sh"
campaign_review_notice() { :; }
campaign_review_flush_notice() { :; }
issue_operational_state() { printf doing; }
log() { :; }
run_codex() { touch "$STATE_ROOT/model-called"; return 124; }
execute_campaign_item 19 "$4" "$5"
[[ ! -e $STATE_ROOT/model-called ]]
[[ $(campaign_review_command phase) == continued ]]
result=0
execute_campaign_item 19 "$4" "$5" || result=$?
[[ $result == 124 && -e $STATE_ROOT/model-called ]]
'''
        execution = subprocess.run(['bash', '-c', shell, 'fixture', str(scripts), str(self.state), str(reviewer),
                                    str(self.worktree), self.stage['branch']], capture_output=True, text=True,
                                   env=dict(os.environ, PATH=str(fake_bin) + ':' + os.environ['PATH']), timeout=30)
        self.assertEqual(execution.returncode, 0, execution.stdout + execution.stderr)
        observation = json.loads(observed.read_text())
        self.assertTrue(observation['closed'])
        self.assertEqual(observation['calls'], 2)
        directory = Path(initial['reviewCheckpoint']['path']).parent
        completion = C.private(directory / 'settlement-host-result.json')
        self.assertEqual(completion['outcome'], 'settled')
        self.assertEqual(completion['exitCode'], 0)
        self.assertEqual(R.job(self.state)[1]['technicalRoute']['phase'], 'observation')
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], expected_reviews)
        self.assertEqual(C.private(self.state / 'campaign.json')['executorPasses'], expected_pass)
        for path, raw in protected.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_assisted_checkpoint_uses_same_plan_proof_and_preserves_original_review(self):
        repository = HERE.parents[2]
        self.installed = repository
        S.SOURCE_ROOT = repository
        # A historical untyped rejection sequence is retained; the new approval is separate.
        for number in range(1, 7):
            if number > 1:
                self.next_packet(number)
            self.response(objectiveId='ide-mcp', evidenceLevel='preparation', cleanupAssessment='unresolved')
            self.finish()
        marker = R.job(self.state)[1]
        self.assertEqual(marker['phase'], 'stalled')
        before = C.private(self.state / 'campaign.json')
        stopped_dir = Path(marker['directory'])
        original_result = (stopped_dir / 'result.json').read_bytes()
        folder = self.operator / 'assisted-settlement'
        folder.mkdir(mode=0o700)
        R.put(folder / 'automatic-marker-before.json', (self.state / 'campaign-auto-review.json').read_bytes())
        origin = R.pending_cleanup_origin(before)
        incident = origin['incident']
        original_manifest = self.manifest
        original_manifest_raw = original_manifest.read_bytes()
        self.candidate_dir = self.root / 'assisted-supplement'
        self.candidate_dir.mkdir(mode=0o700)
        self.manifest = self.candidate_dir / 'manifest-pass6.json'
        C.save(self.manifest, dict(issue=19, executorPass=6, candidate=before['candidate'],
                                 authorizationId=self.auth['authorizationId'], files={}))
        self.add_sources({'regression-before.json': R.encoded(dict(outcome='reproduced')),
                          'regression-after.json': R.encoded(dict(outcome='passed'))})
        plan = self.add_plan(incident, number=6)
        # This is a separately reviewed supplementary snapshot, not a rewritten automatic packet.
        manifest = C.private(self.manifest)
        sources = {}
        for name in manifest['files']:
            raw = (self.candidate_dir / name).read_bytes()
            sources[name] = dict(content=raw.decode(), sha256=R.sha(raw))
        bundle = dict(executorPass=6, candidate=before['candidate'], sources=sources, sourceFingerprint='d' * 64)
        plan_ref = R.put(folder / 'settlement-plan.json', S.source(bundle, 'settlement-plan.json'))
        correction = dict(scope='settlement_only',
            technicalRoute=dict(incident=incident, phase='settlement', attempt=2, reviewPass=6,
                                sourceFingerprint=bundle['sourceFingerprint'], settlementPlan=plan_ref,
                                cleanupOrigin={key: origin[key] for key in ('executorPass', 'manifestSha256')}),
            settlementBundle=R.put(folder / 'settlement-bundle.json', R.encoded(dict(planName='settlement-plan.json', bundle=bundle))))
        diagnosis = dict(verdict='pass', findings=[], ownerRequest=None, scope='settlement_only',
                         cleanupAssessment='unresolved', settlementPlan='settlement-plan.json',
                         evidence=['settlement-plan.json', 'regression-before.json', 'regression-after.json'],
                         technicalCorrection=dict(incident=incident, regressionBefore='regression-before.json',
                                                  regressionAfter='regression-after.json'))
        receipt = dict(schema=1, issue=24, targetIssue=19, reviewedThroughPass=6,
                       previousReview=before['reviewCheckpoint'], beforeState=R.put(folder / 'before.json', R.encoded(before)),
                       handoff=R.put(folder / 'handoff.md', b'Perform only the exact host settlement plan.\n'),
                       diagnosis=R.put(folder / 'diagnosis.json', R.encoded(diagnosis)),
                       correction=R.put(folder / 'correction.json', R.encoded(correction)),
                       cleanup=R.put(folder / 'cleanup.json', R.encoded(dict(scope='settlement_only'))), failureFingerprint=incident)
        for key in ('authorizationSha256', 'stageSha256', 'sessionSha256', 'candidateSha256', 'contractSha256'):
            receipt[key] = before[key]
        checkpoint = R.put(folder / 'review.json', R.encoded(receipt))
        C.save(self.state / 'campaign.json', dict(before, phase='active', reviewCheckpoint=checkpoint))
        R.reconcile(self.state)
        self.assertEqual(R.job(self.state)[1]['phase'], 'operator_reviewed')
        self.assertEqual((stopped_dir / 'result.json').read_bytes(), original_result)
        self.assertEqual(original_manifest.read_bytes(), original_manifest_raw)
        self.assertEqual(R.job(self.state)[1]['unchangedReviews'], 6)
        R.reconcile(self.state)
        self.assertEqual(R.technical_history(C.private(self.state / 'campaign.json'))[0]['attempt'], 2)
        self.run_shell_settlement(repository, expected_reviews=7)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(SettlementTests(name) for name in SettlementTests.__dict__ if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main()
