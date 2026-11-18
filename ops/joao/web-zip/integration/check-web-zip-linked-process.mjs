import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFile, spawn} from 'node:child_process';
import {mkdir, readFile, readdir, writeFile} from 'node:fs/promises';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {runWebZipPackage} from '../source/web-zip-runner.mjs';
import {SettlementTransport} from '../source/windows-settlement-transport.mjs';
import {makeRequest} from '../test/web-zip-runner-contract.test.mjs';
const testRoot=dirname(fileURLToPath(import.meta.url));
const platform=join(testRoot,'web-zip-process-platform.ps1');
const syntheticLogin={email:'synthetic-login@example.invalid',password:'Synthetic-Only-Lab-Password!42'};
function invokePowerShell(path,env) {
  return new Promise((resolve,reject)=>{
    const child=execFile(process.env.PWSH_BIN,['-NoLogo','-NoProfile','-NonInteractive','-File',path],
      {env,timeout:20000,killSignal:'SIGKILL',detached:true,maxBuffer:1024*1024},(error,stdout,stderr)=>{
        // Terminate only this test-owned process group if a fixture fault left a
        // descendant alive. A pre-existing sentinel lives outside this group.
        if(Number.isInteger(child.pid)&&child.pid>0){
          try{process.kill(-child.pid,'SIGKILL');}catch(caught){if(caught.code!=='ESRCH'&&!error)return reject(caught);}
        }
        if(error)return reject(Object.assign(error,{stdout,stderr}));
        resolve({stdout,stderr,settlement:{remoteQuiescenceObserved:true,localProcessTerminated:true}});
      });
  });
}
const changedTaskScenarios=['task-principal-foreign','task-principal-unresolvable','task-arguments-changed','task-executable-changed','task-working-directory-changed','task-path-changed','task-logon-changed','task-runlevel-changed','task-multiple-actions'];
for(const scenario of ['success','discovery-failure','ui-initialization-failure','cdp-listener-failure','cdp-target-failure','cdp-socket-failure','page-enable-failure','primary-write-failure','timeout','foreign-dialog','desktop-drift','tampered-instruction','tampered-archive','unbound-root','partial-root-creation','deadline-before-register','transport-timeout','remote-stderr','missing-login','login-rejected','login-cross-origin','login-timeout','missing-created-revision','wrong-created-product','wrong-created-mode','wrong-upload-name','wrong-upload-environment','duplicate-upload','unexpected-mutation','wrong-rendered-revision','wrong-rendered-definition','partial-coverage','task-principal-alias','task-default-working-directory',...changedTaskScenarios,'wizard-readiness-failure','profile-modify','profile-disposal-failure','browser-start-failure']) {
  test(`linked runner and real PowerShell parent/worker processes: ${scenario}`,async t=>{
    assert.ok(process.env.PWSH_BIN,'PWSH_BIN is required; no Windows/SSH fallback is allowed');
    const f=await makeRequest();let sentinel;let executes=0;let transport;let transportFailure;let scenarioPassed=false;
    try{
      sentinel=spawn(process.execPath,['-e','setTimeout(()=>{},60000)'],{stdio:'ignore'});
      await new Promise((resolve,reject)=>{sentinel.once('spawn',resolve);sentinel.once('error',reject);});
      const args=await f.args();
      t.diagnostic(JSON.stringify({testedSourceHashes:f.request.sourceHashes}));
      const physical=join(f.root,'guest-fixture');await mkdir(physical,{mode:0o700});
      let failure;
      try{await runWebZipPackage(args,{
        loadOfficialLogin:async()=>{if(scenario==='missing-login')throw new Error('synthetic-login-unavailable');return {...syntheticLogin};},
        authorizeRuntime:async prepared=>{assert.equal(prepared.request.executorPass,238);},
        verifyHostIdentity:async()=>({result:'verified'}),
        executeRemote:async({source,timeoutMs})=>{
          executes++;assert.equal(executes,1);assert.ok(timeoutMs<=600000);
          if(scenario==='transport-timeout'){
            return new SettlementTransport('').execute(process.execPath,['-e','setTimeout(()=>{},60000)'],
              {input:'',timeout:200,terminationGraceMs:40,maxOutputBytes:4096});
          }
          const boundary=source.lastIndexOf('\nInvoke-WebZipParent -EnvelopeBase64 ');
          assert.ok(boundary>0,'the runner must invoke its bound worker library');
          if(['tampered-instruction','tampered-archive','unbound-root'].includes(scenario)) {
            const invocation=source.slice(boundary);
            const match=invocation.match(/-EnvelopeBase64 '([A-Za-z0-9+/=]+)'/u);
            assert.ok(match);
            const envelope=JSON.parse(Buffer.from(match[1],'base64'));
            if(scenario==='tampered-archive')envelope.archiveBase64=Buffer.from('substituted archive').toString('base64');
            else {
              const instruction=JSON.parse(Buffer.from(envelope.instructionBase64,'base64'));
              instruction.guestRoot='C:\\UnrelatedRoot';
              const bytes=Buffer.from(JSON.stringify(instruction));envelope.instructionBase64=bytes.toString('base64');
              if(scenario==='unbound-root')envelope.instructionSha256=createHash('sha256').update(bytes).digest('hex');
            }
            source=source.slice(0,boundary)+invocation.replace(match[1],Buffer.from(JSON.stringify(envelope)).toString('base64'));
          }
          const combined=source.slice(0,boundary)+`\n. '${platform.replaceAll("'","''")}'\n`+source.slice(boundary);
          const path=join(f.root,'parent.ps1');await writeFile(path,combined,{mode:0o600});
          try {transport=await invokePowerShell(path,{...process.env,WEB_ZIP_PLATFORM_FIXTURE:platform,
            WEB_ZIP_FIXTURE_ROOT:physical,WEB_ZIP_FIXTURE_SCENARIO:scenario,WEB_ZIP_FIXTURE_ROLE:'parent',
            WEB_ZIP_PREEXISTING_PID:String(sentinel.pid)});}catch(error){transportFailure={message:error.message,code:error.code,stdout:error.stdout,stderr:error.stderr};throw error;}
          assert.equal(transport.stderr,'','the actual PowerShell pipeline must not hide errors');
          if(scenario==='remote-stderr')return {...transport,stderr:'synthetic genuine remote error'};
          return transport;
        },
      });}catch(error){failure=error;}
      if(failure)t.diagnostic(JSON.stringify({runnerFailure:failure.message,transportFailure,transport,fixtureRoot:f.root}));
      const receipt=JSON.parse(await readFile(join(args.outputDirectory,'cleanup.json')));
      const events=await readFile(join(physical,'events.txt'),'utf8').catch(()=> '');
      const debug=await readFile(join(physical,'worker-stderr.txt'),'utf8').catch(()=> '');
      for(const name of await readdir(args.outputDirectory)){
        const content=await readFile(join(args.outputDirectory,name));
        for(const forbidden of [syntheticLogin.email,syntheticLogin.password,Buffer.from(JSON.stringify(syntheticLogin)).toString('base64')]){
          assert.equal(content.includes(Buffer.from(forbidden)),false,`secret persisted in ${name}`);
        }
      }
      const material=await readdir(physical,{recursive:true});
      assert.equal(material.some(name=>name.endsWith('login.dpapi')),false,'ephemeral encrypted login material leaked');
      assert.ok(events.split('login-submitted').length-1<=1,'login must not retry');
      if(scenario==='missing-login'){
        assert.equal(executes,0);assert.ok(failure);assert.equal(receipt.cleanup.verified,false);scenarioPassed=true;return;
      }
      assert.equal(executes,1);assert.equal(process.kill(sentinel.pid,0),true,'pre-existing process must remain alive');
      if(['transport-timeout','partial-root-creation','deadline-before-register'].includes(scenario)){
        assert.ok(failure);assert.equal(events.includes('browser-started:'),false);
        assert.equal(events.includes('task-registered'),false);
        if(scenario==='transport-timeout'){
          assert.equal(receipt.transportFailure.cause,'timeout');
          assert.equal(receipt.transportFailure.localProcessTerminated,true);
          assert.equal(receipt.cleanup.verified,false);
        }else if(scenario==='partial-root-creation'){
          assert.equal(receipt.cleanup.verified,false);
          const instruction=JSON.parse(await readFile(join(args.outputDirectory,'instruction.json')));
          const sentinelPath=join(physical,'drive',instruction.guestRoot.slice(3).replaceAll('\\','/'),'partial-sentinel.txt');
          assert.equal(await readFile(sentinelPath,'utf8'),'preserve-unconfirmed-root');
        }
        scenarioPassed=true;return;
      }
      if(['desktop-drift','tampered-instruction','tampered-archive','unbound-root'].includes(scenario)){
        assert.ok(failure);assert.equal(events.includes('browser-started:'),false);
        assert.equal(events.includes('task-registered'),false);
        assert.equal(receipt.cleanup.verified,false);scenarioPassed=true;return;
      }
      assert.ok(events.includes('worker-started:'),`worker was not executed: ${debug}`);
      if(scenario==='browser-start-failure'){
        assert.ok(failure);assert.equal(events.includes('browser-started:'),false);
        assert.equal(receipt.cleanup.verified,true);
        assert.ok(events.includes('profile-restriction-started'));
        scenarioPassed=true;return;
      }
      assert.ok(events.includes('browser-started:'),`actual owned child missing: ${debug}`);
      assert.ok(events.includes('browser-stopped:'),`launched child was not settled: ${events}\n${debug}`);
      if(changedTaskScenarios.includes(scenario)){
        assert.ok(failure,'changed or unresolved task identity must fail closed');
        assert.equal(events.includes('parent-task-removed'),false,'unconfirmed task must not be removed');
        assert.equal(events.includes('parent-task-stop'),false,'unconfirmed task must not be stopped');
        assert.equal(receipt.cleanup.verified,false);
        assert.equal(receipt.cleanup.taskAbsent,false);
        assert.equal(receipt.cleanup.loginMaterialAbsent,true);
        const primary=JSON.parse(await readFile(join(args.outputDirectory,'primary.json')));
        assert.equal(primary.outcome,'inconclusive');
        assert.equal(primary.remoteOutcome,'completed');
        assert.equal(primary.instructionSha256,receipt.instructionSha256);
        assert.equal((await readdir(args.outputDirectory)).some(name=>name.endsWith('.png')),false);
        scenarioPassed=true;return;
      }
      assert.ok(events.includes('parent-task-removed'),`parent did not settle task: ${events}\n${debug}`);
      assert.equal(events.includes('parent-task-stop'),false,'worker must finish its own cleanup before parent removes task');
      assert.equal(receipt.remoteQuiescenceObserved,true);
      if(scenario==='remote-stderr'){
        assert.ok(failure);assert.equal(receipt.cleanup.verified,false);scenarioPassed=true;return;
      }
      if(scenario==='profile-disposal-failure'){
        assert.ok(failure);assert.equal(receipt.cleanup.verified,false);
        assert.equal(receipt.cleanup.ownedProcessesAbsent,true);
        assert.equal(receipt.cleanup.failureCode,'profile_disposal_unresolved');
        assert.equal(receipt.cleanup.runtimeRootAbsent,false);
        assert.ok(events.includes('profile-restriction-started'));
        assert.equal((await readdir(args.outputDirectory)).some(name=>name.endsWith('.png')),false);
        scenarioPassed=true;return;
      }
      assert.equal(receipt.cleanup.verified,true,`${events}\n${debug}`);
      if(scenario==='profile-modify'){
        assert.ok(events.indexOf('browser-stopped:')<events.indexOf('profile-restriction-started'));
      }
      if(['success','profile-modify','task-principal-alias','task-default-working-directory','primary-write-failure','remote-stderr'].includes(scenario)){
        assert.ok(events.includes('login-submitted'),'official form was not submitted');
        assert.ok(events.indexOf('network-disabled')<events.indexOf('login-submitted'));
        assert.ok(events.indexOf('login-submitted')<events.indexOf('network-enabled'));
        assert.equal((events.match(/cdp-connected:/g)||[]).length,1,'login and upload must reuse one browser CDP connection');
        assert.equal((events.match(/browser-started:/g)||[]).length,1,'login must not create another profile/browser');
      }
      if(scenario==='login-cross-origin')assert.equal(events.includes('login-submitted'),false);
      if(['login-rejected','login-timeout'].includes(scenario))assert.equal(events.includes('network-enabled'),false);
      if(['success','profile-modify','task-principal-alias','task-default-working-directory'].includes(scenario)){
        assert.equal(failure,undefined,debug);
        assert.equal(events.split('upload-submitted').length-1,1);
        assert.equal(events.split('picker-opened').length-1,1);
        assert.ok(events.indexOf('zip-chosen')<events.indexOf('synthetic-details-filled'));
        assert.ok(events.indexOf('synthetic-details-filled')<events.indexOf('upload-submitted'));
      }
      else assert.ok(failure,`${scenario} must never be accepted as completed`);
      if(scenario==='partial-coverage')assert.ok(events.includes('partial-coverage-observed'),'partial coverage must be observed before the synthetic work deadline expires');
      const expectedStage={
        'discovery-failure':'browser_readiness','timeout':'browser_readiness','foreign-dialog':'file_selection',
        'ui-initialization-failure':'browser_readiness','cdp-listener-failure':'browser_readiness',
        'cdp-target-failure':'browser_readiness','cdp-socket-failure':'browser_readiness','page-enable-failure':'browser_readiness',
        'login-rejected':'login','login-timeout':'login','login-cross-origin':'login',
        'wizard-readiness-failure':'wizard_readiness','wrong-upload-name':'upload',
        'wrong-rendered-revision':'result','partial-coverage':'result',
      }[scenario];
      if(expectedStage){
        const primary=JSON.parse(await readFile(join(args.outputDirectory,'primary.json')));
        assert.equal(primary.failureStage,expectedStage);
        if(scenario==='discovery-failure'){assert.equal(primary.failureStep,'process_binding');assert.equal(primary.failureReason,'unknown');}
        if(scenario==='timeout'){assert.equal(primary.failureStep,'listener_wait');assert.equal(primary.failureReason,'operation-deadline');}
        const readinessFaults={
          'ui-initialization-failure':['ui_initialization','unknown'],
          'cdp-listener-failure':['cdp_listener','debug-listener-ownership-mismatch'],
          'cdp-target-failure':['cdp_targets','debug-target-mismatch'],
          'cdp-socket-failure':['cdp_socket','unknown'],
          'page-enable-failure':['page_enable','unknown'],
        };
        if(readinessFaults[scenario]){
          assert.deepEqual([primary.failureStep,primary.failureReason],readinessFaults[scenario]);
        }
        if(expectedStage==='browser_readiness'){
          assert.equal(events.includes('login-submitted'),false);
          assert.equal(events.includes('upload-submitted'),false);
          assert.equal(JSON.stringify(primary).includes('Synthetic-Private-Readiness-Detail'),false);
          assert.equal(receipt.cleanup.verified,true);
        }else{
          assert.equal(primary.failureStep,'unknown','readiness step cannot leak into a later stage');
        }
        assert.equal(JSON.stringify(primary).includes('synthetic-private-page-text'),false);
      }
      if(scenario==='foreign-dialog'){
        const primary=JSON.parse(await readFile(join(args.outputDirectory,'primary.json')));
        assert.notEqual(primary.outcome,'completed');
      }
      scenarioPassed=true;
    }finally{
      if(sentinel&&!sentinel.killed){sentinel.kill('SIGKILL');await new Promise(resolve=>sentinel.once('close',resolve));}
      if(scenarioPassed)await f.close();else t.diagnostic('fixture_retained='+f.root);
    }
  });
}
