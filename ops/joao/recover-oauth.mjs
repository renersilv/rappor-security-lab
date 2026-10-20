import {assertRecoveryEligible} from './oauth-recovery-policy.mjs';
import {spawn} from 'node:child_process';
import {readFile,writeFile,rename,mkdtemp,rm,lstat} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {HmlClient} from '../../src/run-windows-agent-lab.mjs';
const root='/home/linux/.config/rappor-security-lab';
const origin='https://linux-ai2.taile60a95.ts.net:8443';
const server='rapporLabIssue19';
const scopes=['product.read','product.manage','analysis.read','analysis.execute','problem.read','computer.manage'];
const config=`mcp_servers.${server}.url="${origin}/mcp"`;
const probe=process.argv.includes('--browser-preflight');
let phase='browser-start',browser,cli,socket,folder,client,callback,cliOutput='',browserOutput='';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(check,seconds=15){for(let n=0;n<seconds*5;n++){const v=await check();if(v)return v;await sleep(200);}throw new Error('bounded-wait-expired');}
async function save(path,value){const tmp=path+'.'+process.pid+'.tmp';await writeFile(tmp,JSON.stringify(value),{mode:0o600,flag:'wx'});await rename(tmp,path);}
const startedAtUtc=new Date().toISOString();
const receipt=root+'/issue19-oauth-recovery-'+new Date().toISOString().replace(/[^0-9TZ]/g,'')+'.json';
let recoveryStarted=false;
try{
 for(const name of ['issue19-preparation.json','issue19-hml.env']){const m=await lstat(root+'/'+name);assert.ok(m.isFile()&&!m.isSymbolicLink()&&m.uid===process.getuid()&&(m.mode&0o777)===0o600);}
 folder=await mkdtemp('/tmp/issue19-cdp-');
 browser=spawn('/usr/bin/google-chrome',['--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking',`--user-data-dir=${folder}`,'--remote-debugging-port=0','about:blank'],{stdio:['ignore','ignore','pipe']});
 browser.stderr.on('data',d=>{browserOutput=(browserOutput+d).slice(-65536);});
 const debug=await wait(()=>{if(browser.exitCode!==null)throw new Error('browser-exited');return browserOutput.match(/DevTools listening on (ws:\/\/\S+)/)?.[1];});
 const endpoint=new URL(debug);assert.ok(['127.0.0.1','localhost'].includes(endpoint.hostname));
 const response=await fetch(`http://${endpoint.host}/json/new?about:blank`,{method:'PUT',signal:AbortSignal.timeout(5000)});assert.ok(response.ok);
 const target=await response.json();socket=new WebSocket(target.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',()=>reject(new Error('debug-socket-failed')),{once:true});});
 let id=0;const pending=new Map();let capture;
 const command=(method,params={})=>new Promise((resolve,reject)=>{const key=++id;const timer=setTimeout(()=>{pending.delete(key);reject(new Error('debug-command-timeout'));},8000);pending.set(key,{resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}});socket.send(JSON.stringify({id:key,method,params}));});
 socket.addEventListener('message',event=>{const m=JSON.parse(String(event.data));if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);if(m.error)p.reject(new Error('debug-command-failed'));else p.resolve(m.result);}else if(m.method==='Fetch.requestPaused'){const p=m.params;capture(p,command).catch(()=>{phase='callback-validation-failed';});}});
 const evaluate=async expression=>{const r=await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error('browser-expression-failed');return r.result?.value;};
 await command('Page.enable');await command('Runtime.enable');
 phase='login-page';await command('Page.navigate',{url:origin+'/login'});
 await wait(()=>evaluate(`location.pathname === '/login' && !!document.querySelector('input[type=email]') && !!document.querySelector('input[type=password]')`));
 if(probe){console.log(JSON.stringify({browserPreflight:'passed',sandboxDisabled:false,oauthStarts:0,inferenceStarts:0}));}
 else{
  await writeFile(receipt,JSON.stringify({startedAtUtc,status:'started',inferenceStarts:0}),{mode:0o600,flag:'wx'});recoveryStarted=true;
  const proof=JSON.parse(await readFile(root+'/issue19-preparation.json','utf8'));assert.equal(proof.origin,origin);assert.equal(proof.oauthConfigOverride,config);
  const credentials=Object.fromEntries((await readFile(root+'/issue19-hml.env','utf8')).trim().split('\n').map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1)]));
  assert.equal(credentials.RAPPOR_HML_EMAIL,'lab-issue19-20261015@rappor.test');
  client=new HmlClient(origin);await client.login(credentials.RAPPOR_HML_EMAIL,credentials.RAPPOR_HML_PASSWORD);const previous=await client.request('/api/oauth/applications');const ids=new Set(previous.map(a=>a.authorizationId));
  assertRecoveryEligible(proof,credentials.RAPPOR_HML_EMAIL,previous,scopes);
  phase='browser-login';
  await evaluate(`(()=>{const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;for(const [selector,value] of ${JSON.stringify([['input[type=email]',credentials.RAPPOR_HML_EMAIL],['input[type=password]',credentials.RAPPOR_HML_PASSWORD]])}){const el=document.querySelector(selector);set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));}document.querySelector('button[type=submit]').click();return true;})()`);
  await wait(()=>evaluate(`location.pathname === '/overview'`));
  phase='official-cli';const env={...process.env};delete env.OPENAI_API_KEY;delete env.CODEX_API_KEY;
  cli=spawn('/home/linux/.local/bin/codex',['-c',config,'mcp','login',server,'--no-browser','--oauth-client-registration','cimd','--scopes',scopes.join(',')],{env,stdio:['pipe','pipe','pipe']});
  cli.stdout.on('data',d=>{cliOutput=(cliOutput+d).slice(-65536);});cli.stderr.on('data',d=>{cliOutput=(cliOutput+d).slice(-65536);});
  const exit=new Promise(resolve=>cli.once('exit',resolve));
  const authorization=new URL(await wait(()=>{if(cli.exitCode!==null)throw new Error('cli-exited');return (cliOutput.match(/https:\/\/[^\s]+/g)??[]).find(x=>x.startsWith(origin)&&/authorize|oauth/.test(x));}));assert.equal(authorization.origin,origin);
  const requested=(authorization.searchParams.get('scope')??'').split(/[ ,]+/).filter(Boolean);assert.ok(scopes.every(s=>requested.includes(s)));assert.ok(requested.every(s=>[...scopes,'openid','email','profile','offline_access'].includes(s)));
  const redirect=new URL(authorization.searchParams.get('redirect_uri'));assert.ok(['localhost','127.0.0.1','[::1]'].includes(redirect.hostname));const state=authorization.searchParams.get('state');assert.ok(state);
  capture=async(p,send)=>{const u=new URL(p.request.url);assert.equal(u.origin,redirect.origin);assert.equal(u.pathname,redirect.pathname);assert.equal(u.searchParams.get('state'),state);assert.ok(u.searchParams.get('code'));assert.ok(!u.searchParams.get('error'));callback=u.href;await send('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:200,body:Buffer.from('Laboratory authorization received.').toString('base64')});};
  await command('Fetch.enable',{patterns:[{urlPattern:redirect.origin+'/*',requestStage:'Request'}]});
  phase='consent-page';await command('Page.navigate',{url:authorization.href});
  await wait(()=>callback||evaluate(`location.pathname !== '/overview' && [...document.querySelectorAll('button')].some(b=>/^(autorizar|permitir|authorize|allow)( acesso| access)?$/i.test((b.textContent||'').trim()))`));
  if(!callback){phase='consent-approval';assert.equal(await evaluate(`(()=>{const b=[...document.querySelectorAll('button')].filter(b=>/^(autorizar|permitir|authorize|allow)( acesso| access)?$/i.test((b.textContent||'').trim()));if(b.length!==1)return false;b[0].click();return true;})()`),true);}
  phase='callback-capture';await wait(()=>callback);phase='token-exchange';cli.stdin.write(callback+'\n');assert.equal(await exit,0);
  phase='authorization-verification';const fresh=(await client.request('/api/oauth/applications')).filter(a=>!ids.has(a.authorizationId));assert.equal(fresh.length,1);assert.equal(fresh[0].applicationName,'Codex');assert.ok(scopes.every(s=>fresh[0].scopes.includes(s)));assert.ok(fresh[0].scopes.every(s=>[...scopes,'offline_access','openid','profile','email'].includes(s)));
  const now=new Date().toISOString();proof.oauthAuthorizationHistory=[...(proof.oauthAuthorizationHistory??[]),{authorizationId:proof.authorizationId,replacedAtUtc:now,reason:'assisted_recovery_after_session_expiry'}];Object.assign(proof,{authorizationId:fresh[0].authorizationId,oauthReauthorizedAtUtc:now,oauthPrepared:true,oauthRefreshPersistenceVerified:false});await save(root+'/issue19-preparation.json',proof);
  await save(receipt,{startedAtUtc,completedAtUtc:now,status:'completed',officialCli:true,publicConsentUi:true,systemBrowser:true,inferenceStarts:0,priorAttemptPreserved:true});
  console.log(JSON.stringify({oauthRecovery:'completed',inferenceStarts:0,scopeChanged:false}));
 }
}catch(e){if(recoveryStarted)await save(receipt,{startedAtUtc,failedAtUtc:new Date().toISOString(),status:'failed',phase,errorType:e.name,inferenceStarts:0});console.error(JSON.stringify({phase,errorType:e.name,errorCode:['bounded-wait-expired','browser-exited','browser-expression-failed','debug-command-failed','debug-command-timeout','cli-exited'].includes(e.message)?e.message:'validation-failed',browserExited:browser?.exitCode!==null,inferenceStarts:0}));process.exitCode=1;}
finally{if(client)try{await client.request('/api/auth/logout',{method:'POST',body:{},csrf:true});}catch{}if(cli&&cli.exitCode===null)cli.kill('SIGTERM');socket?.close();if(browser&&browser.exitCode===null){browser.kill('SIGTERM');await sleep(600);}if(folder)await rm(folder,{recursive:true,force:true});}
