import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';
import test from 'node:test';
const local=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const source=process.env.WEB_ZIP_TEST_SOURCE_ROOT??join(local,'source');
const worker=await readFile(join(source,'web-zip-windows-orchestrator.ps1'),'utf8');
const match=worker.match(/function Get-WebZipCreationExpression[^]*?\$script = @'\n([^]*?)\n'@/u);
assert.ok(match,'first-upload wizard browser expression must exist');
// Minimal independent DOM primitive double. This executes the actual browser
// expression, including its selectors and native value/event operations.
class Element {
  constructor(tag,attributes={},children=[]){this.tag=tag;this.attributes=attributes;this.children=children;this.disabled=false;this.innerText='';this.listeners={};}
  getClientRects(){return this.hidden?[]:[{}];}
  matches(selector){
    const excluded=[...selector.matchAll(/:not\(([^)]+)\)/gu)].map(match=>match[1]);
    if(excluded.some(part=>this.matches(part)))return false;
    selector=selector.replace(/:not\([^)]+\)/gu,'');
    const tag=selector.match(/^[a-z]+/u)?.[0];if(tag&&tag!==this.tag)return false;
    return [...selector.matchAll(/\[([^=\]]+)(?:="([^"]*)")?\]/gu)]
      .every(([,name,value])=>Object.hasOwn(this.attributes,name)&&(value===undefined||this.attributes[name]===value));
  }
  querySelectorAll(selector){const selectors=selector.split(',').map(value=>value.trim());
    return this.children.flatMap(child=>[...(selectors.some(value=>child.matches(value))?[child]:[]),...child.querySelectorAll(selector)]);}
  querySelector(selector){return this.querySelectorAll(selector)[0]??null;}
  click(){this.onClick?.();}
  dispatchEvent(event){this.listeners[event.type]?.();return true;}
}
class Input extends Element {
  constructor(attributes={}){super('input',attributes);this.current='';this.files=[];this.checked=false;this.accept=attributes.accept??'';}
  get value(){return this.current;} set value(value){this.current=value;}
}
class Select extends Element {
  constructor(){super('select');this.current='Production';this.options=[{value:'Production'},{value:'Development'}];}
  get value(){return this.current;} set value(value){this.current=value;}
}
function fixture(){
  const product={productId:'00000000-0000-4000-8000-000000000001',analysisName:'Rappor Lab Web ZIP pass238',environment:'Development'};
  const location={pathname:`/products/${product.productId}/analyses/new`};
  const document=new Element('document');document.body={innerText:'v0.92.0'};
  const events=[];let submitted=0,selectedName='',selectedEnvironment='Production';
  const button=(text,onClick,type='button')=>Object.assign(new Element('button',{type}),{innerText:text,onClick});
  const show=(name,controls)=>{document.children=[new Element('div',{'aria-labelledby':`analysis-step-${name}`},controls)];};
  const file=new Input({type:'file',accept:'.zip,application/zip'});
  file.onClick=()=>{events.push('native-picker');file.files=[{name:'synthetic.zip',size:1966,lastModified:1}];};
  const review=()=>show('review',[... [selectedName,selectedEnvironment].map(text=>Object.assign(new Element('dd'),{innerText:text})),
    button('Confirm and start analysis',()=>{submitted++;events.push('submit');},'submit')]);
  const configuration=()=>show('configuration',[file,button('Next',review)]);
  const name=new Input();name.listeners.input=()=>{selectedName=name.value;};
  const environment=new Select();environment.listeners.change=()=>{selectedEnvironment=environment.value;};
  const details=()=>show('details',[name,environment,button('Next',configuration)]);
  const radio=new Input({type:'radio',name:'source-choice',value:'zip'});radio.onClick=()=>{radio.checked=true;events.push('zip');};
  show('source',[radio,button('Next',details)]);
  const action=vm.runInNewContext(`(${match[1]})`,{document,location,HTMLInputElement:Input,HTMLSelectElement:Select,Event:class{constructor(type){this.type=type;}}});
  return {product,document,location,file,events,name,environment,radio,run:name=>action({action:name,product}),submitted:()=>submitted};
}
function throughReview(f){
  assert.equal(f.run('ready').ready,true);f.run('choose-zip');assert.equal(f.run('zip-selected'),true);f.run('source-next');
  assert.equal(f.run('details-ready'),true);f.run('fill-details');assert.equal(f.run('details-match'),true);f.run('details-next');
  assert.equal(f.run('file-ready'),true);f.run('open-picker');assert.equal(f.run('selection').name,'synthetic.zip');
  f.run('configuration-next');assert.equal(f.run('review'),true);
}
test('public first-upload wizard selects native file after synthetic details and confirms once',()=>{
  const f=fixture();throughReview(f);assert.equal(f.submitted(),0);f.run('confirm');
  assert.equal(f.name.value,f.product.analysisName);assert.equal(f.environment.value,'Development');
  assert.deepEqual(f.events,['zip','native-picker','submit']);assert.equal(f.submitted(),1);
});
test('browser wizard rejects unrelated product route before any interaction',()=>{
  const f=fixture();f.location.pathname='/products/unrelated/analyses/new';assert.throws(()=>f.run('choose-zip'),/creation-path-mismatch/);
  assert.deepEqual(f.events,[]);
});
test('browser wizard requires actual ZIP source selector rather than generic page text',()=>{
  const f=fixture();f.radio.attributes.value='repository';assert.throws(()=>f.run('choose-zip'),/creation-control-unavailable/);
});
test('browser wizard rejects substituted review name without submitting',()=>{
  const f=fixture();throughReview(f);f.document.querySelector('dd').innerText='Different analysis';
  assert.throws(()=>f.run('review'),/creation-review-mismatch/);assert.equal(f.submitted(),0);
});
test('browser wizard rejects ambiguous submit controls',()=>{
  const f=fixture();throughReview(f);const review=f.document.children[0];review.children.push(new Element('button',{type:'submit'}));
  assert.throws(()=>f.run('confirm'),/creation-control-unavailable/);assert.equal(f.submitted(),0);
});
test('native picker never replaces an already selected package',()=>{
  const f=fixture();f.run('choose-zip');f.run('source-next');f.run('fill-details');f.run('details-next');f.run('open-picker');
  assert.throws(()=>f.run('open-picker'),/input-not-empty/);
});

test('readiness waits through the same-origin navigation before acting on the wizard',()=>{
  const f=fixture(),path=f.location.pathname;f.location.pathname='/overview';
  assert.equal(f.run('ready').ready,false);assert.deepEqual(f.events,[]);
  f.location.pathname=path;assert.equal(f.run('ready').ready,true);
});

const coverageExpression=worker.match(/function Get-WebZipCoverageExpression[^]*?\$script = @'\n([^]*?)\n'@/u)?.[1];
assert.ok(coverageExpression);
function coverage(count,statuses){
  const paragraphs=[{tagName:'P',innerText:count},{tagName:'P',querySelectorAll:()=>statuses.map(innerText=>({innerText}))}];
  return vm.runInNewContext(coverageExpression,{document:{querySelectorAll:()=>[{innerText:'COVERAGE',getClientRects:()=>[{}],parentElement:{children:paragraphs}}]}});
}
test('rendered coverage accepts exact complete English and Portuguese summaries',()=>{
  assert.equal(coverage('3 of 3 tools',['Complete','Gitleaks, Semgrep, and Trivy completed.']),true);
  assert.equal(coverage('3 de 3 ferramentas',['Completa','Gitleaks, Semgrep e Trivy concluíram.']),true);
});
test('three completed tools with partial Semgrep coverage never establish full coverage',()=>{
  assert.equal(coverage('3 of 3 tools',['Gitleaks, Semgrep, and Trivy completed.','Semgrep limitation']),false);
  assert.equal(coverage('2 of 3 tools',['Complete','Gitleaks, Semgrep, and Trivy completed.']),false);
  assert.equal(coverage('3 of 3 tools',['Complete','Gitleaks and Trivy completed.']),false);
});
