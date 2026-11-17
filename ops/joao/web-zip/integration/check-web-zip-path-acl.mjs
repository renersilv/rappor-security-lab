import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import test from 'node:test';
const helperUrl=process.env.WEB_ZIP_ACL_HELPER_SOURCE?pathToFileURL(process.env.WEB_ZIP_ACL_HELPER_SOURCE):new URL('../source/powershell-stdin-transport.mjs',import.meta.url);
const workerUrl=process.env.WEB_ZIP_ACL_WORKER_SOURCE?pathToFileURL(process.env.WEB_ZIP_ACL_WORKER_SOURCE):new URL('../source/web-zip-windows-orchestrator.ps1',import.meta.url);
const {buildWebZipStagePreparation}=await import(helperUrl);
const sid='S-1-5-21-100-200-300-1001';
const prepared={requestSha256:'a'.repeat(64),instruction:{desktop:{sid}},package:{schema:1,instructionBase64:'',instructionSha256:'',archiveBase64:'',archiveSha256:'',workerBase64:'',workerSha256:'b'.repeat(64)}};
const command=buildWebZipStagePreparation(prepared).command;
const publicSource=Buffer.from(command.split(' ').at(-1),'base64').toString('utf16le');
const helperStart=publicSource.indexOf('function Check(');
const helperEnd=publicSource.indexOf("\nCheck 'C:\\RapporLab\\runtime'",helperStart);
assert.ok(helperStart>=0&&helperEnd>helperStart,'complete ACL function must precede the public staging invocation');
const helper=publicSource.slice(helperStart,helperEnd);
const worker=(await readFile(workerUrl,'utf8')).match(/function Assert-WebZipPath\([^]*?\n\}\n/u)?.[0];
assert.ok(helper&&worker,'actual ACL validators required');
// Only native filesystem canonicalization is replaced on Linux; ACL decisions are the actual source.
const fixture=String.raw`
$ErrorActionPreference='Stop';$s='S-1-5-21-100-200-300-1001'
$trusted='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
class FixtureAcl {
 [string]$Owner;[object[]]$Rules
 [object] GetOwner([type]$type){return [pscustomobject]@{Value=$this.Owner}}
 [object[]] GetAccessRules([bool]$explicit,[bool]$inherited,[type]$type){return $this.Rules}
}
function Rule([int]$Rights,[int]$Propagation=0,[string]$Principal='S-1-5-11',[string]$Type='Allow'){
 return [pscustomobject]@{IdentityReference=[pscustomobject]@{Value=$Principal};FileSystemRights=$Rights;PropagationFlags=[Security.AccessControl.PropagationFlags]$Propagation;AccessControlType=[Security.AccessControl.AccessControlType]$Type}
}
function Acl([string]$Owner,[object[]]$Rules){$a=[FixtureAcl]::new();$a.Owner=$Owner;$a.Rules=$Rules;return $a}
function Get-WebZipCanonicalPath([string]$Path){return $Path}
function Get-Item {param([string]$LiteralPath,[switch]$Force,$ErrorAction)
 if(!$script:tree.ContainsKey($LiteralPath)){throw 'fixture-path'}
 return [pscustomobject]@{Attributes=0;PSIsContainer=$true;FullName=$LiteralPath}
}
function Get-Acl {param([string]$LiteralPath,$ErrorAction)return $script:tree[$LiteralPath]}
function Split-Path {param([switch]$Parent,[Parameter(Position=0)][string]$Path)
 switch -CaseSensitive ($Path){'C:\RapporLab\runtime'{return 'C:\RapporLab'}'C:\RapporLab'{return 'C:\'}'C:\'{return ''}'c:\'{return ''}default{throw 'fixture-parent'}}
}
$cases=@(
 @{name='legitimate-volume-private-lab';path='C:\RapporLab\runtime';ok=$true},
 @{name='inherit-only-not-effective';path='C:\RapporLab\runtime';at='C:\RapporLab';rights=1245631;propagation=2;ok=$true},
 @{name='effective-modify-denied';path='C:\RapporLab\runtime';at='C:\RapporLab';rights=1245631;ok=$false},
 @{name='child-effective-inheritance-denied';path='C:\RapporLab\runtime';at='C:\RapporLab\runtime';rights=1245631;ok=$false},
 @{name='lab-create-directory-denied';path='C:\RapporLab';at='C:\RapporLab';rights=4;ok=$false},
 @{name='trusted-installer-not-lab-owner';path='C:\RapporLab';at='C:\RapporLab';owner=$trusted;ok=$false},
 @{name='trusted-installer-not-other-volume-spelling';path='c:\';ok=$false},
 @{name='foreign-owner-denied';path='C:\RapporLab';at='C:\RapporLab';owner='S-1-5-11';ok=$false},
 @{name='foreign-deny-is-not-grant';path='C:\RapporLab';at='C:\RapporLab';rights=1245631;type='Deny';ok=$true}
)
foreach($right in @(2,64,65536,262144,524288,1073741824,268435456)){
 foreach($path in @('C:\','C:\RapporLab','C:\RapporLab\runtime')){$cases+=@{name=('effective-right-'+$right+'-'+$path);path=$path;at=$path;rights=$right;ok=$false}}
}
$failures=@();$passed=0
foreach($case in $cases){
 $script:tree=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 $script:tree['C:\']=Acl $trusted @((Rule 4),(Rule -536805376 2));$script:tree['c:\']=Acl $trusted @((Rule 4));$script:tree['C:\RapporLab']=Acl $s @();$script:tree['C:\RapporLab\runtime']=Acl $s @()
 if($case.ContainsKey('owner')){$script:tree[$case.at].Owner=$case.owner}
 if($case.ContainsKey('rights')){
  $propagation=if($case.ContainsKey('propagation')){$case.propagation}else{0}
  $type=if($case.ContainsKey('type')){$case.type}else{'Allow'}
  $script:tree[$case.at].Rules+=@(Rule $case.rights $propagation 'S-1-5-11' $type)
 }
 $accepted=$false;try{& $validate $case.path;$accepted=$true}catch{}
 if($accepted -ne $case.ok){$failures+=$case.name}else{$passed++}
}
@{cases=$cases.Count;passed=$passed;failed=$failures.Count;failures=$failures}|ConvertTo-Json -Compress
if($failures.Count){exit 65}
`;
for(const [name,source,invoke] of [['staging',helper.replace('[IO.Path]::GetFullPath($p)','(Get-WebZipCanonicalPath $p)'),'Check $target'],['worker',worker,'Assert-WebZipPath $target $s']]){
 test(`actual ${name} ACL validator scopes the Windows volume exception and rejects private-path mutations`,()=>{
  assert.ok(process.env.PWSH_BIN,'PWSH_BIN required; no remote fallback');
  const script=source+`\n$validate={param($target)${invoke}}\n`+fixture;
  const result=spawnSync(process.env.PWSH_BIN,['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:20000,maxBuffer:32768});
  assert.equal(result.error,undefined);assert.equal(result.status,0,`${name}-acl-fixture-failed:${result.stdout.trim()}:${result.stderr.slice(0,600)}`);
  const receipt=JSON.parse(result.stdout);assert.equal(receipt.cases,30);assert.equal(receipt.passed,30);assert.equal(receipt.failed,0);assert.deepEqual(receipt.failures,[]);
 });
}
