import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { POWERSHELL_STDIN_BOOTSTRAP_BASE64 } from "../../src/powershell-stdin-transport.mjs";
const image = "mcr.microsoft.com/dotnet/sdk@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b";
function powershell(source, framed = true) {
  return spawnSync("docker", ["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--env", "HOME=/tmp",
    "--user", "65534:65534", "-i", image, "/usr/bin/pwsh", "-NoLogo", "-NoProfile", "-NonInteractive",
    ...(framed ? ["-EncodedCommand", POWERSHELL_STDIN_BOOTSTRAP_BASE64] : ["-Command", "-"])],
  { input: source, encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024 });
}
const digest = value => createHash("sha256").update(value).digest("hex");
test("actual PowerShell reproduces historical multiline parsing failure and fixed framing", () => {
  const source = "& {\n  $value = [ordered]@{ probe = 'complete' }\n  $value | ConvertTo-Json -Compress\n}\n";
  const before = powershell(source, false);
  assert.equal(before.error, undefined);
  assert.notEqual(before.stdout.trim(), '{"probe":"complete"}', "historical framing must reproduce the missing result");
  const after = powershell(source);
  assert.equal(after.error, undefined); assert.equal(after.status, 0, after.stderr);
  assert.deepEqual(JSON.parse(after.stdout), { probe: "complete" });
});
test("actual PowerShell executes the fixed settlement functions against closed local cmdlet fixtures", async () => {
  const source = (await readFile(new URL("../../src/windows-resource-settlement.ps1", import.meta.url), "utf8"))
    .replaceAll("__ORIGIN_PASS__", "220").replace("__DURATION_MS__", "30000").replace("__INTERACTIVE_SHA256__", digest("interactive-original"))
    .replace("__OBSERVER_SHA256__", digest("observer-original"));
  const start = source.indexOf("\nAssert-Deadline\nAssert-Root\n");
  assert.ok(start > 0);
  const definitions = source.slice(0, start), body = source.slice(start);
  const fixture = `
$ErrorActionPreference = 'Stop'
$scenarios = @('absent','empty-owned-root','owned-process','wrong-action','wrong-principal','changed-script','generation-reuse','unknown-related','unreadable-command','task-query-error','process-query-error','reparse-child','running-task')
foreach ($scenario in $scenarios) {
    $directory = Join-Path '/tmp' ([Guid]::NewGuid().ToString())
    [void](New-Item -ItemType Directory -Path $directory)
    [void](New-PSDrive -Name C -PSProvider FileSystem -Root $directory)
    $root = 'C:\\RapporLab\\runtime\\pass220-ide-readiness'
    $script:task = $null
    $script:processes = @()
    $script:rows = @()
    $script:killed = @()
    $script:unregistered = $false
    $script:stopped = $false
    if ($scenario -ne 'absent') {
        [void](New-Item -ItemType Directory -Path $root -Force)
        [IO.File]::WriteAllText((Join-Path $directory 'RapporLab/runtime/pass220-ide-readiness/interactive.ps1'), 'interactive-original')
        [IO.File]::WriteAllText((Join-Path $directory 'RapporLab/runtime/pass220-ide-readiness/observe.ps1'), 'observer-original')
        $script:task = [pscustomobject]@{ TaskName='RapporLab-Pass220-IdeReadiness'; TaskPath='\\'; State='Ready';
            Actions=@([pscustomobject]@{ Execute='powershell.exe'; Arguments=('-NoLogo -NoProfile -NonInteractive -File "'+$root+'\\interactive.ps1"'); WorkingDirectory='' });
            Principal=[pscustomobject]@{ UserId='fixture\\joao'; LogonType='Interactive'; RunLevel='Limited' } }
    }
    if ($scenario -in @('owned-process','generation-reuse','process-query-error')) {
        $timestamp = [DateTime]::Parse('2026-11-12T12:00:00Z').ToUniversalTime()
        $script:processes = @([pscustomobject]@{ Id=221; Handle=123; ProcessName='Code'; SessionId=1; StartTime=$timestamp })
        $entry = [ordered]@{ name='Code'; processId=221; sessionId=1; startTicks=[string]$timestamp.Ticks }
        if ($scenario -eq 'generation-reuse') { $entry.startTicks = [string]($timestamp.Ticks - 1) }
        [ordered]@{ schema=1; processes=@($entry) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'owned-processes.json')
    }
    if ($scenario -eq 'wrong-action') { $script:task.Actions[0].Arguments = '-Command arbitrary' }
    if ($scenario -eq 'wrong-principal') { $script:task.Principal.UserId = 'other' }
    if ($scenario -eq 'changed-script') { Set-Content -LiteralPath (Join-Path $root 'interactive.ps1') -Value 'changed' }
    if ($scenario -eq 'unknown-related') { $script:rows = @([pscustomobject]@{ ProcessId=999; Name='Code.exe'; CommandLine='Code C:\\RapporLab\\ide-fixture-197' }) }
    if ($scenario -eq 'unreadable-command') { $script:rows = @([pscustomobject]@{ ProcessId=999; Name='Code.exe'; CommandLine=$null }) }
    if ($scenario -eq 'reparse-child') { [void](New-Item -ItemType SymbolicLink -Path (Join-Path $root 'outside') -Target '/tmp') }
    if ($scenario -eq 'running-task') { $script:task.State = 'Running' }
    function Get-ScheduledTask { if ($scenario -eq 'task-query-error') { throw 'fixture-query-failed' }; if ($null -ne $script:task) { return $script:task } }
    function Get-Process { if ($scenario -eq 'process-query-error') { throw 'fixture-process-query-failed' }; return $script:processes }
    function Get-CimInstance { return $script:rows }
    function Stop-Process { param($InputObject,[switch]$Force,$ErrorAction); $script:killed += $InputObject.Id; $script:processes=@() }
    function Stop-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction); $script:stopped=$true; $script:task.State='Ready' }
    function Unregister-ScheduledTask { param($TaskName,$TaskPath,$Confirm,$ErrorAction); $script:unregistered=$true; $script:task=$null }
    $failed = $false
    $message = ''
    try {
        & {
${definitions}
            function Get-CurrentAccountSid { return 'fixture-sid' }
            function Get-TaskAccountSid([string]$userId) { if ($userId -eq 'fixture\\joao') { return 'fixture-sid' }; return 'wrong-sid' }
${body}
        } | Out-Null
    } catch { $failed=$true; $message=$_.Exception.Message }
    $expectedSuccess = $scenario -in @('absent','empty-owned-root','owned-process','running-task')
    if ($failed -eq $expectedSuccess) { throw ('scenario-failed:'+ $scenario + ':' + $message) }
    if (-not $expectedSuccess -and ($script:killed.Count -ne 0 -or $script:unregistered)) { throw ('unsafe-mutation:'+$scenario) }
    if ($scenario -eq 'owned-process' -and ($script:killed.Count -ne 1 -or $script:killed[0] -ne 221)) { throw 'owned-process-not-stopped' }
    if ($scenario -eq 'running-task' -and -not $script:stopped) { throw 'bound-task-not-stopped' }
    if ($expectedSuccess -and (Test-Path -LiteralPath $root)) { throw 'root-remains' }
    [void](Remove-PSDrive C)
    Remove-Item -LiteralPath $directory -Force -Recurse
    Write-Output ('PASS:'+$scenario)
}
`;
  const result = powershell(fixture);
  assert.equal(result.error, undefined); assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(result.stdout.match(/PASS:/gu)?.length, 13);
});
