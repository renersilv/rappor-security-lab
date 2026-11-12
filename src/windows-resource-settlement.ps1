$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = 'C:\RapporLab\runtime\pass__ORIGIN_PASS__-ide-readiness'
$taskName = 'RapporLab-Pass__ORIGIN_PASS__-IdeReadiness'
$fixture = 'C:\RapporLab\ide-fixture-197'
$clock = [Diagnostics.Stopwatch]::StartNew()
$durationMs = __DURATION_MS__
$expectedHashes = @{ 'interactive.ps1' = '__INTERACTIVE_SHA256__'; 'observe.ps1' = '__OBSERVER_SHA256__' }

function Assert-Deadline {
    if ($clock.ElapsedMilliseconds -ge $durationMs) { throw 'settlement-deadline-exhausted' }
}
function Assert-PlainPath([string]$path) {
    $current = $path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'settlement-reparse-path' }
        }
        $parent = Split-Path -Path $current -Parent
        if ($parent -eq $current) { break }
        $current = $parent
    }
}
function Assert-Root {
    Assert-PlainPath $root
    if (-not (Test-Path -LiteralPath $root)) { return }
    $directory = Get-Item -LiteralPath $root -Force
    if (-not $directory.PSIsContainer) { throw 'settlement-root-not-directory' }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $entryCount = 0
    while ($pending.Count -gt 0) {
        Assert-Deadline
        foreach ($entry in @(Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop)) {
            $entryCount++
            if ($entryCount -gt 2048) { throw 'settlement-root-entry-limit' }
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'settlement-reparse-child' }
            if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
        }
    }
    foreach ($name in $expectedHashes.Keys) {
        $path = Join-Path $root $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'settlement-origin-script-missing' }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHashes[$name]) {
            throw 'settlement-origin-script-changed'
        }
    }
}
function Get-CurrentAccountSid { return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
function Get-TaskAccountSid([string]$userId) {
    return [Security.Principal.NTAccount]::new($userId).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Get-BoundTask {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $taskName -and $_.TaskPath -ceq '\' })
    if ($tasks.Count -gt 1) { throw 'settlement-task-ambiguous' }
    if ($tasks.Count -eq 0) { return $null }
    $task = $tasks[0]
    $actions = @($task.Actions)
    $argument = '-NoLogo -NoProfile -NonInteractive -File "' + $root + '\interactive.ps1"'
    if ($actions.Count -ne 1 -or $actions[0].Execute -cne 'powershell.exe' -or
        $actions[0].Arguments -cne $argument -or $actions[0].WorkingDirectory -notin @('', $null)) {
        throw 'settlement-task-action-mismatch'
    }
    if ((Get-TaskAccountSid ([string]$task.Principal.UserId)) -cne (Get-CurrentAccountSid) -or
        [string]$task.Principal.LogonType -cne 'Interactive' -or [string]$task.Principal.RunLevel -cne 'Limited') {
        throw 'settlement-task-principal-mismatch'
    }
    return $task
}
function Get-Ownership {
    $entries = @()
    foreach ($name in @('owned-processes.json', 'observer-ownership.json')) {
        $path = Join-Path $root $name
        if (-not (Test-Path -LiteralPath $path)) { continue }
        Assert-PlainPath $path
        $file = Get-Item -LiteralPath $path
        if ($file.Length -gt 131072) { throw 'settlement-ownership-size' }
        $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($document.schema -ne 1 -or $null -eq $document.processes) { throw 'settlement-ownership-schema' }
        $rows = @($document.processes)
        if ($name -ceq 'observer-ownership.json') { $rows += @($document.roots) }
        foreach ($entry in $rows) {
            if ($null -eq $entry -or @('Code','codex') -cnotcontains [string]$entry.name -or
                ($entry.processId -isnot [int] -and $entry.processId -isnot [long]) -or
                ($entry.sessionId -isnot [int] -and $entry.sessionId -isnot [long]) -or
                [long]$entry.processId -le 0 -or [long]$entry.sessionId -lt 0 -or
                [string]$entry.startTicks -notmatch '^[1-9][0-9]{10,18}$') { throw 'settlement-ownership-entry' }
            $entries += $entry
        }
    }
    return @($entries)
}
function Get-ExactProcess($entry) {
    $process = @(Get-Process -ErrorAction Stop | Where-Object { $_.Id -eq [int]$entry.processId })
    if ($process.Count -eq 0) { return $null }
    if ($process.Count -ne 1) { throw 'settlement-process-ambiguous' }
    $process = $process[0]
    $null = $process.Handle # Retain the generation-bound handle before checking identity or stopping.
    if ($null -eq $process) { return $null }
    if ($process.ProcessName -cne [string]$entry.name -or $process.SessionId -ne [int]$entry.sessionId -or
        [string]$process.StartTime.ToUniversalTime().Ticks -cne [string]$entry.startTicks) {
        throw 'settlement-process-generation-mismatch'
    }
    return $process
}
function Get-RelatedProcesses {
    # Inventory is read-only. Unknown matching processes prevent cleanup; they are never killed.
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        if ([string]$_.Name -in @('Code.exe','codex.exe','powershell.exe','pwsh.exe') -and
            [string]::IsNullOrWhiteSpace([string]$_.CommandLine)) { throw 'settlement-process-command-unreadable' }
        $text = [string]$_.CommandLine
        $text.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $text.IndexOf($fixture, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
}
function Assert-KnownInventory($entries) {
    $known = @($entries | ForEach-Object { [int]$_.processId })
    foreach ($row in @(Get-RelatedProcesses)) {
        if ($known -notcontains [int]$row.ProcessId) { throw 'settlement-unowned-related-process' }
    }
}

Assert-Deadline
Assert-Root
$task = Get-BoundTask
$entries = @(Get-Ownership)
foreach ($entry in $entries) { $null = Get-ExactProcess $entry }
# Only the exact, source-bound task can be stopped. Unknown processes are never killed.
if ($null -ne $task -and [string]$task.State -eq 'Running') {
    if (-not (Test-Path -LiteralPath $root)) { throw 'settlement-running-task-without-root' }
    Stop-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    do {
        Assert-Deadline
        Start-Sleep -Milliseconds 100
        $task = Get-BoundTask
    } while ($null -ne $task -and [string]$task.State -eq 'Running')
}
if ($null -ne $task -and [string]$task.State -notin @('Ready','Disabled')) { throw 'settlement-task-not-quiescent' }
$entries = @(Get-Ownership)
foreach ($entry in $entries) { $null = Get-ExactProcess $entry }
Assert-KnownInventory $entries
foreach ($entry in $entries) {
    Assert-Deadline
    $process = Get-ExactProcess $entry
    if ($null -ne $process) { Stop-Process -InputObject $process -Force -ErrorAction Stop }
}
Start-Sleep -Milliseconds 200
foreach ($entry in $entries) {
    if ($null -ne (Get-ExactProcess $entry)) { throw 'settlement-owned-process-remains' }
}
if (@(Get-RelatedProcesses).Count -ne 0) { throw 'settlement-related-process-remains' }
Assert-Deadline
Assert-Root
$task = Get-BoundTask
if ($null -ne $task) {
    if ([string]$task.State -notin @('Ready','Disabled')) { throw 'settlement-task-restarted' }
    Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
}
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
Start-Sleep -Milliseconds 200
Assert-Deadline
if ($null -ne (Get-BoundTask) -or (Test-Path -LiteralPath $root) -or @(Get-RelatedProcesses).Count -ne 0) {
    throw 'settlement-absence-not-confirmed'
}
[ordered]@{ schema = 1; kind = 'windows_task_settlement_guest'; taskAbsent = $true; rootAbsent = $true;
    ownershipVerified = $true; remainingOwnedProcesses = 0 } | ConvertTo-Json -Compress
