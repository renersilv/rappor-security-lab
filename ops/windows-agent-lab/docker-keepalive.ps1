$ErrorActionPreference = 'Stop'

$docker = Get-Command docker.exe -ErrorAction Stop
& $docker.Source desktop start --timeout 180 *> $null
if ($LASTEXITCODE -ne 0) { exit 1 }

while ($true) {
    Start-Sleep -Seconds 30
}
