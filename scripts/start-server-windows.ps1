# Startet src/server.js als Hintergrundprozess und leitet Logs in logs\server.log
param(
  [switch]$HideWindow
)

$node = "$Env:ProgramFiles\nodejs\node.exe"
if (-not (Test-Path $node)) {
  $node = "node"
}

$script = Join-Path $PSScriptRoot "..\src\server.js"
$logDir = Join-Path $PSScriptRoot "..\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$stdout = Join-Path $logDir "server.log"
$stderr = Join-Path $logDir "server.err.log"

$startInfo = @{
  FilePath = $node
  ArgumentList = @($script)
  RedirectStandardOutput = $true
  RedirectStandardError = $true
  WorkingDirectory = (Resolve-Path (Join-Path $PSScriptRoot ".."))
  NoNewWindow = $false
}
if ($HideWindow) { $startInfo.WindowStyle = 'Hidden'; $startInfo.NoNewWindow = $true }

$proc = Start-Process @startInfo -PassThru
# Asynchrone Weiterleitung der Ausgaben in Dateien
$proc.StandardOutput.BeginReadLine()
$proc.StandardError.BeginReadLine()
Register-ObjectEvent -InputObject $proc -EventName 'Exited' -Action { Write-Host "Server process exited with code $($proc.ExitCode)" }

Write-Host "Started node process (PID: $($proc.Id)). Logs: $stdout and $stderr"
