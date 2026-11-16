<#
.SYNOPSIS
  Scheduled whitelist low-sensitivity auto-sync runner for Obsidian Agent Memory.
.DESCRIPTION
  Executes `mem auto-sync` (Codex + Antigravity whitelist projects only, excluding DSH and unmapped projects)
  using pre-authorized low-sensitivity wildcard approval IDs stored in manifests\auto-sync-config.json,
  then optionally runs `mem reconcile` and saves timestamped logs to runtime\logs\.
#>
[CmdletBinding()]
param(
  [string]$VaultDir = "",
  [string]$DataDir = "",
  [string]$ConfigPath = "",
  [int]$LookbackDays = 30,
  [int]$MaxSessions = 10,
  [switch]$DryRun,
  [switch]$SkipReconcile,
  [switch]$NoMoc
)

$ErrorActionPreference = "Stop"
$cfgFile = Join-Path $HOME ".mindloom\config.json"
$cfgObj = $null
if (Test-Path -LiteralPath $cfgFile) {
  try { $cfgObj = (Get-Content -LiteralPath $cfgFile -Raw -Encoding utf8) | ConvertFrom-Json } catch {}
}
$docsDir = [Environment]::GetFolderPath('MyDocuments')
if ([string]::IsNullOrWhiteSpace($docsDir)) { $docsDir = Join-Path $HOME "Documents" }
if ([string]::IsNullOrWhiteSpace($VaultDir)) {
  if ($env:MINDLOOM_VAULT) { $VaultDir = $env:MINDLOOM_VAULT }
  elseif ($env:AGENT_MEMORY_VAULT) { $VaultDir = $env:AGENT_MEMORY_VAULT }
  elseif ($cfgObj -and $cfgObj.vaultPath) { $VaultDir = $cfgObj.vaultPath }
  else { $VaultDir = Join-Path $docsDir "Obsidian\MindLoom" }
}
if ([string]::IsNullOrWhiteSpace($DataDir)) {
  if ($env:MINDLOOM_DATA) { $DataDir = $env:MINDLOOM_DATA }
  elseif ($env:AGENT_MEMORY_DATA) { $DataDir = $env:AGENT_MEMORY_DATA }
  elseif ($cfgObj -and $cfgObj.dataPath) { $DataDir = $cfgObj.dataPath }
  else { $DataDir = Join-Path $docsDir "Obsidian\MindLoom-Data" }
}

$resolvedVault = [System.IO.Path]::GetFullPath($VaultDir)
$resolvedData = [System.IO.Path]::GetFullPath($DataDir)

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
  $ConfigPath = Join-Path $resolvedData "manifests\auto-sync-config.json"
}

$memCliCandidates = @(
  (Join-Path $resolvedData "cli\mem.mjs"),
  (Join-Path $PSScriptRoot "..\cli\mem.mjs")
)
$memCli = $memCliCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $memCli) {
  Write-Error "NOT_FOUND (EXIT 45): mem.mjs not found in AgentMemory-Data\cli or repo\cli." -ErrorAction Continue
  exit 45
}

$logDir = Join-Path $resolvedData "runtime\logs"
if (-not (Test-Path -LiteralPath $logDir)) {
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logFile = Join-Path $logDir "auto-sync-runner.log"
$timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")

$nodeArgs = @(
  $memCli,
  "auto-sync",
  "--vault", $resolvedVault,
  "--data", $resolvedData,
  "--lookback-days", "$LookbackDays",
  "--max-sessions", "$MaxSessions",
  "--json"
)
if (Test-Path -LiteralPath $ConfigPath) {
  $nodeArgs += @("--config", $ConfigPath)
}
if ($DryRun) {
  $nodeArgs += "--dry-run"
}
if ($NoMoc) {
  $nodeArgs += "--no-moc"
}

$syncOut = & node @nodeArgs 2>&1
$syncExit = $LASTEXITCODE
$syncText = ($syncOut | Out-String).Trim()
Add-Content -LiteralPath $logFile -Value "[$timestamp] auto-sync exit=$syncExit`n$syncText`n" -Encoding utf8

if ($syncExit -ne 0) {
  Write-Error "auto-sync failed with exit code ${syncExit}: $syncText" -ErrorAction Continue
  exit $syncExit
}

$reconcileText = ""
if (-not $DryRun -and -not $SkipReconcile) {
  $recOut = & node $memCli "reconcile" "--vault" $resolvedVault "--data" $resolvedData "--json" 2>&1
  $recExit = $LASTEXITCODE
  $reconcileText = ($recOut | Out-String).Trim()
  Add-Content -LiteralPath $logFile -Value "[$timestamp] reconcile exit=$recExit`n$reconcileText`n" -Encoding utf8
}

Write-Output $syncText
exit 0
