<#
.SYNOPSIS
  Human-only interactive installer for Obsidian Agent Memory scheduled whitelist auto-sync.
.DESCRIPTION
  Refuses non-interactive terminals and automated agent environments (EXIT 43).
  Requires explicit "YES" confirmation before:
    1) Issuing 30-day renewable low-sensitivity ingest approvals (codex:* and antigravity:*; DSH excluded)
    2) Writing non-secret ticket IDs to AgentMemory-Data\manifests\auto-sync-config.json
    3) Registering daily Windows Scheduled Task "ObsidianMemory AutoSync" (12:20 & 21:20, staggered around OpenViking)
#>
[CmdletBinding()]
param(
  [string]$VaultDir = "",
  [string]$DataDir = "",
  [int]$TtlHours = 720,
  [string]$TaskName = "MindLoom AutoSync",
  [string[]]$Times = @("12:20", "21:20"),
  [string]$ApprovedBy = "human-operator-tty",
  [switch]$SkipTaskRegistration
)

$ErrorActionPreference = "Stop"
$cfgFile = Join-Path $HOME ".mindloom\config.json"
$cfgObj = $null
if (Test-Path -LiteralPath $cfgFile) {
  try { $cfgObj = (Get-Content -LiteralPath $cfgFile -Raw -Encoding utf8) | ConvertFrom-Json } catch {}
}
if ([string]::IsNullOrWhiteSpace($VaultDir)) {
  if ($env:MINDLOOM_VAULT) { $VaultDir = $env:MINDLOOM_VAULT }
  elseif ($env:AGENT_MEMORY_VAULT) { $VaultDir = $env:AGENT_MEMORY_VAULT }
  elseif ($cfgObj -and $cfgObj.vaultPath) { $VaultDir = $cfgObj.vaultPath }
  else { $VaultDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "Obsidian\MindLoom" }
}
if ([string]::IsNullOrWhiteSpace($DataDir)) {
  if ($env:MINDLOOM_DATA) { $DataDir = $env:MINDLOOM_DATA }
  elseif ($env:AGENT_MEMORY_DATA) { $DataDir = $env:AGENT_MEMORY_DATA }
  elseif ($cfgObj -and $cfgObj.dataPath) { $DataDir = $cfgObj.dataPath }
  else { $DataDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "Obsidian\MindLoom-Data" }
}

# 1. Strictly refuse non-interactive terminals or automated agent environments
$isInputRedirected = $false
try {
  $isInputRedirected = [Console]::IsInputRedirected
} catch {
  $isInputRedirected = $true
}

$cliArgs = @()
try {
  $cliArgs = [Environment]::GetCommandLineArgs()
} catch {
  $cliArgs = @()
}
$hasNonInteractiveArg = $cliArgs | Where-Object { $_ -match '^-NonI' }

if (
  -not [Environment]::UserInteractive -or
  $isInputRedirected -or
  $hasNonInteractiveArg -or
  $env:ANTIGRAVITY_AGENT -or
  $env:CODEX_SANDBOX -or
  $env:CODEX_CI -or
  $env:CODEX_THREAD_ID -or
  $env:CLAUDECODE -or
  $env:GEMINI_CLI -or
  $env:CURSOR_AGENT -or
  $env:CI
) {
  Write-Error "ACCESS_DENIED (EXIT 43): register-auto-sync-task.ps1 is restricted to interactive human terminals only." -ErrorAction Continue
  exit 43
}

$resolvedVault = [System.IO.Path]::GetFullPath($VaultDir)
$resolvedData = [System.IO.Path]::GetFullPath($DataDir)
$stateDbPath = Join-Path $resolvedData "runtime\state.sqlite"
if (-not (Test-Path -LiteralPath $stateDbPath)) {
  Write-Error "NOT_FOUND (EXIT 45): state.sqlite not found at '$stateDbPath'. Run mem init first." -ErrorAction Continue
  exit 45
}

$issueHelper = Join-Path $PSScriptRoot "issue-ingest-approval-internal.mjs"
$runnerScript = Join-Path $PSScriptRoot "auto-sync-memory.ps1"
if (-not (Test-Path -LiteralPath $issueHelper) -or -not (Test-Path -LiteralPath $runnerScript)) {
  Write-Error "NOT_FOUND (EXIT 45): Required helper script missing in $PSScriptRoot." -ErrorAction Continue
  exit 45
}

if ($TtlHours -lt 1 -or $TtlHours -gt 720) {
  Write-Error "INVALID_ARG (EXIT 44): TtlHours must be between 1 and 720 (30 days max)." -ErrorAction Continue
  exit 44
}

Write-Host "=== HUMAN-ONLY OBSIDIAN MEMORY AUTO-SYNC REGISTRATION ===" -ForegroundColor Yellow
Write-Host "  Vault Dir     : $resolvedVault"
Write-Host "  Data Dir      : $resolvedData"
Write-Host "  Sources       : codex (*), antigravity (*)  [DSH excluded]"
Write-Host "  Policy        : Whitelist mapped projects only (unmapped -> skipped queue)"
Write-Host "  Approval TTL  : $TtlHours hours (renewable)"
Write-Host "  Schedule      : $($Times -join ', ') daily (Task: $TaskName)"
Write-Host "==========================================================" -ForegroundColor Yellow

$reply = Read-Host "Type YES to authorize low-sensitivity auto-sync and register task"
if ([string]::IsNullOrEmpty($reply) -or $reply.Trim() -cne "YES") {
  Write-Error "ACCESS_DENIED (EXIT 43): Interactive confirmation not granted." -ErrorAction Continue
  exit 43
}

$prevFlag = $env:OAM_APPROVE_INGEST_HUMAN_TTY
try {
  $env:OAM_APPROVE_INGEST_HUMAN_TTY = "1"

  $codexRaw = & node $issueHelper "--data-dir" $resolvedData "--source-tool" "codex" "--session" "*" "--ttl-hours" "$TtlHours" "--approved-by" $ApprovedBy
  if ($LASTEXITCODE -ne 0) { throw "Failed to issue codex wildcard approval (exit $LASTEXITCODE)" }
  $codexParsed = ($codexRaw -join "`n") | ConvertFrom-Json
  $codexApprovalId = $codexParsed.approvals[0].ingestApprovalId

  $agRaw = & node $issueHelper "--data-dir" $resolvedData "--source-tool" "antigravity" "--session" "*" "--ttl-hours" "$TtlHours" "--approved-by" $ApprovedBy
  if ($LASTEXITCODE -ne 0) { throw "Failed to issue antigravity wildcard approval (exit $LASTEXITCODE)" }
  $agParsed = ($agRaw -join "`n") | ConvertFrom-Json
  $agApprovalId = $agParsed.approvals[0].ingestApprovalId
} finally {
  $env:OAM_APPROVE_INGEST_HUMAN_TTY = $prevFlag
}

$manifestsDir = Join-Path $resolvedData "manifests"
if (-not (Test-Path -LiteralPath $manifestsDir)) {
  New-Item -ItemType Directory -Path $manifestsDir -Force | Out-Null
}
$configPath = Join-Path $manifestsDir "auto-sync-config.json"

$configObj = [ordered]@{
  version = 1
  sourceTool = "all"
  lookbackDays = 30
  maxSessionsPerRun = 10
  codexApprovalId = $codexApprovalId
  antigravityApprovalId = $agApprovalId
  dshApprovalId = $null
  vaultDir = $resolvedVault
  dataDir = $resolvedData
  ttlHours = $TtlHours
  issuedAt = (Get-Date).ToUniversalTime().ToString("o")
  expiresAt = (Get-Date).ToUniversalTime().AddHours($TtlHours).ToString("o")
}
$configJson = ($configObj | ConvertTo-Json -Depth 4) + "`n"
[System.IO.File]::WriteAllText($configPath, $configJson, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Wrote auto-sync config: $configPath" -ForegroundColor Green
Write-Host "  codexApprovalId       = $codexApprovalId"
Write-Host "  antigravityApprovalId = $agApprovalId"

if (-not $SkipTaskRegistration) {
  $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
  $shellExe = if ($pwshCmd) { $pwshCmd.Source } else { "powershell.exe" }
  $argLine = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runnerScript`" -VaultDir `"$resolvedVault`" -DataDir `"$resolvedData`" -ConfigPath `"$configPath`""

  $action = New-ScheduledTaskAction -Execute $shellExe -Argument $argLine
  $triggers = @()
  foreach ($t in $Times) {
    $triggers += (New-ScheduledTaskTrigger -Daily -At $t)
  }
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Settings $settings -Description "Obsidian Agent Memory whitelist low-sensitivity auto-sync (Codex + Antigravity, DSH excluded)" -Force | Out-Null
  Write-Host "Registered Windows Scheduled Task: '$TaskName' at $($Times -join ', ')" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done! Renew every 30 days by re-running register-auto-sync-task.ps1." -ForegroundColor Cyan
