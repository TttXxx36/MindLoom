<#
.SYNOPSIS
  Human-only interactive local_ingest approval issuer (approved_low_sensitivity).
.DESCRIPTION
  PLAN.md §3.3 / B6: Refuses non-interactive terminals and automated agent environments.
  Requires explicit interactive console confirmation ("YES") before issuing
  approved_low_sensitivity_ingest ticket(s) into AgentMemory-Data\runtime\state.sqlite.
#>
[CmdletBinding()]
param(
  [string]$DataDir = "",
  [string]$SourceTool = "",
  [string[]]$SessionId = @(),
  [string]$Project = "auto",
  [int]$TtlHours = 24,
  [string]$ApprovedBy = "human-operator-tty"
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($DataDir)) {
  if ($env:MINDLOOM_DATA) { $DataDir = $env:MINDLOOM_DATA }
  elseif ($env:AGENT_MEMORY_DATA) { $DataDir = $env:AGENT_MEMORY_DATA }
  else {
    $cfgFile = Join-Path $HOME ".mindloom\config.json"
    if (Test-Path -LiteralPath $cfgFile) {
      try { $DataDir = ((Get-Content -LiteralPath $cfgFile -Raw -Encoding utf8) | ConvertFrom-Json).dataPath } catch {}
    }
    if ([string]::IsNullOrWhiteSpace($DataDir)) {
      $DataDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "Obsidian\MindLoom-Data"
    }
  }
}

# 1. Refuse non-interactive or known automated agent execution environments
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
  Write-Error "ACCESS_DENIED (EXIT 43): approve-ingest-human.ps1 is restricted to interactive human terminals only." -ErrorAction Continue
  exit 43
}

$resolvedDataDir = [System.IO.Path]::GetFullPath($DataDir)
$stateDbPath = Join-Path $resolvedDataDir "runtime\state.sqlite"
if (-not (Test-Path -LiteralPath $stateDbPath)) {
  Write-Error "NOT_FOUND (EXIT 45): state.sqlite not found at '$stateDbPath'. Run mem init first." -ErrorAction Continue
  exit 45
}

$issueHelper = Join-Path $PSScriptRoot "issue-ingest-approval-internal.mjs"
if (-not (Test-Path -LiteralPath $issueHelper)) {
  Write-Error "NOT_FOUND (EXIT 45): issue-ingest-approval-internal.mjs not found at '$issueHelper'." -ErrorAction Continue
  exit 45
}

# 2. Prompt interactively if SourceTool or SessionId omitted
if ([string]::IsNullOrWhiteSpace($SourceTool)) {
  $SourceTool = (Read-Host "Enter source tool (codex / antigravity / dsh)").Trim().ToLowerInvariant()
} else {
  $SourceTool = $SourceTool.Trim().ToLowerInvariant()
}

if ($SourceTool -notin @("codex", "antigravity", "dsh")) {
  Write-Error "INVALID_ARG (EXIT 44): SourceTool must be one of codex, antigravity, dsh." -ErrorAction Continue
  exit 44
}

$normalizedSessions = New-Object System.Collections.Generic.List[string]
foreach ($item in $SessionId) {
  foreach ($part in ($item -split ',')) {
    $trimmed = $part.Trim().Trim([char]'"', [char]"'")
    if ($trimmed -and -not $normalizedSessions.Contains($trimmed)) {
      $normalizedSessions.Add($trimmed)
    }
  }
}

if ($normalizedSessions.Count -eq 0) {
  $rawSessInput = Read-Host "Enter session ID(s) comma-separated (or * for all $SourceTool sessions)"
  foreach ($part in ($rawSessInput -split ',')) {
    $trimmed = $part.Trim().Trim([char]'"', [char]"'")
    if ($trimmed -and -not $normalizedSessions.Contains($trimmed)) {
      $normalizedSessions.Add($trimmed)
    }
  }
}

if ($normalizedSessions.Count -eq 0) {
  Write-Error "INVALID_ARG (EXIT 44): At least one SessionId is required." -ErrorAction Continue
  exit 44
}

Write-Host "=== HUMAN-ONLY LOW-SENSITIVITY INGEST APPROVAL SUMMARY ===" -ForegroundColor Yellow
Write-Host "  Data Dir     : $resolvedDataDir"
Write-Host "  State DB     : $stateDbPath"
Write-Host "  Source Tool  : $SourceTool"
Write-Host "  Session Count: $($normalizedSessions.Count)"
foreach ($sid in $normalizedSessions) {
  Write-Host "    - $sid"
}
Write-Host "  Project Hint : $Project"
Write-Host "  Sensitivity  : approved_low_sensitivity"
Write-Host "  TTL          : $TtlHours hours"
Write-Host "  Approved By  : $ApprovedBy"
Write-Host "============================================================" -ForegroundColor Yellow

$reply = (Read-Host "Type YES to issue approved_low_sensitivity ingest approval(s)")
if ([string]::IsNullOrEmpty($reply) -or $reply.Trim() -cne "YES") {
  Write-Error "ACCESS_DENIED (EXIT 43): Interactive confirmation not granted." -ErrorAction Continue
  exit 43
}

$nodeArgs = @(
  $issueHelper,
  "--data-dir", $resolvedDataDir,
  "--source-tool", $SourceTool,
  "--ttl-hours", "$TtlHours",
  "--approved-by", $ApprovedBy
)
foreach ($sid in $normalizedSessions) {
  $nodeArgs += @("--session", $sid)
}

$prevFlag = $env:OAM_APPROVE_INGEST_HUMAN_TTY
try {
  $env:OAM_APPROVE_INGEST_HUMAN_TTY = "1"
  $jsonOut = & node @nodeArgs
  if ($LASTEXITCODE -ne 0) {
    throw "Ingest approval issuance failed with exit code $LASTEXITCODE"
  }
  $parsed = ($jsonOut -join "`n") | ConvertFrom-Json
  Write-Host ""
  Write-Host "Issued local_ingest approval(s) successfully:" -ForegroundColor Green
  Write-Host $jsonOut
  Write-Host ""
  $memCli = Join-Path $resolvedDataDir "cli\mem.mjs"
  Write-Host "Next step (run ingest with the bound approval ID):" -ForegroundColor Cyan
  foreach ($ap in $parsed.approvals) {
    $projFlag = if ($Project -and $Project -ne "auto") { " --project `"$Project`"" } else { "" }
    Write-Host "  node `"$memCli`" ingest --source $($ap.sourceTool) --session `"$($ap.sessionId)`"$projFlag --sensitivity approved_low_sensitivity --approval $($ap.ingestApprovalId)" -ForegroundColor White
  }
} finally {
  $env:OAM_APPROVE_INGEST_HUMAN_TTY = $prevFlag
}
