#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Human-only interactive cloud egress approval issuer (V3.3-2).
.DESCRIPTION
  PLAN.md §5.2: Refuses non-interactive terminals and automated agent environments.
  Requires elevated Administrator privilege + interactive console confirmation ("YES")
  before issuing embed_doc and embed_query approvals into <OperatorRoot>\operator-state\operator-state.sqlite.
#>
[CmdletBinding()]
param(
  [string]$OperatorRoot = (Join-Path $(if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }) "MindLoom"),
  [string]$Provider = "emrank",
  [string]$EndpointUrl = "https://emrank.tech/v1/embeddings",
  [string]$ModelId = "Qwen/Qwen3-Embedding-0.6B",
  [int]$InputMicroCnyPerMillionTokens = 140000,
  [int]$DocCalls = 4,
  [int]$DocTokens = 6000,
  [int]$DocCostMicroCny = 20000,
  [int]$QueryCalls = 16,
  [int]$QueryTokens = 14000,
  [int]$QueryCostMicroCny = 80000,
  [int]$TtlHours = 24
)

$ErrorActionPreference = "Stop"

# 1. Refuse non-interactive or known automated agent execution environments (matching inspect-raw-local.ps1)
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
  Write-Error "ACCESS_DENIED (EXIT 43): approve-human.ps1 is restricted to interactive elevated human terminals only." -ErrorAction Continue
  exit 43
}

$resolvedRoot = [System.IO.Path]::GetFullPath($OperatorRoot)
$cliRoot = Join-Path $resolvedRoot "operator-cli"
$issueHelper = Join-Path $cliRoot "scripts\issue-approval-internal.mjs"
if (-not (Test-Path -LiteralPath $issueHelper)) {
  $repoHelper = Join-Path $PSScriptRoot "issue-approval-internal.mjs"
  if (Test-Path -LiteralPath $repoHelper) {
    $issueHelper = $repoHelper
  } else {
    Write-Error "NOT_FOUND (EXIT 45): issue-approval-internal.mjs not found. Run setup-operator-isolation.ps1 first." -ErrorAction Continue
    exit 45
  }
}

$totalCalls = $DocCalls + $QueryCalls
$totalTokens = $DocTokens + $QueryTokens
$totalCostMicroCny = $DocCostMicroCny + $QueryCostMicroCny
$totalCostCny = [Math]::Round($totalCostMicroCny / 1000000.0, 4)

Write-Host "=== HUMAN-ONLY CLOUD EGRESS APPROVAL SUMMARY ===" -ForegroundColor Yellow
Write-Host "  Operator Root   : $resolvedRoot"
Write-Host "  Provider        : $Provider"
Write-Host "  Endpoint URL    : $EndpointUrl"
Write-Host "  Model ID        : $ModelId"
Write-Host "  Unit Price      : $InputMicroCnyPerMillionTokens micro-CNY / 1M input tokens"
Write-Host "  embed_doc cap   : maxCalls=$DocCalls, maxInputTokens=$DocTokens, maxCostMicroCny=$DocCostMicroCny (query_egress=0)"
Write-Host "  embed_query cap : maxCalls=$QueryCalls, maxInputTokens=$QueryTokens, maxCostMicroCny=$QueryCostMicroCny (query_egress=1)"
Write-Host "  Combined Cap    : $totalCalls calls | $totalTokens input tokens | $totalCostMicroCny micro-CNY (CNY $totalCostCny)"
Write-Host "  Scope           : Isolated synthetic trial workspace only (Live Vault untouched)"
Write-Host "  TTL             : $TtlHours hours"
Write-Host "=================================================" -ForegroundColor Yellow

$reply = (Read-Host "Type YES to issue BOTH embed_doc and embed_query approvals")
if ([string]::IsNullOrEmpty($reply) -or $reply.Trim() -cne "YES") {
  Write-Error "ACCESS_DENIED (EXIT 43): Interactive confirmation not granted." -ErrorAction Continue
  exit 43
}

$prevFlag = $env:OAM_APPROVE_HUMAN_TTY
try {
  $env:OAM_APPROVE_HUMAN_TTY = "1"
  $jsonOut = & node $issueHelper `
    --operator-root $resolvedRoot `
    --provider $Provider `
    --endpoint-url $EndpointUrl `
    --model-id $ModelId `
    --price-micro-cny "$InputMicroCnyPerMillionTokens" `
    --doc-calls "$DocCalls" `
    --doc-tokens "$DocTokens" `
    --doc-cost "$DocCostMicroCny" `
    --query-calls "$QueryCalls" `
    --query-tokens "$QueryTokens" `
    --query-cost "$QueryCostMicroCny" `
    --ttl-hours "$TtlHours"
  if ($LASTEXITCODE -ne 0) {
    throw "Approval issuance failed with exit code $LASTEXITCODE"
  }
  $parsed = ($jsonOut -join "`n") | ConvertFrom-Json
  Write-Host ""
  Write-Host "Issued cloud egress approvals successfully:" -ForegroundColor Green
  Write-Host $jsonOut
  Write-Host ""
  Write-Host "Run controlled EMRank trial in THIS elevated PowerShell:" -ForegroundColor Cyan
  $opEntry = Join-Path $cliRoot "cli\mem-operator.mjs"
  Write-Host "  node `"$opEntry`" trial-emrank --model `"$ModelId`" --embed-doc-approval $($parsed.embedDocApprovalId) --embed-query-approval $($parsed.embedQueryApprovalId) --json" -ForegroundColor White
} finally {
  $env:OAM_APPROVE_HUMAN_TTY = $prevFlag
}
