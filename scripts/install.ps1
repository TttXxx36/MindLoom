<#
.SYNOPSIS
  MindLoom one-click setup & optional interactive auto-sync installer for Windows.
.DESCRIPTION
  Verifies Node >= 22.15.0 and Git, initializes MindLoom Vault + Data, discovers local workspaces,
  injects the MindLoom companion plugin into Obsidian, and optionally authorizes 30-day
  whitelist auto-sync + Windows Scheduled Task in interactive human terminals only (EXIT 43 guard).
#>
[CmdletBinding()]
param(
  [string]$VaultDir = "",
  [string]$DataDir = "",
  [switch]$Yes,
  [switch]$AuthorizeAutoSync,
  [switch]$SkipPlugin
)

$ErrorActionPreference = "Stop"

if ($AuthorizeAutoSync) {
  $isInputRedirected = $false
  try { $isInputRedirected = [Console]::IsInputRedirected } catch { $isInputRedirected = $true }
  $hasNonInteractiveArg = ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-NonI' })
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
    Write-Error "ACCESS_DENIED (EXIT 43): install.ps1 -AuthorizeAutoSync is restricted to interactive human terminals only." -ErrorAction Continue
    exit 43
  }
}

$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
  Write-Error "Node.js >= 22.15.0 is required. Install from https://nodejs.org/" -ErrorAction Continue
  exit 1
}

$nodeVer = ((& node -p "process.versions.node") | Out-String).Trim()
$verParts = $nodeVer.Split('.')
$nodeMajor = [int]$verParts[0]
$nodeMinor = if ($verParts.Length -gt 1) { [int]$verParts[1] } else { 0 }
$nodeSupported = ($nodeMajor -ge 24) -or ($nodeMajor -eq 23 -and $nodeMinor -ge 8) -or ($nodeMajor -eq 22 -and $nodeMinor -ge 15)
if (-not $nodeSupported) {
  Write-Error "Node.js 22 LTS (>= 22.15.0) or Node.js 24+ (or >= 23.8.0) is required (found v$nodeVer)." -ErrorAction Continue
  exit 1
}

& node -e "const z = require('node:zlib'); const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(':memory:'); db.close(); if (typeof z.zstdCompressSync !== 'function' || typeof z.zstdDecompressSync !== 'function') process.exit(2);"
if ($LASTEXITCODE -ne 0) {
  Write-Error "Node.js runtime lacks built-in node:sqlite or node:zlib Zstd support (v$nodeVer)." -ErrorAction Continue
  exit 1
}

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
  Write-Error "Git is required on PATH." -ErrorAction Continue
  exit 1
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$memCli = Join-Path $repoRoot "cli\mem.mjs"

$argsList = @($memCli, "setup")
if (-not [string]::IsNullOrWhiteSpace($VaultDir)) { $argsList += @("--vault", $VaultDir) }
if (-not [string]::IsNullOrWhiteSpace($DataDir)) { $argsList += @("--data", $DataDir) }
if ($Yes) { $argsList += "--yes" }
if ($AuthorizeAutoSync) { $argsList += "--authorize-autosync" }
if ($SkipPlugin) { $argsList += "--skip-plugin" }

& node @argsList
exit $LASTEXITCODE
