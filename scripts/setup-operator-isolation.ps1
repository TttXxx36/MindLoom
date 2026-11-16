#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install and NTFS-harden the privileged operator package for Obsidian Agent Memory (V3.3-2).
.DESCRIPTION
  Creates <OperatorRoot>\{operator-cli,keys,operator-state,trial-workspace},
  mirrors read-only operator code/config, initializes operator-state.sqlite & isolated trial workspace,
  stores the EMRank API key via hidden prompt (never logged), and enforces strict Windows SID-based
  NTFS ACLs (SYSTEM + BUILTIN\Administrators only on keys/ and operator-state/; ReadAndExecute for Users
  on operator-cli/ and trial-workspace/).
#>
[CmdletBinding()]
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$OperatorRoot = (Join-Path $(if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }) "MindLoom"),
  [string]$EndpointUrl = "https://emrank.tech/v1/embeddings",
  [string]$ModelId = "Qwen/Qwen3-Embedding-0.6B",
  [switch]$KeepExistingKey
)

$ErrorActionPreference = "Stop"

# Refuse non-interactive or agent contexts
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
  Write-Error "ACCESS_DENIED (EXIT 43): setup-operator-isolation.ps1 must run interactively by an elevated human operator." -ErrorAction Continue
  exit 43
}

$SID_SYSTEM = "*S-1-5-18"
$SID_ADMINS = "*S-1-5-32-544"
$SID_USERS  = "*S-1-5-32-545"

function Invoke-IcaclsChecked {
  param([string[]]$Arguments)
  $out = & icacls @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "icacls failed ($LASTEXITCODE): $($out -join ' ')"
  }
}

function Set-PrivateAdminOnlyAcl {
  param([string]$TargetPath, [switch]$IsDirectory)
  Invoke-IcaclsChecked @($TargetPath, "/setowner", $SID_ADMINS, "/Q")
  if ($IsDirectory) {
    Invoke-IcaclsChecked @($TargetPath, "/inheritance:r", "/grant:r", "${SID_SYSTEM}:(OI)(CI)F", "${SID_ADMINS}:(OI)(CI)F", "/Q")
  } else {
    Invoke-IcaclsChecked @($TargetPath, "/inheritance:r", "/grant:r", "${SID_SYSTEM}:F", "${SID_ADMINS}:F", "/Q")
  }
}

function Set-ReadOnlyPackageAcl {
  param([string]$TargetPath, [switch]$IsDirectory)
  Invoke-IcaclsChecked @($TargetPath, "/setowner", $SID_ADMINS, "/Q")
  if ($IsDirectory) {
    Invoke-IcaclsChecked @($TargetPath, "/inheritance:r", "/grant:r", "${SID_SYSTEM}:(OI)(CI)F", "${SID_ADMINS}:(OI)(CI)F", "${SID_USERS}:(OI)(CI)RX", "/Q")
  } else {
    Invoke-IcaclsChecked @($TargetPath, "/inheritance:r", "/grant:r", "${SID_SYSTEM}:F", "${SID_ADMINS}:F", "${SID_USERS}:RX", "/Q")
  }
}

$resolvedRepo = (Resolve-Path $RepoRoot).Path
$resolvedRoot = [System.IO.Path]::GetFullPath($OperatorRoot)
$cliRoot      = Join-Path $resolvedRoot "operator-cli"
$keysDir      = Join-Path $resolvedRoot "keys"
$stateDir     = Join-Path $resolvedRoot "operator-state"
$trialDir     = Join-Path $resolvedRoot "trial-workspace"
$configDir    = Join-Path $cliRoot "config"
$keyFile      = Join-Path $keysDir "provider-secrets.json"
$operatorDb   = Join-Path $stateDir "operator-state.sqlite"
$configFile   = Join-Path $configDir "operator-config.json"

Write-Host "[1/6] Creating isolated directory tree under $resolvedRoot ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $resolvedRoot, $cliRoot, $keysDir, $stateDir, $trialDir, $configDir -Force | Out-Null

# Temporarily grant Admins/SYSTEM full control to stage files cleanly
Set-PrivateAdminOnlyAcl -TargetPath $resolvedRoot -IsDirectory
Set-PrivateAdminOnlyAcl -TargetPath $keysDir -IsDirectory
Set-PrivateAdminOnlyAcl -TargetPath $stateDir -IsDirectory
Set-PrivateAdminOnlyAcl -TargetPath $cliRoot -IsDirectory
Set-PrivateAdminOnlyAcl -TargetPath $trialDir -IsDirectory

Write-Host "[2/6] Copying operator runtime package (excluding .git, tests, .tmp) ..." -ForegroundColor Cyan
$copyPairs = @(
  @{ Src = (Join-Path $resolvedRepo "package.json"); Dest = (Join-Path $cliRoot "package.json"); Dir = $false },
  @{ Src = (Join-Path $resolvedRepo "cli\mem-operator.mjs"); Dest = (Join-Path $cliRoot "cli\mem-operator.mjs"); Dir = $false },
  @{ Src = (Join-Path $resolvedRepo "scripts\approve-human.ps1"); Dest = (Join-Path $cliRoot "scripts\approve-human.ps1"); Dir = $false },
  @{ Src = (Join-Path $resolvedRepo "scripts\issue-approval-internal.mjs"); Dest = (Join-Path $cliRoot "scripts\issue-approval-internal.mjs"); Dir = $false },
  @{ Src = (Join-Path $resolvedRepo "src"); Dest = (Join-Path $cliRoot "src"); Dir = $true }
)

foreach ($item in $copyPairs) {
  if (-not (Test-Path -LiteralPath $item.Src)) {
    throw "Missing source path: $($item.Src)"
  }
  if ($item.Dir) {
    if (Test-Path -LiteralPath $item.Dest) { Remove-Item -LiteralPath $item.Dest -Recurse -Force }
    Copy-Item -LiteralPath $item.Src -Destination $item.Dest -Recurse -Force
  } else {
    New-Item -ItemType Directory -Path (Split-Path $item.Dest -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $item.Src -Destination $item.Dest -Force
  }
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$configObj = [ordered]@{
  schema_version = 1
  provider       = "emrank"
  endpointUrl    = $EndpointUrl
  modelId        = $ModelId
  maxBatchSize   = 32
  updatedAt      = (Get-Date).ToString("o")
}
[System.IO.File]::WriteAllText($configFile, ($configObj | ConvertTo-Json -Depth 4) + "`n", $utf8NoBom)

Write-Host "[3/6] Initializing operator-state.sqlite and isolated trial workspace ..." -ForegroundColor Cyan
$operatorCliEntry = Join-Path $cliRoot "cli\mem-operator.mjs"
& node $operatorCliEntry init-operator-db --operator-root $resolvedRoot --json | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to initialize operator-state.sqlite" }

& node $operatorCliEntry init-trial-workspace --operator-root $resolvedRoot --workspace $trialDir --json | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to initialize isolated trial workspace" }

Write-Host "[4/6] Configuring protected provider API key ..." -ForegroundColor Cyan
$shouldWriteKey = $true
if ((Test-Path -LiteralPath $keyFile) -and $KeepExistingKey) {
  $shouldWriteKey = $false
  Write-Host "Keeping existing key file: $keyFile" -ForegroundColor Yellow
}

if ($shouldWriteKey) {
  $secKey = Read-Host -AsSecureString "Enter EMRank API Key (hidden input; press Enter to keep existing if present)"
  $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secKey)
  $plainKey = ""
  try {
    $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  } finally {
    if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }

  if ([string]::IsNullOrWhiteSpace($plainKey)) {
    if (Test-Path -LiteralPath $keyFile) {
      Write-Host "Empty input received; keeping existing key file." -ForegroundColor Yellow
    } else {
      throw "EMRank API key cannot be empty on initial setup."
    }
  } else {
    $secretsObj = [ordered]@{
      schema_version = 1
      providers      = [ordered]@{
        emrank = [ordered]@{
          endpointUrl = $EndpointUrl
          apiKey      = $plainKey.Trim()
          updatedAt   = (Get-Date).ToString("o")
        }
      }
    }
    [System.IO.File]::WriteAllText($keyFile, ($secretsObj | ConvertTo-Json -Depth 5) + "`n", $utf8NoBom)
    $plainKey = $null
    $secretsObj = $null
  }
}

Write-Host "[5/6] Hardening NTFS ACLs & ownership (BUILTIN\Administrators) ..." -ForegroundColor Cyan
# 5a. Private Admin+SYSTEM only: keys/ and operator-state/
foreach ($privFile in (Get-ChildItem -LiteralPath $keysDir -Recurse -File -Force)) {
  Set-PrivateAdminOnlyAcl -TargetPath $privFile.FullName
}
Set-PrivateAdminOnlyAcl -TargetPath $keysDir -IsDirectory

foreach ($privDir in (Get-ChildItem -LiteralPath $stateDir -Recurse -Directory -Force)) {
  Set-PrivateAdminOnlyAcl -TargetPath $privDir.FullName -IsDirectory
}
foreach ($privFile in (Get-ChildItem -LiteralPath $stateDir -Recurse -File -Force)) {
  Set-PrivateAdminOnlyAcl -TargetPath $privFile.FullName
}
Set-PrivateAdminOnlyAcl -TargetPath $stateDir -IsDirectory

# 5b. Unwritable (ReadAndExecute for Users) on operator-cli/ and trial-workspace/
foreach ($roRoot in @($cliRoot, $trialDir)) {
  Set-ReadOnlyPackageAcl -TargetPath $roRoot -IsDirectory
  foreach ($d in (Get-ChildItem -LiteralPath $roRoot -Recurse -Directory -Force)) {
    Set-ReadOnlyPackageAcl -TargetPath $d.FullName -IsDirectory
  }
  foreach ($f in (Get-ChildItem -LiteralPath $roRoot -Recurse -File -Force)) {
    Set-ReadOnlyPackageAcl -TargetPath $f.FullName
  }
}

# Lock root folder to Admin+SYSTEM full, Users RX (non-inheriting into keys/operator-state because inheritance:r is set there)
Set-ReadOnlyPackageAcl -TargetPath $resolvedRoot -IsDirectory

Write-Host "[6/6] Verifying Windows NTFS ACL isolation from elevated inspection ..." -ForegroundColor Cyan
& node $operatorCliEntry sentinel-check --operator-root $resolvedRoot --allow-elevated --json
if ($LASTEXITCODE -ne 0) {
  throw "Elevated Windows NTFS ACL verification failed!"
}

Write-Host ""
Write-Host "Setup complete. Next steps:" -ForegroundColor Green
Write-Host "  1) In a NON-ELEVATED ordinary terminal (or Agent), verify 4-point OS sentinel:" -ForegroundColor Gray
Write-Host "     node `"$operatorCliEntry`" sentinel-check --json" -ForegroundColor White
Write-Host "  2) In THIS elevated Admin PowerShell, run interactive approval:" -ForegroundColor Gray
Write-Host "     pwsh -File `"$(Join-Path $cliRoot 'scripts\approve-human.ps1')`"" -ForegroundColor White
