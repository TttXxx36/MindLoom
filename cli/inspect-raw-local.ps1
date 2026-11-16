<#
.SYNOPSIS
  Human-only local raw session inspector (AgentMemory-Data\raw).
.DESCRIPTION
  PLAN.md §3.3: Refuses non-interactive / automated agent execution to reduce accidental misuse.
  Note: Script-level checks alone do NOT replace OS/host access isolation (verified via B01).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SnapshotFile,

  [string]$DataDir = "",

  [switch]$HumanConfirmed
)

$ErrorActionPreference = "Stop"

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
  Write-Error "ACCESS_DENIED (EXIT 43): inspect-raw-local.ps1 is restricted to interactive human terminals only." -ErrorAction Continue
  exit 43
}

if ([string]::IsNullOrWhiteSpace($DataDir)) {
  if ($env:MINDLOOM_DATA) { $DataDir = $env:MINDLOOM_DATA }
  elseif ($env:AGENT_MEMORY_DATA) { $DataDir = $env:AGENT_MEMORY_DATA }
  else {
    $docsDir = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($docsDir)) { $docsDir = Join-Path $HOME "Documents" }
    $DataDir = Join-Path $docsDir "Obsidian\MindLoom-Data"
  }
}

# 2. Restrict lexical target path inside DataDir\raw BEFORE interactive confirmation prompt
$resolvedRawRoot = [System.IO.Path]::GetFullPath((Join-Path $DataDir "raw"))
$candidatePath = if ([System.IO.Path]::IsPathRooted($SnapshotFile)) { $SnapshotFile } else { Join-Path $resolvedRawRoot $SnapshotFile }
$resolvedTarget = [System.IO.Path]::GetFullPath($candidatePath)

if (-not $resolvedTarget.StartsWith($resolvedRawRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-Error "ACCESS_DENIED (EXIT 44): Target path must reside inside '$resolvedRawRoot'." -ErrorAction Continue
  exit 44
}

# 3. Enforce interactive human confirmation prompt (prevents blind programmatic invocation)
if (-not $HumanConfirmed) {
  $reply = Read-Host "HUMAN-ONLY RAW ACCESS: Inspecting raw session '$SnapshotFile'. Type YES to continue"
  if ($reply -ne "YES") {
    Write-Error "ACCESS_DENIED (EXIT 43): Interactive confirmation not granted." -ErrorAction Continue
    exit 43
  }
}

if (-not (Test-Path -LiteralPath $resolvedTarget)) {
  Write-Error "NOT_FOUND (EXIT 45): Snapshot file does not exist." -ErrorAction Continue
  exit 45
}

$item = Get-Item -LiteralPath $resolvedTarget -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
  $linkTarget = $null
  try {
    $resolvedLink = $item.ResolveLinkTarget($true)
    if ($resolvedLink) { $linkTarget = [System.IO.Path]::GetFullPath($resolvedLink.FullName) }
  } catch {
    $linkTarget = $null
  }
  if (-not $linkTarget -or -not $linkTarget.StartsWith($resolvedRawRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Error "ACCESS_DENIED (EXIT 44): Reparse points escaping raw root are blocked." -ErrorAction Continue
    exit 44
  }
}

# 4. Stream output (decompressing single/multi-frame .zst / .zstd via Node 22+ built-in zlib; pass path cleanly as process.argv[1])
if ($resolvedTarget.EndsWith(".zst", [System.StringComparison]::OrdinalIgnoreCase) -or $resolvedTarget.EndsWith(".zstd", [System.StringComparison]::OrdinalIgnoreCase)) {
  $jsOneLiner = 'const fs=require("node:fs"),zlib=require("node:zlib"),b=fs.readFileSync(process.argv[1]);let o=0;const out=[];while(o<b.length){if(o+4>b.length)throw new Error("Truncated zstd");const m=b.readUInt32LE(o);if(m>=0x184d2a50&&m<=0x184d2a5f){if(o+8>b.length)throw new Error("Truncated skippable");const s=b.readUInt32LE(o+4);if(o+8+s>b.length)throw new Error("Truncated skippable");o+=8+s;continue;}if(m!==0xfd2fb528)throw new Error("Invalid zstd magic");if(o+5>b.length)throw new Error("Truncated header");const f=b[o+4],ff=(f>>6)&3,ss=(f>>5)&1,cs=(f>>2)&1,di=f&3;let p=o+5+(ss?0:1)+[0,1,2,4][di]+(ff===0?(ss?1:0):[0,2,4,8][ff]);if(p>b.length)throw new Error("Truncated header");let lb=0;while(!lb){if(p+3>b.length)throw new Error("Truncated block");const h=b[p]|(b[p+1]<<8)|(b[p+2]<<16);p+=3;lb=h&1;const bt=(h>>1)&3,bs=h>>3;if(bt===3)throw new Error("Corrupt block");p+=(bt===1?1:bs);if(p>b.length)throw new Error("Truncated payload");}if(cs)p+=4;if(p>b.length)throw new Error("Truncated checksum");out.push(zlib.zstdDecompressSync(b.subarray(o,p)));o=p;}process.stdout.write(Buffer.concat(out).toString("utf8"));'
  & node -e $jsOneLiner $resolvedTarget
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
} else {
  Get-Content -LiteralPath $resolvedTarget -Encoding UTF8
}
