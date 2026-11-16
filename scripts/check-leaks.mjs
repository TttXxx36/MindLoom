import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

const IGNORED_DIRS = new Set(['.git', 'node_modules', '.tmp', 'dist']);

const FORBIDDEN_PATH_PATTERNS = [
  { name: 'personal_user_home', regex: /Users[/\\]+XT/i },
  { name: 'personal_d_document', regex: /D:[/\\]+Document[/\\]/i },
  { name: 'personal_e_backup', regex: /E:[/\\]+Backup[/\\]/i },
  { name: 'private_repo_slug', regex: /obsidian-agent-memory/i }
];

const FORBIDDEN_SECRET_PATTERNS = [
  { name: 'continuous_sk_token', regex: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'continuous_jwt_bearer', regex: /Bearer\s+eyJ[A-Za-z0-9._-]{16,}/ }
];

const FORBIDDEN_PLUGIN_PATTERNS = [
  { name: 'plugin_api_key_access', regex: /provider-secrets\.json/i },
  { name: 'plugin_operator_db_access', regex: /operator[-_]state\.sqlite/i },
  { name: 'plugin_sqlite_import', regex: /node:sqlite/i },
  { name: 'plugin_spoof_trusted_context', regex: /trustedHumanContext/i }
];

function walk(dir, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, results);
    } else if (entry.isFile()) {
      results.push(full);
    }
  }
  return results;
}

export function runLeakScan(repoRoot = REPO_ROOT) {
  const files = walk(repoRoot);
  const findings = [];

  for (const filePath of files) {
    const rel = path.relative(repoRoot, filePath).replace(/\\/g, '/');
    if (rel === 'scripts/check-leaks.mjs') continue;

    if (/\.(sqlite|sqlite-wal|sqlite-shm)$/i.test(rel)) {
      findings.push({ file: rel, line: 0, rule: 'forbidden_sqlite_file' });
      continue;
    }
    if (!rel.startsWith('tests/fixtures/') && /\.(jsonl|zst|zstd)$/i.test(rel)) {
      findings.push({ file: rel, line: 0, rule: 'forbidden_session_blob' });
      continue;
    }

    const ext = path.extname(rel).toLowerCase();
    if (['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff2', '.zip'].includes(ext)) continue;

    const text = fs.readFileSync(filePath, 'utf8');
    const lines = text.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      for (const p of FORBIDDEN_PATH_PATTERNS) {
        if (p.regex.test(line)) {
          findings.push({ file: rel, line: idx + 1, rule: p.name });
        }
      }
      for (const s of FORBIDDEN_SECRET_PATTERNS) {
        if (s.regex.test(line)) {
          findings.push({ file: rel, line: idx + 1, rule: s.name });
        }
      }
      if (rel.startsWith('plugin/src/')) {
        for (const pp of FORBIDDEN_PLUGIN_PATTERNS) {
          if (pp.regex.test(line)) {
            findings.push({ file: rel, line: idx + 1, rule: pp.name });
          }
        }
      }
    }
  }

  return { ok: findings.length === 0, filesScanned: files.length, findings };
}

const isEntrypoint = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);
if (isEntrypoint) {
  const res = runLeakScan();
  if (!res.ok) {
    process.stderr.write(`LEAK SCAN FAILED (${res.findings.length} findings):\n`);
    for (const f of res.findings) {
      process.stderr.write(`  - ${f.file}:${f.line} [${f.rule}]\n`);
    }
    process.exit(1);
  }
  process.stdout.write(`LEAK SCAN OK: scanned ${res.filesScanned} files, 0 findings.\n`);
}
