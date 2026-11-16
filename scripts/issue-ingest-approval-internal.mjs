#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { resolveConfiguredPaths } from '../src/config/paths.mjs';
import { issueTrustedLowSensitivityApproval } from '../src/security/trusted-approvals.mjs';
import { ALLOWED_SOURCE_TOOLS } from '../src/schema/validator.mjs';
import { withWriteLock } from '../src/storage/write-lock.mjs';

const AGENT_ENV_VARS = [
  'ANTIGRAVITY_AGENT',
  'CODEX_SANDBOX',
  'CODEX_CI',
  'CODEX_THREAD_ID',
  'CLAUDECODE',
  'GEMINI_CLI',
  'CURSOR_AGENT',
  'CI'
];

function parseCliArgs(argv) {
  const out = { sessions: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = String(argv[i]);
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const val = argv[i + 1];
    if (key === 'session') {
      if (val === undefined || String(val).startsWith('--')) {
        throw new Error('ERR_INVALID_ARGS: --session requires a value');
      }
      for (const part of String(val).split(',')) {
        const trimmed = part.trim().replace(/^["']+|["']+$/g, '');
        if (trimmed) out.sessions.push(trimmed);
      }
      i++;
      continue;
    }
    if (val !== undefined && !String(val).startsWith('--')) {
      out[key] = val;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
}

if (process.env.OAM_APPROVE_INGEST_HUMAN_TTY !== '1') {
  throw new Error('ERR_UNTRUSTED_INGEST_APPROVAL_INVOCATION: Must be invoked exclusively via interactive approve-ingest-human.ps1');
}

for (const envName of AGENT_ENV_VARS) {
  if (process.env[envName]) {
    throw new Error(`ERR_UNTRUSTED_INGEST_AGENT_ENV: Refusing automated environment variable ${envName}`);
  }
}

const args = parseCliArgs(process.argv.slice(2));
const dataDir = path.resolve(String(args['data-dir'] || resolveConfiguredPaths().dataPath));
const sourceTool = String(args['source-tool'] || '').trim().toLowerCase();
const ttlHours = Number(args['ttl-hours'] ?? 24);
const approvedBy = String(args['approved-by'] || 'human-operator-tty').trim() || 'human-operator-tty';
const sessions = [...new Set(args.sessions)];

if (!ALLOWED_SOURCE_TOOLS.includes(sourceTool)) {
  throw new Error(`ERR_INVALID_SOURCE_TOOL: --source-tool must be one of [${ALLOWED_SOURCE_TOOLS.join(', ')}]`);
}
if (sessions.length === 0) {
  throw new Error('ERR_MISSING_SESSION: Provide at least one --session <id> (or *)');
}
if (!Number.isFinite(ttlHours) || ttlHours <= 0 || ttlHours > 720) {
  throw new Error('ERR_INVALID_TTL: --ttl-hours must be between 1 and 720');
}

const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
if (!fs.existsSync(dbPath)) {
  throw new Error(`ERR_STATE_DB_NOT_FOUND: Missing SQLite database at ${dbPath}`);
}

const approvals = withWriteLock({ dataPath: dataDir, command: 'approve-ingest-human' }, () => {
  const db = openExistingDatabase(dbPath);
  try {
    return sessions.map((sessionId) =>
      issueTrustedLowSensitivityApproval({
        db,
        sourceTool,
        sessionId,
        approvedBy,
        ttlHours,
        trustedHumanContext: true
      })
    );
  } finally {
    db.close();
  }
});

process.stdout.write(
  JSON.stringify(
    {
      issuedAt: new Date().toISOString(),
      dataDir,
      dbPath,
      sourceTool,
      ttlHours,
      approvedBy,
      approvals
    },
    null,
    2
  ) + '\n'
);
