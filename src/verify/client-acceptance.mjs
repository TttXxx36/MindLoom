import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openExistingDatabase } from '../db/sqlite.mjs';
import { locateSnapshotEvent } from '../ingest/session-ingestor.mjs';
import { detectResidualSecrets } from '../security/sanitizer.mjs';
import { assertVaultGitNoRemote, validateEngineeringCommitPaths } from '../git/repo-manager.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_MEM_CLI = path.resolve(__dirname, '../../cli/mem.mjs');

/**
 * C04 客户端验收检查器（执行本端 Antigravity 独立验收；绝不代验 Codex 端）
 * 验证：
 *   1. CLI 触发与状态检查 (mem status / mem doctor)
 *   2. 检索命中与双通道区分 (mem search)
 *   3. 引用定位 (#^event-NNNNNN 跨快照定位)
 *   4. 错误报告 Exit B 脱敏清洗（异常消息中绝无秘密或 raw/ 路径泄露）
 *
 * @param {{
 *   clientName: 'antigravity',
 *   vaultDir: string,
 *   dataDir: string,
 *   query: string,
 *   expectedId?: string,
 *   citationLink?: string,
 *   cliPath?: string
 * }} params
 */
export function runClientAcceptanceChecks({
  clientName = 'antigravity',
  vaultDir,
  dataDir,
  query,
  sourceTool = null,
  expectedId = null,
  citationLink = null,
  cliPath = DEFAULT_MEM_CLI
}) {
  if (clientName !== 'antigravity') {
    throw new Error('C04 铁律：Antigravity、Codex 与 DSH 必须各自独立验收，严禁相互代验！');
  }

  const env = {
    ...process.env,
    AGENT_MEMORY_VAULT: vaultDir,
    AGENT_MEMORY_DATA: dataDir,
    AGENT_MEMORY_HOST_TOOL: clientName
  };

  // 1. 触发 CLI 状态自检
  const doctorOut = execFileSync(process.execPath, [cliPath, 'doctor'], { env, encoding: 'utf8' });
  const statusOut = execFileSync(process.execPath, [cliPath, 'status'], { env, encoding: 'utf8' });

  // 2. 检索命中校验（支持 --source 过滤校验）
  const searchArgs = [cliPath, 'search', query, '--json'];
  if (sourceTool) {
    searchArgs.push('--source', sourceTool);
  }
  const searchJsonOut = execFileSync(process.execPath, searchArgs, {
    env,
    encoding: 'utf8'
  });
  const searchParsed = JSON.parse(searchJsonOut);
  const hitMatched = expectedId
    ? searchParsed.items.some(item => item.id === expectedId)
    : searchParsed.items.length > 0;

  // 3. 引用定位校验 (#^event-NNNNNN)
  let citationVerified = null;
  if (citationLink) {
    const loc = locateSnapshotEvent({ vaultDir, dataDir, sourceLink: citationLink });
    citationVerified = loc.found && loc.anchor.startsWith('^event-');
  }

  // 4. 错误报告 Exit B 全通道脱敏校验（传入含合成敏感词与 raw/ 路径的异常场景）
  const syntheticToken = ['sk', 'ant', 'c04ErrorProbeToken99887766'].join('-');
  const fakeRawArg = path.join(dataDir, 'raw', `secret-${syntheticToken}.jsonl`);
  let errStderr = '';
  try {
    execFileSync(
      process.execPath,
      [cliPath, 'ingest', '--session', 'c04-err-probe', '--source-file', fakeRawArg],
      { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
  } catch (err) {
    errStderr = (err.stderr || '') + (err.stdout || '');
  }
  const residual = detectResidualSecrets(errStderr);
  const errorReportSanitized = errStderr.length > 0 && residual.clean && !errStderr.includes(syntheticToken);

  return {
    client: 'antigravity',
    codexIndependentVerificationStatus: 'PENDING_INDEPENDENT_CODEX_RUN (C04: 不得相互代验)',
    dshIndependentVerificationStatus: 'PENDING_INDEPENDENT_DSH_RUN (C04: 不得相互代验)',
    checks: {
      triggerOk: doctorOut.includes('[mem doctor]') && statusOut.includes('[mem status]'),
      searchHitOk: hitMatched,
      citationOk: citationVerified,
      errorReportSanitized
    },
    passed:
      doctorOut.includes('[mem doctor]') &&
      statusOut.includes('[mem status]') &&
      hitMatched &&
      (citationVerified === null || citationVerified === true) &&
      errorReportSanitized
  };
}

/**
 * 只读诊断当前工程仓、Vault 与 Data 目录的 V2.5 分阶段验收就绪状态（绝不读取原始会话或凭据）
 * @param {{
 *   repoRoot?: string,
 *   vaultDir: string,
 *   dataDir: string,
 *   skillPaths?: Record<string, string[]>
 * }} params
 */
export function collectAcceptanceReadiness({
  repoRoot = null,
  vaultDir = null,
  dataDir = null,
  vaultPath = null,
  dataPath = null,
  skillPaths = null
}) {
  vaultDir = vaultDir || vaultPath;
  dataDir = dataDir || dataPath;
  if (!vaultDir || !dataDir) {
    throw new Error('collectAcceptanceReadiness 需要传入有效的 vaultDir 与 dataDir');
  }
  const basesDir = path.join(vaultDir, '50_Bases_Views');
  const expectedBases = ['知识总览.base', '待处理更新.base', '到期复核.base', '会话与证据溯源.base'];
  const basesPresent = expectedBases.filter(f => fs.existsSync(path.join(basesDir, f)));

  let communityPluginsEmpty = false;
  const cpPath = path.join(vaultDir, '.obsidian', 'community-plugins.json');
  if (fs.existsSync(cpPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(cpPath, 'utf8'));
      communityPluginsEmpty = Array.isArray(parsed) && parsed.length === 0;
    } catch {
      communityPluginsEmpty = false;
    }
  }

  let vaultGitZeroRemote = false;
  if (fs.existsSync(path.join(vaultDir, '.git'))) {
    try {
      assertVaultGitNoRemote(vaultDir);
      vaultGitZeroRemote = true;
    } catch {
      vaultGitZeroRemote = false;
    }
  }

  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
  let dbClean = false;
  let noteCount = 0;
  let snapshotCounts = { codex: 0, antigravity: 0, dsh: 0 };
  if (fs.existsSync(dbPath)) {
    const db = openExistingDatabase(dbPath, { readOnly: true });
    try {
      const pending = db.prepare("SELECT count(*) as c FROM publish_intents WHERE state = 'linking'").get().c;
      dbClean = pending === 0;
      noteCount = db.prepare('SELECT count(*) as c FROM notes').get().c;
      for (const r of db.prepare('SELECT source_tool, count(*) as c FROM session_snapshots GROUP BY source_tool').all()) {
        const k = String(r.source_tool || '').toLowerCase();
        if (k in snapshotCounts) snapshotCounts[k] = r.c;
      }
    } finally {
      db.close();
    }
  }

  const rawToolDirsReady = ['codex', 'antigravity', 'dsh'].every(t => fs.existsSync(path.join(dataDir, 'raw', t)));
  const projectMapPath = path.join(dataDir, 'manifests', 'project-map.json');
  let projectMapValid = false;
  if (fs.existsSync(projectMapPath)) {
    try {
      const pm = JSON.parse(fs.readFileSync(projectMapPath, 'utf8'));
      projectMapValid = Array.isArray(pm.projects) && Boolean(pm.default_unmapped_project);
    } catch {
      projectMapValid = false;
    }
  }

  let gate1RepoValid = null;
  let gate1Blocked = [];
  if (repoRoot && fs.existsSync(path.join(repoRoot, '.git'))) {
    const trackedOut = execFileSync('git', ['ls-files'], { cwd: repoRoot, encoding: 'utf8' });
    const tracked = trackedOut.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const gateRes = validateEngineeringCommitPaths({ repoRoot, filePaths: tracked });
    gate1RepoValid = gateRes.valid;
    gate1Blocked = gateRes.blocked;
  }

  const skillStatus = {};
  if (skillPaths) {
    for (const [host, paths] of Object.entries(skillPaths)) {
      skillStatus[host] = paths.map(p => ({ path: p, exists: fs.existsSync(p) }));
    }
  }

  return {
    vault: {
      basesPresentCount: basesPresent.length,
      allFourBasesPresent: basesPresent.length === expectedBases.length,
      communityPluginsEmpty,
      vaultGitZeroRemote
    },
    data: {
      dbClean,
      noteCount,
      snapshotCounts,
      rawToolDirsReady,
      revisionsDirPresent: fs.existsSync(path.join(dataDir, 'runtime', 'revisions')),
      projectMapValid,
      writeLockPresent: fs.existsSync(path.join(dataDir, 'runtime', 'write.lock'))
    },
    engineeringGate1: repoRoot ? { valid: gate1RepoValid, blocked: gate1Blocked } : null,
    skillStatus
  };
}
