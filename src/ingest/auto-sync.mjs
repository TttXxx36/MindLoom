import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { SANITIZER_VERSION } from '../security/sanitizer.mjs';
import { verifyLowSensitivityIngestApproval } from '../security/trusted-approvals.mjs';
import { settlePublishedGitCommit } from '../git/repo-manager.mjs';
import { recordOperationSettlement } from '../storage/write-lock.mjs';
import {
  PARSER_VERSION,
  listDiscoverableSessions,
  resolveProjectMatchFromMap,
  ingestSession
} from './session-ingestor.mjs';
import { extractAntigravityCwdHint } from './adapters/antigravity-adapter.mjs';
import { rebuildVaultMocAndHome } from './human-digest.mjs';

function computeFileSha256(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function readQuickWorkspaceHints(sessionItem) {
  const hints = {
    cwd: sessionItem.cwd || null,
    gitRoot: null,
    workspaceSlug: sessionItem.workspace_slug || null,
    sourcePath: sessionItem._internal_source_path || null
  };
  if (hints.cwd || !sessionItem._internal_source_path || !fs.existsSync(sessionItem._internal_source_path)) {
    return hints;
  }

  if (sessionItem.source_tool === 'antigravity') {
    hints.cwd = extractAntigravityCwdHint(sessionItem._internal_source_path);
  }
  return hints;
}

function computeCandidateSnapshotId(sessionItem) {
  const sourceTool = sessionItem.source_tool;
  const sessionId = sessionItem.session_id;
  const rawSha256 = computeFileSha256(sessionItem._internal_source_path);
  if (sourceTool === 'antigravity' && sessionItem._internal_companion_path && fs.existsSync(sessionItem._internal_companion_path)) {
    const compSha = computeFileSha256(sessionItem._internal_companion_path);
    return `${sourceTool}-${sessionId}-${rawSha256}-${compSha.slice(0, 16)}`;
  }
  return `${sourceTool}-${sessionId}-${rawSha256}`;
}

/**
 * 方案 A：定时/白名单低敏增量同步引擎
 * - 默认仅处理 codex 与 antigravity（不触碰未启用的 dsh）
 * - 仅自动导入 project-map.json 明确映射的白名单项目；unmapped 会话保留在待审清单绝不误导
 * - 严格保留 verifyLowSensitivityIngestApproval 人类签发门禁校验
 *
 * @param {{
 *   db: any,
 *   vaultDir: string,
 *   dataDir: string,
 *   sourceTool?: 'all' | 'codex' | 'antigravity' | 'dsh',
 *   codexHome?: string,
 *   codexArchivedDir?: string | null,
 *   antigravityBrainDir?: string,
 *   dshHome?: string,
 *   codexApprovalId?: string | null,
 *   antigravityApprovalId?: string | null,
 *   dshApprovalId?: string | null,
 *   lookbackDays?: number,
 *   maxSessionsPerRun?: number,
 *   dryRun?: boolean,
 *   updateMoc?: boolean,
 *   nowMs?: number,
 *   nowIso?: string
 * }} params
 */
export function runWhitelistAutoSync({
  db,
  vaultDir,
  dataDir,
  sourceTool = 'all',
  codexHome = undefined,
  codexArchivedDir = undefined,
  antigravityBrainDir = undefined,
  dshHome = undefined,
  codexApprovalId = null,
  antigravityApprovalId = null,
  dshApprovalId = null,
  lookbackDays = 30,
  maxSessionsPerRun = 10,
  dryRun = false,
  updateMoc = true,
  nowMs = Date.now(),
  nowIso = new Date().toISOString()
}) {
  if (!db) {
    throw new Error('runWhitelistAutoSync requires an open state.sqlite db');
  }

  const cutoffMs = lookbackDays > 0 ? nowMs - lookbackDays * 86_400_000 : 0;
  const discovered = listDiscoverableSessions({
    sourceTool,
    codexHome,
    codexArchivedDir,
    antigravityBrainDir,
    dshHome
  });

  const approvalsByTool = {
    codex: codexApprovalId,
    antigravity: antigravityApprovalId,
    dsh: dshApprovalId
  };

  const synced = [];
  const dryRunCandidates = [];
  const alreadySynced = [];
  const skippedUnmapped = [];
  const skippedOld = [];
  const skippedUnapproved = [];
  const errors = [];

  for (const item of discovered) {
    if (sourceTool === 'all' && item.source_tool === 'dsh') {
      continue;
    }

    const updatedMs = item.updated_at ? Date.parse(item.updated_at) : nowMs;
    if (cutoffMs > 0 && Number.isFinite(updatedMs) && updatedMs < cutoffMs) {
      skippedOld.push({ sourceTool: item.source_tool, sessionId: item.session_id, updatedAt: item.updated_at });
      continue;
    }

    const hints = readQuickWorkspaceHints(item);
    const projectMatch = resolveProjectMatchFromMap({
      dataDir,
      explicitProject: 'auto',
      sessionHints: hints
    });

    if (!projectMatch.matched || projectMatch.reason !== 'rule_matched') {
      skippedUnmapped.push({
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        reason: projectMatch.reason,
        cwdHint: hints.cwd || null
      });
      continue;
    }
    const resolvedProject = projectMatch.project;

    const expectedSnapshotId = computeCandidateSnapshotId(item);
    const existingSnap = db
      .prepare('SELECT snapshot_id, parser_version, sanitizer_version, status FROM session_snapshots WHERE snapshot_id = ?')
      .get(expectedSnapshotId);
    if (
      existingSnap &&
      existingSnap.parser_version === PARSER_VERSION &&
      existingSnap.sanitizer_version === SANITIZER_VERSION &&
      existingSnap.status !== 'needs_reaudit'
    ) {
      alreadySynced.push({
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        project: resolvedProject
      });
      continue;
    }

    if (synced.length + dryRunCandidates.length >= maxSessionsPerRun) {
      break;
    }

    if (dryRun) {
      dryRunCandidates.push({
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        project: resolvedProject,
        hasApproval: Boolean(approvalsByTool[item.source_tool])
      });
      continue;
    }

    const approvalId = approvalsByTool[item.source_tool] || null;
    const approvalCheck = verifyLowSensitivityIngestApproval({
      db,
      approvalId,
      sourceTool: item.source_tool,
      sessionId: item.session_id
    });
    if (!approvalCheck.valid) {
      skippedUnapproved.push({
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        project: resolvedProject,
        reason: approvalCheck.reason
      });
      continue;
    }

    try {
      const ingRes = ingestSession({
        db,
        vaultDir,
        dataDir,
        sourcePath: item._internal_source_path,
        companionFullPath: item._internal_companion_path || null,
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        project: resolvedProject,
        sensitivity: 'approved_low_sensitivity',
        isolationReport: { strongIsolationEstablished: false, mode: 'degraded_low_sensitivity_only' },
        dryRun: false
      });
      let gitState = 'skipped_no_git';
      if (ingRes.readableSessionPath && fs.existsSync(path.join(vaultDir, '.git'))) {
        try {
          const gitRes = settlePublishedGitCommit({
            vaultDir,
            filePath: ingRes.readableSessionPath,
            expectedSha256: ingRes.contentSha256 || null,
            commitMessage: `feat(memory): auto-sync ${item.source_tool} ${item.session_id}`
          });
          gitState = gitRes.gitState;
        } catch {
          gitState = 'failed';
        }
      }
      if (ingRes.operationId) {
        recordOperationSettlement({
          db,
          operationId: ingRes.operationId,
          gitState,
          indexState: 'stale'
        });
      }
      synced.push({
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        project: resolvedProject,
        status: ingRes.status,
        gitState,
        readableSessionPath: ingRes.readableSessionPath || null
      });
    } catch (err) {
      errors.push({
        sourceTool: item.source_tool,
        sessionId: item.session_id,
        project: resolvedProject,
        error: err.message
      });
    }
  }

  let mocResult = null;
  if (!dryRun && updateMoc && synced.length > 0) {
    mocResult = rebuildVaultMocAndHome({ db, vaultDir, updateSessionDigests: false, nowIso });
  }

  const summary = {
    executedAt: nowIso,
    dryRun,
    sourceTool,
    lookbackDays,
    syncedCount: synced.length,
    synced,
    dryRunCandidatesCount: dryRunCandidates.length,
    dryRunCandidates,
    alreadySyncedCount: alreadySynced.length,
    skippedUnmappedCount: skippedUnmapped.length,
    skippedUnmapped,
    skippedUnapprovedCount: skippedUnapproved.length,
    skippedUnapproved,
    skippedOldCount: skippedOld.length,
    errorsCount: errors.length,
    errors,
    mocUpdated: Boolean(mocResult)
  };

  if (!dryRun) {
    const logDir = path.join(dataDir, 'runtime', 'logs');
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
    fs.writeFileSync(path.join(logDir, 'auto-sync-latest.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
  }

  return summary;
}
