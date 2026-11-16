import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { openDatabase } from '../db/sqlite.mjs';
import { initRepository } from '../init.mjs';
import { stageCandidate, publishFile } from '../storage/atomic-publisher.mjs';
import { ensureInstanceIdentity, readInstanceIdentity } from '../storage/instance-identity.mjs';
import { indexSanitizedVaultVectors, openVectorIndexDatabase } from '../search/vector-index.mjs';
import { searchKnowledge, searchKnowledgeAsync } from '../search/query-engine.mjs';
import { callCloudProviderGateway } from '../providers/api-gateway.mjs';
import { reserveCloudEgressBudget } from '../security/cloud-approvals.mjs';

export const EMRANK_DEFAULT_ENDPOINT_URL = 'https://emrank.tech/v1/embeddings';
export const EMRANK_DEFAULT_MODEL_ID = 'Qwen/Qwen3-Embedding-0.6B';
export const EMRANK_TRIAL_SCOPE_REF = 'trial:emrank-v33-2';
export const LOCAL_ONLY_CANARY = 'CANARY_LOCAL_ONLY_TOKEN_NEVER_EGRESS';
export const UNREGISTERED_CANARY = 'CANARY_UNREGISTERED_MANUAL_NOTE_NEVER_EGRESS';

export const EMRANK_TRIAL_QUESTIONS = Object.freeze([
  {
    id: 'EQ01',
    kind: 'semantic_paraphrase',
    query: '后端服务连不上关系型库总报客户端连接数打满怎么缓解',
    expectedId: 'KN-019316a8-2001-7000-8000-000000000001'
  },
  {
    id: 'EQ02',
    kind: 'semantic_paraphrase',
    query: 'Node 在微软系统上检测磁盘写入限制总是误判可读怎么处理',
    expectedId: 'KN-019316a8-2001-7000-8000-000000000002'
  },
  {
    id: 'EQ03',
    kind: 'semantic_paraphrase',
    query: '轻量嵌入式数据库开启预写日志后配套临时文件权限漏设怎么办',
    expectedId: 'KN-019316a8-2001-7000-8000-000000000003'
  },
  {
    id: 'EQ04',
    kind: 'semantic_paraphrase',
    query: '防跨域名自动跳转把 Authorization 密钥头转发给第三方站点',
    expectedId: 'KN-019316a8-2001-7000-8000-000000000005'
  },
  {
    id: 'EQ05',
    kind: 'literal_anchor',
    query: 'PgBouncer',
    expectedId: 'KN-019316a8-2001-7000-8000-000000000001'
  }
]);

const TRIAL_SESSION = Object.freeze({
  id: 'SES-019316a8-2001-7000-8000-000000000s01',
  filename: 'SES-20261114-codex-200s01_EMRank试点排查会话.md',
  title: 'EMRank 小批对照合成排查会话',
  project: 'ObsidianOps',
  source_tool: 'codex',
  session_id: 'trial-emrank-codex-001',
  snapshot_id: 'codex-trial-emrank-001'
});

const TRIAL_EVIDENCE = Object.freeze({
  id: 'EV-019316a8-2001-7000-8000-000000000e01',
  filename: 'EV-20261114-200e01_EMRank试点原子证据.md',
  title: 'EMRank 小批对照工程原子证据',
  project: 'ObsidianOps',
  source_tool: 'codex'
});

const TRIAL_NOTES = Object.freeze([
  {
    id: 'KN-019316a8-2001-7000-8000-000000000001',
    folder: 'Playbooks',
    filename: 'KN-20261114-200001_PgBouncer事务池复用.md',
    note_type: 'playbook',
    title: 'PgBouncer 事务级连接池复用方案',
    privacy: 'sanitized',
    register: true,
    body: '## 1. 现象与根因\n高并发下 PostgreSQL 主库进程数暴增、TCP socket 队列枯竭。\n## 4. 处理步骤\n部署 PgBouncer 将 pool_mode 设为 transaction，配合应用短事务归还句柄。\n'
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000002',
    folder: 'Playbooks',
    filename: 'KN-20261114-200002_WindowsNTFS真实写探针.md',
    note_type: 'playbook',
    title: 'Windows NTFS 用 openSync r+ 探测不可写边界',
    privacy: 'sanitized',
    register: true,
    body: '## 1. 现象与根因\naccessSync(W_OK) 在 Windows 仅看只读属性位而忽略 NTFS ACL。\n## 4. 处理步骤\n改用 fs.openSync(targetPath, "r+") 直接探测真实权限，命中 EACCES/EPERM 才判受阻。\n'
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000003',
    folder: 'Playbooks',
    filename: 'KN-20261114-200003_SQLiteWAL伴生文件加固.md',
    note_type: 'playbook',
    title: 'SQLite -wal 与 -shm 伴生文件同步权限锁定',
    privacy: 'sanitized',
    register: true,
    body: '## 1. 现象与根因\n主库 .sqlite 收紧权限后，未锁定已存在的 -wal 与 -shm 文件会导致旁路修改。\n## 4. 处理步骤\n加锁检查同时遍历主库、-wal 与 -shm 三个路径。\n'
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000004',
    folder: 'Playbooks',
    filename: 'KN-20261114-200004_Zstd多帧与跳帧解码.md',
    note_type: 'playbook',
    title: 'Zstd 多帧串联与 Skippable Frame 解码',
    privacy: 'sanitized',
    register: true,
    body: '## 1. 现象与根因\n多帧追加归档混有 0x184D2A50 跳帧块时单次解压会漏读尾部内容。\n## 4. 处理步骤\n按魔数逐帧切分偏移并跳过 Skippable Frame。\n'
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000005',
    folder: 'Playbooks',
    filename: 'KN-20261114-200005_网关禁止重定向防凭据外泄.md',
    note_type: 'playbook',
    title: '出站 fetch 强制 redirect: error 防 302 劫持',
    privacy: 'sanitized',
    register: true,
    body: '## 1. 现象与根因\n允许 HTTP 302 自动重定向会把请求头随跳转带往未审批主机。\n## 4. 处理步骤\n在 fetch 选项固定 redirect: "error"，遇到 3xx 立即拦截并记为 http_error。\n'
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000006',
    folder: 'Playbooks',
    filename: 'KN-20261114-200006_原子硬链接R1补偿.md',
    note_type: 'playbook',
    title: 'NTFS CreateHardLinkW 崩溃后 R1 状态补偿',
    privacy: 'sanitized',
    register: true,
    body: '## 1. 现象与根因\n硬链接建好但 staging 尚未删除时进程中断。\n## 4. 处理步骤\n启动恢复检查目标硬链接是否已存在，校验哈希一致后再清理 staging。\n'
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000091',
    folder: 'Playbooks',
    filename: 'KN-20261114-200091_本地保密凭据陷阱.md',
    note_type: 'playbook',
    title: '本地私有密钥备忘录（禁外发测试陷阱）',
    privacy: 'local_only',
    register: true,
    body: `## 1. 本地隐私隔离测试\n此笔记标注 local_only，禁止进入向量索引与云端载荷：${LOCAL_ONLY_CANARY}\n`
  },
  {
    id: 'KN-019316a8-2001-7000-8000-000000000092',
    folder: 'Decisions',
    filename: 'KN-20261114-200092_手建未登记脱敏笔记陷阱.md',
    note_type: 'decision',
    title: '手建未登记脱敏笔记（仅限 Mode 0 Channel 2）',
    privacy: 'sanitized',
    register: false,
    body: `## 1. 未登记隔离测试\n本文件未写入 state.sqlite notes 表：${UNREGISTERED_CANARY}\n`
  }
]);

function buildKnowledgeMarkdown(note, nowIso) {
  return `---
schema_version: 1
id: "${note.id}"
note_type: "${note.note_type}"
title: "${note.title}"
project: "ObsidianOps"
privacy: "${note.privacy}"
lifecycle: "active"
evidence_level: "user_confirmed"
review_state: "accepted"
env: "windows"
aliases:
  - "${note.title}"
sources:
  - "[[20_Evidence_Cards/${TRIAL_EVIDENCE.filename}]]"
created_at: "${nowIso}"
---

${note.body}`;
}

export function initEmrankTrialWorkspace({ workspaceDir }) {
  if (!workspaceDir || typeof workspaceDir !== 'string') {
    throw new Error('workspaceDir is required');
  }
  const root = path.resolve(workspaceDir);
  const vaultDir = path.join(root, 'vault');
  const dataDir = path.join(root, 'data');
  const vectorsDbPath = path.join(root, 'tmp-index', 'vectors.sqlite');
  const reportsDir = path.join(root, 'reports');
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
  const markerPath = path.join(root, 'workspace-meta.json');

  fs.mkdirSync(reportsDir, { recursive: true });
  fs.mkdirSync(path.dirname(vectorsDbPath), { recursive: true });

  const nowIso = '2026-11-14T12:00:00+08:00';
  if (!fs.existsSync(dbPath)) {
    initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  }
  const identity = ensureInstanceIdentity({ vaultPath: vaultDir, dataPath: dataDir });

  const db = openDatabase(dbPath);
  const stagingDir = path.join(dataDir, 'staging');
  try {
    const existingSes = db.prepare('SELECT id FROM notes WHERE id = ?').get(TRIAL_SESSION.id);
    if (!existingSes) {
      const sesMd = `---
schema_version: 1
id: "${TRIAL_SESSION.id}"
note_type: "session"
title: "${TRIAL_SESSION.title}"
project: "${TRIAL_SESSION.project}"
privacy: "sanitized"
source_tool: "${TRIAL_SESSION.source_tool}"
session_id: "${TRIAL_SESSION.session_id}"
snapshot_id: "${TRIAL_SESSION.snapshot_id}"
coverage:
  total_events: 1
  rendered_events: 1
  omitted_events: 0
  parse_error_events: 0
  backfilled_truncations: 0
  unresolved_truncations: 0
  attachments_count: 0
created_at: "${nowIso}"
---

# ${TRIAL_SESSION.title}

### 事件 #1 · user
> EMRank 合成对照会话锚点
^event-000001
`;
      const sesPath = path.join(vaultDir, '10_Readable_Sessions', TRIAL_SESSION.filename);
      const stg = stageCandidate({ stagingDir, outputUuid: TRIAL_SESSION.id, content: sesMd });
      publishFile({
        db,
        operationId: 'trial-ses-1',
        outputUuid: TRIAL_SESSION.id,
        stagingPath: stg.stagingPath,
        vaultTargetPath: sesPath,
        contentSha256: stg.contentSha256,
        metadata: {
          note_type: 'session',
          source_tool: TRIAL_SESSION.source_tool,
          title: TRIAL_SESSION.title,
          project: TRIAL_SESSION.project,
          privacy: 'sanitized',
          created_at: nowIso
        }
      });
    }

    const existingEv = db.prepare('SELECT id FROM notes WHERE id = ?').get(TRIAL_EVIDENCE.id);
    if (!existingEv) {
      const evMd = `---
schema_version: 1
id: "${TRIAL_EVIDENCE.id}"
note_type: "evidence"
title: "${TRIAL_EVIDENCE.title}"
project: "${TRIAL_EVIDENCE.project}"
privacy: "sanitized"
source_tool: "${TRIAL_EVIDENCE.source_tool}"
evidence_level: "observed"
sources:
  - "[[10_Readable_Sessions/${TRIAL_SESSION.filename}#^event-000001]]"
created_at: "${nowIso}"
---

# ${TRIAL_EVIDENCE.title}
`;
      const evPath = path.join(vaultDir, '20_Evidence_Cards', TRIAL_EVIDENCE.filename);
      const stg = stageCandidate({ stagingDir, outputUuid: TRIAL_EVIDENCE.id, content: evMd });
      publishFile({
        db,
        operationId: 'trial-ev-1',
        outputUuid: TRIAL_EVIDENCE.id,
        stagingPath: stg.stagingPath,
        vaultTargetPath: evPath,
        contentSha256: stg.contentSha256,
        metadata: {
          note_type: 'evidence',
          source_tool: TRIAL_EVIDENCE.source_tool,
          title: TRIAL_EVIDENCE.title,
          project: TRIAL_EVIDENCE.project,
          privacy: 'sanitized',
          evidence_level: 'observed',
          created_at: nowIso
        }
      });
    }

    for (let i = 0; i < TRIAL_NOTES.length; i++) {
      const note = TRIAL_NOTES[i];
      const targetPath = path.join(vaultDir, '30_Knowledge_Notes', note.folder, note.filename);
      const md = buildKnowledgeMarkdown(note, nowIso);
      if (note.register) {
        const row = db.prepare('SELECT id FROM notes WHERE id = ?').get(note.id);
        if (!row && !fs.existsSync(targetPath)) {
          const stg = stageCandidate({ stagingDir, outputUuid: note.id, content: md });
          publishFile({
            db,
            operationId: `trial-kn-${i + 1}`,
            outputUuid: note.id,
            stagingPath: stg.stagingPath,
            vaultTargetPath: targetPath,
            contentSha256: stg.contentSha256,
            metadata: {
              note_type: note.note_type,
              title: note.title,
              project: 'ObsidianOps',
              privacy: note.privacy,
              lifecycle: 'active',
              evidence_level: 'user_confirmed',
              review_state: 'accepted',
              created_at: nowIso
            }
          });
        }
      } else if (!fs.existsSync(targetPath)) {
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        fs.writeFileSync(targetPath, md, 'utf8');
      }
    }
  } finally {
    db.close();
  }

  const sanitizedDigestHash = crypto.createHash('sha256');
  for (const note of TRIAL_NOTES.filter((n) => n.register && n.privacy === 'sanitized')) {
    const rel = path.join('30_Knowledge_Notes', note.folder, note.filename).replace(/\\/g, '/');
    const content = fs.readFileSync(path.join(vaultDir, rel), 'utf8');
    sanitizedDigestHash.update(`${rel}\n${content}\n`, 'utf8');
  }
  const corpusDigest = sanitizedDigestHash.digest('hex');

  const meta = {
    schema_version: 1,
    scope_ref: EMRANK_TRIAL_SCOPE_REF,
    workspace_dir: root,
    vault_dir: vaultDir,
    data_dir: dataDir,
    vectors_db_path: vectorsDbPath,
    reports_dir: reportsDir,
    state_db_path: dbPath,
    vault_id: identity.vaultId,
    data_id: identity.dataId,
    corpus_digest: corpusDigest,
    registered_sanitized_notes: TRIAL_NOTES.filter((n) => n.register && n.privacy === 'sanitized').length,
    trap_notes_excluded: TRIAL_NOTES.filter((n) => !n.register || n.privacy !== 'sanitized').length
  };
  fs.writeFileSync(markerPath, JSON.stringify(meta, null, 2) + '\n', 'utf8');
  return meta;
}

function scoreResults(questions, runs) {
  let hit1 = 0;
  let hit5 = 0;
  let mrrSum = 0;
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    const items = (runs[i]?.items || []).filter((it) => it.actionable === true);
    const rank = items.findIndex((it) => it.id === q.expectedId);
    if (rank === 0) hit1++;
    if (rank >= 0 && rank < 5) {
      hit5++;
      mrrSum += 1 / (rank + 1);
    }
  }
  const n = questions.length || 1;
  return {
    total: questions.length,
    hitAt1: Number((hit1 / n).toFixed(4)),
    hitAt5: Number((hit5 / n).toFixed(4)),
    mrrAt5: Number((mrrSum / n).toFixed(4))
  };
}

function toReportModelSlug(modelId) {
  return String(modelId || 'unknown').replace(/[^A-Za-z0-9._-]+/g, '-');
}

function roundMs(value) {
  return typeof value === 'number' && Number.isFinite(value) ? Number(value.toFixed(2)) : null;
}

function computePercentileMs(values, pct) {
  if (!Array.isArray(values) || values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1));
  return roundMs(sorted[idx]);
}

function extractGatewayLatencySummary(reportObj) {
  const rows = Array.isArray(reportObj?.billing?.ledgerRows) ? reportObj.billing.ledgerRows : [];
  const docOk = rows.filter((r) => r.purpose === 'embed_doc' && r.outcome === 'ok').map((r) => Number(r.latency_ms));
  const qOk = rows.filter((r) => r.purpose === 'embed_query' && r.outcome === 'ok').map((r) => Number(r.latency_ms));
  const avgQ = qOk.length > 0 ? roundMs(qOk.reduce((s, v) => s + v, 0) / qOk.length) : null;
  const docTotal = docOk.length > 0 ? roundMs(docOk.reduce((s, v) => s + v, 0)) : null;
  return {
    embedDocGatewayLatencyMs: docTotal,
    embedQueryGatewayLatenciesMs: qOk.map(roundMs),
    avgEmbedQueryGatewayMs: avgQ,
    p50EmbedQueryGatewayMs: computePercentileMs(qOk, 50),
    p95EmbedQueryGatewayMs: computePercentileMs(qOk, 95)
  };
}

function buildAbComparison(baselineReport, currentReport) {
  if (!baselineReport || !currentReport || baselineReport.modelId === currentReport.modelId) {
    return null;
  }
  const baseGw = baselineReport.timingSummary
    ? baselineReport.timingSummary
    : extractGatewayLatencySummary(baselineReport);
  const curGw = currentReport.timingSummary;
  const baseAvgQ = baseGw?.avgEmbedQueryGatewayMs ?? null;
  const curAvgQ = curGw?.avgEmbedQueryGatewayMs ?? null;
  const deltaMs = baseAvgQ !== null && curAvgQ !== null ? roundMs(curAvgQ - baseAvgQ) : null;
  const speedup = baseAvgQ && curAvgQ ? Number((baseAvgQ / curAvgQ).toFixed(2)) : null;
  return {
    baselineModelId: baselineReport.modelId,
    baselineGeneratedAt: baselineReport.generatedAt || null,
    currentModelId: currentReport.modelId,
    baselineDimension: baselineReport.indexStats?.dimensions ?? null,
    currentDimension: currentReport.indexStats?.dimensions ?? null,
    baselineMode1HitAt1: baselineReport.comparison?.mode1Hybrid?.hitAt1 ?? null,
    currentMode1HitAt1: currentReport.comparison?.mode1Hybrid?.hitAt1 ?? null,
    baselineMode1HitAt5: baselineReport.comparison?.mode1Hybrid?.hitAt5 ?? null,
    currentMode1HitAt5: currentReport.comparison?.mode1Hybrid?.hitAt5 ?? null,
    baselineEmbedDocGatewayMs: baseGw?.embedDocGatewayLatencyMs ?? null,
    currentEmbedDocGatewayMs: curGw?.embedDocGatewayLatencyMs ?? null,
    baselineAvgEmbedQueryGatewayMs: baseAvgQ,
    currentAvgEmbedQueryGatewayMs: curAvgQ,
    queryLatencyDeltaMs: deltaMs,
    querySpeedupRatio: speedup,
    baselineTotalBilledMicroCny: baselineReport.billing?.totalBilledMicroCny ?? null,
    currentTotalBilledMicroCny: currentReport.billing?.totalBilledMicroCny ?? null
  };
}

export async function runEmrankControlledTrial({
  workspaceDir,
  operatorDb,
  embedDocApprovalId,
  embedQueryApprovalId,
  endpointUrl = EMRANK_DEFAULT_ENDPOINT_URL,
  modelId = EMRANK_DEFAULT_MODEL_ID,
  apiKeyProvider,
  sentinelReport,
  testContext = false,
  fetchFn = globalThis.fetch,
  overallDeadlineMs = 10_000,
  runProbes = true
} = {}) {
  const trialStartMs = performance.now();
  const meta = initEmrankTrialWorkspace({ workspaceDir });
  const { vault_dir: vaultDir, data_dir: dataDir, vectors_db_path: vectorsDbPath, state_db_path: dbPath, reports_dir: reportsDir } = meta;
  const { vaultId, dataId } = readInstanceIdentity({ vaultPath: vaultDir, dataPath: dataDir });

  // Always rebuild disposable vectors.sqlite cleanly for each trial run
  for (const suffix of ['', '-wal', '-shm']) {
    const p = `${vectorsDbPath}${suffix}`;
    if (fs.existsSync(p)) {
      fs.rmSync(p, { force: true });
    }
  }

  const outboundBodyAudits = [];
  const auditedFetch = async (url, init) => {
    const bodyText = typeof init?.body === 'string' ? init.body : '';
    outboundBodyAudits.push({
      url: String(url),
      bytes: Buffer.byteLength(bodyText, 'utf8'),
      hasLocalOnlyCanary: bodyText.includes(LOCAL_ONLY_CANARY),
      hasUnregisteredCanary: bodyText.includes(UNREGISTERED_CANARY),
      hasNoteUuid: /KN-019316a8-/i.test(bodyText)
    });
    return fetchFn(url, init);
  };

  const stateDb = openDatabase(dbPath, { readOnly: true });
  try {
    // 1. Index registered sanitized notes via real/mock EMRank embed_doc approval
    const embedDocStartMs = performance.now();
    const indexStats = await indexSanitizedVaultVectors({
      stateDb,
      vectorsDbPath,
      vaultDir,
      provider: 'emrank',
      model: modelId,
      maxBatchSize: 32,
      embedTextsFn: async (texts) => {
        const res = await callCloudProviderGateway({
          operatorDb,
          cloudApprovalId: embedDocApprovalId,
          provider: 'emrank',
          modelId,
          purpose: 'embed_doc',
          endpointUrl,
          requiresQueryEgress: false,
          apiKeyProvider,
          vaultId,
          dataId,
          payloadInput: { inputs: texts, maxBatchSize: 32 },
          reservedInputTokens: Math.max(
            64,
            texts.reduce((sum, t) => sum + Math.max(16, Buffer.byteLength(t, 'utf8') + 8), 0)
          ),
          maxOutputTokens: 0,
          overallDeadlineMs,
          testContext,
          sentinelReport,
          fetchFn: auditedFetch
        });
        return {
          vectors: res.parsed.vectors,
          dimension: res.parsed.dimension
        };
      }
    });

    const embedDocWallMs = roundMs(performance.now() - embedDocStartMs);

    // Verify 0 vectors for privacy-excluded trap notes in disposable vectors.sqlite
    let trapVectorCount = 0;
    const vdb = openVectorIndexDatabase(vectorsDbPath, { readOnly: true });
    try {
      const row = vdb
        .prepare(
          `SELECT COUNT(*) AS c FROM vector_chunks WHERE doc_id IN (?, ?)`
        )
        .get('KN-019316a8-2001-7000-8000-000000000091', 'KN-019316a8-2001-7000-8000-000000000092');
      trapVectorCount = Number(row?.c || 0);
    } finally {
      vdb.close();
    }

    // 2. Compare Mode 0 (literal) vs Mode 1 (hybrid + EMRank)
    const todayStr = '2026-11-14';
    const mode0Runs = [];
    const mode1Runs = [];
    const perQuestion = [];
    const mode0PerQueryMs = [];
    const mode1PerQueryMs = [];

    for (const q of EMRANK_TRIAL_QUESTIONS) {
      const m0Start = performance.now();
      const m0 = searchKnowledge({
        db: stateDb,
        vaultDir,
        query: q.query,
        todayStr,
        mode: 'literal',
        topK: 5
      });
      const m0Ms = roundMs(performance.now() - m0Start);
      mode0PerQueryMs.push(m0Ms);

      const m1Start = performance.now();
      const m1 = await searchKnowledgeAsync({
        db: stateDb,
        vaultDir,
        query: q.query,
        todayStr,
        mode: 'hybrid',
        topK: 5,
        cloudConfig: {
          operatorDb,
          embedApprovalId: embedQueryApprovalId,
          provider: 'emrank',
          embedModel: modelId,
          embedEndpointUrl: endpointUrl,
          apiKeyProvider,
          vaultId,
          dataId,
          vectorsDbPath,
          overallDeadlineMs,
          testContext,
          sentinelReport,
          fetchFn: auditedFetch
        }
      });
      const m1Ms = roundMs(performance.now() - m1Start);
      mode1PerQueryMs.push(m1Ms);

      mode0Runs.push(m0);
      mode1Runs.push(m1);

      const m0Top5 = m0.items.filter((i) => i.actionable).map((i) => i.id);
      const m1Top5 = m1.items.filter((i) => i.actionable).map((i) => i.id);
      perQuestion.push({
        id: q.id,
        kind: q.kind,
        expectedId: q.expectedId,
        mode0Hit: m0Top5.includes(q.expectedId),
        mode0LatencyMs: m0Ms,
        mode0TopIds: m0Top5,
        mode1Hit: m1Top5.includes(q.expectedId),
        mode1LatencyMs: m1Ms,
        mode1TopIds: m1Top5,
        mode1FallbackUsed: Boolean(m1.fallbackUsed),
        mode1FallbackReason: m1.fallbackReason || null,
        recoveredOverMode0: !m0Top5.includes(q.expectedId) && m1Top5.includes(q.expectedId)
      });
    }

    const mode0Score = scoreResults(EMRANK_TRIAL_QUESTIONS, mode0Runs);
    const mode1Score = scoreResults(EMRANK_TRIAL_QUESTIONS, mode1Runs);
    const recoveredCount = perQuestion.filter((p) => p.recoveredOverMode0).length;

    // 3. Controlled fault & boundary probes (0 unexpected real spend)
    let probes = null;
    if (runProbes) {
      let endpointMismatchBlocked = false;
      let endpointMismatchCode = null;
      const callsBeforeProbes = outboundBodyAudits.length;
      try {
        await callCloudProviderGateway({
          operatorDb,
          cloudApprovalId: embedQueryApprovalId,
          provider: 'emrank',
          modelId,
          purpose: 'embed_query',
          endpointUrl: 'https://evil.example.com/v1/embeddings',
          requiresQueryEgress: true,
          apiKeyProvider,
          vaultId,
          dataId,
          payloadInput: { inputs: ['endpoint mismatch probe'] },
          reservedInputTokens: 64,
          maxOutputTokens: 0,
          overallDeadlineMs,
          testContext,
          sentinelReport,
          fetchFn: auditedFetch
        });
      } catch (err) {
        endpointMismatchCode = err.code || null;
        endpointMismatchBlocked = err.code === 'ERR_ENDPOINT_MISMATCH';
      }

      let budgetExhaustionBlocked = false;
      let budgetExhaustionCode = null;
      try {
        reserveCloudEgressBudget(operatorDb, {
          cloudApprovalId: embedQueryApprovalId,
          provider: 'emrank',
          modelId,
          purpose: 'embed_query',
          endpointUrl,
          requiresQueryEgress: true,
          reservedInputTokens: 1_000_000,
          maxOutputTokens: 0,
          vaultId,
          dataId
        });
      } catch (err) {
        budgetExhaustionCode = err.code || null;
        budgetExhaustionBlocked = err.code === 'ERR_CLOUD_BUDGET_EXCEEDED';
      }

      probes = {
        endpointMismatchProbe: {
          blocked: endpointMismatchBlocked,
          errorCode: endpointMismatchCode,
          outboundNetworkCallsTriggered: outboundBodyAudits.length - callsBeforeProbes
        },
        budgetExhaustionProbe: {
          blocked: budgetExhaustionBlocked,
          errorCode: budgetExhaustionCode,
          outboundNetworkCallsTriggered: 0
        }
      };
    }

    // 4. Ledger & approval billing summary
    const approvalSummaries = operatorDb
      .prepare(
        `SELECT cloud_approval_id, purpose, status, max_calls, used_calls,
                max_input_tokens, used_input_tokens, max_cost_micro_cny, used_cost_micro_cny
         FROM cloud_egress_approvals
         WHERE cloud_approval_id IN (?, ?)`
      )
      .all(embedDocApprovalId, embedQueryApprovalId);

    const ledgerRows = operatorDb
      .prepare(
        `SELECT request_id, cloud_approval_id, purpose, reservation_state, outcome, http_status,
                prompt_tokens, billed_cost_micro_cny, egress_bytes, latency_ms
         FROM cloud_egress_usage_ledger
         WHERE cloud_approval_id IN (?, ?)
         ORDER BY created_at ASC`
      )
      .all(embedDocApprovalId, embedQueryApprovalId);

    const privacyAudit = {
      trapVectorCount,
      outboundRequestsCaptured: outboundBodyAudits.length,
      localOnlyCanaryLeaked: outboundBodyAudits.some((a) => a.hasLocalOnlyCanary),
      unregisteredCanaryLeaked: outboundBodyAudits.some((a) => a.hasUnregisteredCanary),
      noteUuidLeaked: outboundBodyAudits.some((a) => a.hasNoteUuid)
    };

    const totalBilledMicroCny = approvalSummaries.reduce((s, r) => s + Number(r.used_cost_micro_cny || 0), 0);
    const partialReportForGw = { billing: { ledgerRows } };
    const gwSummary = extractGatewayLatencySummary(partialReportForGw);
    const mode0TotalMs = roundMs(mode0PerQueryMs.reduce((s, v) => s + v, 0));
    const mode1TotalMs = roundMs(mode1PerQueryMs.reduce((s, v) => s + v, 0));
    const avgMode1QueryMs = mode1PerQueryMs.length > 0 ? roundMs(mode1TotalMs / mode1PerQueryMs.length) : null;
    const timingSummary = {
      totalTrialMs: roundMs(performance.now() - trialStartMs),
      embedDocWallMs,
      mode0TotalMs,
      mode1TotalMs,
      mode1PerQueryMs,
      avgMode1QueryMs,
      p50Mode1QueryMs: computePercentileMs(mode1PerQueryMs, 50),
      p95Mode1QueryMs: computePercentileMs(mode1PerQueryMs, 95),
      ...gwSummary
    };

    const report = {
      generatedAt: new Date().toISOString(),
      provider: 'emrank',
      endpointUrl,
      modelId,
      dailyDefaultModeMaintained: 'literal',
      liveVaultMutated: false,
      vectorsIndexDisposable: true,
      sentinelAllFourPassed: Boolean(sentinelReport?.allFourPassed),
      indexStats,
      timingSummary,
      privacyAudit,
      comparison: {
        mode0: mode0Score,
        mode1Hybrid: mode1Score,
        literalMissSemanticRecovered: recoveredCount,
        perQuestion
      },
      probes,
      billing: {
        totalCallsSettled: approvalSummaries.reduce((s, r) => s + Number(r.used_calls || 0), 0),
        totalPromptTokens: approvalSummaries.reduce((s, r) => s + Number(r.used_input_tokens || 0), 0),
        totalBilledMicroCny,
        totalBilledCny: Number((totalBilledMicroCny / 1_000_000).toFixed(6)),
        approvals: approvalSummaries,
        ledgerEntriesCount: ledgerRows.length,
        ledgerRows
      }
    };

    const latestPath = path.join(reportsDir, 'emrank-trial-latest.json');
    let baselineReport = null;
    if (fs.existsSync(latestPath)) {
      try {
        const prev = JSON.parse(fs.readFileSync(latestPath, 'utf8'));
        if (prev && prev.modelId && prev.modelId !== modelId) {
          baselineReport = prev;
          const prevArchivePath = path.join(reportsDir, `emrank-trial-${toReportModelSlug(prev.modelId)}.json`);
          if (!fs.existsSync(prevArchivePath)) {
            fs.writeFileSync(prevArchivePath, JSON.stringify(prev, null, 2) + '\n', 'utf8');
          }
        }
      } catch {
        baselineReport = null;
      }
    }
    if (!baselineReport && fs.existsSync(reportsDir)) {
      for (const fname of fs.readdirSync(reportsDir)) {
        if (!fname.startsWith('emrank-trial-') || fname === 'emrank-trial-latest.json' || !fname.endsWith('.json')) continue;
        try {
          const cand = JSON.parse(fs.readFileSync(path.join(reportsDir, fname), 'utf8'));
          if (cand && cand.modelId && cand.modelId !== modelId) {
            baselineReport = cand;
            break;
          }
        } catch {
          // ignore unreadable archive
        }
      }
    }
    report.abComparisonVsBaseline = buildAbComparison(baselineReport, report);

    const modelReportPath = path.join(reportsDir, `emrank-trial-${toReportModelSlug(modelId)}.json`);
    report.modelReportPath = modelReportPath;
    report.reportPath = latestPath;
    fs.writeFileSync(modelReportPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
    fs.writeFileSync(latestPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
    return report;
  } finally {
    stateDb.close();
  }
}
