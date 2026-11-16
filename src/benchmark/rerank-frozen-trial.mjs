import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { openDatabase } from '../db/sqlite.mjs';
import { initRepository } from '../init.mjs';
import { stageCandidate, publishFile } from '../storage/atomic-publisher.mjs';
import { ensureInstanceIdentity, readInstanceIdentity } from '../storage/instance-identity.mjs';
import { indexSanitizedVaultVectors } from '../search/vector-index.mjs';
import {
  searchKnowledge,
  searchKnowledgeAsync,
  rerankFrozenCandidatesAsync
} from '../search/query-engine.mjs';
import { callCloudProviderGateway } from '../providers/api-gateway.mjs';

export const RERANK_TRIAL_SCOPE_REF = 'trial:rerank-frozen-v33-3';
export const RERANK_TRIAL_LOCAL_CANARY = 'CANARY_RERANK_LOCAL_ONLY_NEVER_EGRESS';
export const RERANK_TRIAL_UNREG_CANARY = 'CANARY_RERANK_UNREG_NEVER_EGRESS';
export const RERANK_TRIAL_EXPIRED_CANARY = 'CANARY_RERANK_EXPIRED_NEVER_EGRESS';
export const RERANK_TRIAL_PENDING_CANARY = 'CANARY_RERANK_PENDING_PROP_NEVER_EGRESS';

const TRIAL_SESSION = Object.freeze({
  id: 'SES-019316a8-3001-7000-8000-000000000s01',
  filename: 'SES-20261114-codex-300s01_Rerank冻结池排查会话.md',
  title: '冻结候选池重排合成排查会话',
  project: 'ObsidianOps',
  source_tool: 'codex',
  session_id: 'trial-rerank-codex-001',
  snapshot_id: 'codex-trial-rerank-001'
});

const TRIAL_EVIDENCE = Object.freeze({
  id: 'EV-019316a8-3001-7000-8000-000000000e01',
  filename: 'EV-20261114-300e01_Rerank冻结池原子证据.md',
  title: '冻结候选池重排原子证据',
  project: 'ObsidianOps',
  source_tool: 'codex'
});

const TRIAL_NOTES = Object.freeze([
  {
    id: 'KN-019316a8-3001-7000-8000-000000000001',
    folder: 'Playbooks',
    filename: 'KN-20261114-300001_PostgreSQL主库只读连接超时.md',
    note_type: 'playbook',
    title: 'PostgreSQL 跨区专线延迟升高应急切换',
    privacy: 'sanitized',
    register: true,
    body: '跨区专线抖动导致主从复制延迟升高，临时切回本机房只读节点。RERANK_MARKER_DISTRACTOR_PG\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000002',
    folder: 'Playbooks',
    filename: 'KN-20261114-300002_PgBouncer空闲连接清理.md',
    note_type: 'playbook',
    title: 'PostgreSQL 空闲长事务定时清理规则',
    privacy: 'sanitized',
    register: true,
    body: '空闲事务占用表锁阻塞 DDL，设置 idle_in_transaction_session_timeout=60000。\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000003',
    folder: 'Playbooks',
    filename: 'KN-20261114-300003_PgBouncer事务池限流根治.md',
    note_type: 'playbook',
    title: 'PgBouncer transaction_mode 防连接风暴暴涨',
    privacy: 'sanitized',
    register: true,
    body: '微服务重启把连接数打满，启用事务复用将 max_client_conn 与 default_pool_size 分层限流。RERANK_MARKER_TARGET_PG_STORM\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000004',
    folder: 'Playbooks',
    filename: 'KN-20261114-300004_SQLite只读快照导出.md',
    note_type: 'playbook',
    title: 'SQLite 只读备份窗口锁表顺序规范',
    privacy: 'sanitized',
    register: true,
    body: '并发写库直接拷贝产生断页，改用 VACUUM INTO 导出一致性快照。RERANK_MARKER_DISTRACTOR_SQLITE\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000005',
    folder: 'Playbooks',
    filename: 'KN-20261114-300005_SQLiteWAL伴生权限继承.md',
    note_type: 'playbook',
    title: 'SQLite WAL 模式临时页与共享内存 ACL 检查',
    privacy: 'sanitized',
    register: true,
    body: '嵌入式库启用预写日志后配套 -wal 与 -shm 漏锁，应从父目录继承独占 ACL。RERANK_MARKER_TARGET_WAL_ACL\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000006',
    folder: 'Playbooks',
    filename: 'KN-20261114-300006_HTTPS出站域名校验.md',
    note_type: 'playbook',
    title: 'HTTPS 外发网关主机名与证书校验策略',
    privacy: 'sanitized',
    register: true,
    body: '未知代理域名伪装下游接口，校验审批精确端点并拒绝非 HTTPS 协议。RERANK_MARKER_DISTRACTOR_HTTP\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000007',
    folder: 'Playbooks',
    filename: 'KN-20261114-300007_防3xx跳转鉴权泄露.md',
    note_type: 'playbook',
    title: '禁用 fetch 跨站自动跳转防 Authorization 外泄',
    privacy: 'sanitized',
    register: true,
    body: '服务器返回 302 跳转会转发私有密钥头，固定 redirect error 阻断 3xx 状态码。RERANK_MARKER_TARGET_3XX\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000008',
    folder: 'Playbooks',
    filename: 'KN-20261114-300008_WindowsACL探针防误判.md',
    note_type: 'playbook',
    title: 'Windows NTFS 真实写探测规避只读位误报',
    privacy: 'sanitized',
    register: true,
    body: 'accessSync W_OK 忽略 NTFS 访问控制列表而误判，改用 openSync r+ 捕获 EPERM。RERANK_MARKER_TARGET_NTFS\n'
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000091',
    folder: 'Playbooks',
    filename: 'KN-20261114-300091_本地保密凭据陷阱.md',
    note_type: 'playbook',
    title: '本地私有密钥（Channel 2 / local_only 陷阱）',
    privacy: 'local_only',
    register: true,
    body: `## 1. 本地隐私隔离测试\n此笔记禁出站：${RERANK_TRIAL_LOCAL_CANARY}\n`
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000092',
    folder: 'Decisions',
    filename: 'KN-20261114-300092_未登记手建笔记陷阱.md',
    note_type: 'decision',
    title: '未登记手建脱敏笔记（Channel 2 陷阱）',
    privacy: 'sanitized',
    register: false,
    body: `## 1. 未登记隔离测试\n本文件未写入 state.sqlite notes 表：${RERANK_TRIAL_UNREG_CANARY}\n`
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000093',
    folder: 'Decisions',
    filename: 'KN-20261114-300093_过期复核笔记陷阱.md',
    note_type: 'decision',
    title: '过期复核笔记（Channel 2 陷阱）',
    privacy: 'sanitized',
    register: true,
    review_after: '2020-01-01',
    body: `## 1. 过期复核隔离测试\nreview_after 已过期：${RERANK_TRIAL_EXPIRED_CANARY}\n`
  },
  {
    id: 'KN-019316a8-3001-7000-8000-000000000094',
    folder: 'Decisions',
    filename: 'KN-20261114-300094_待审冲突笔记陷阱.md',
    note_type: 'decision',
    title: '存在 pending 冲突提案的笔记（Channel 2 陷阱）',
    privacy: 'sanitized',
    register: true,
    hasPendingProposal: true,
    body: `## 1. 待审提案隔离测试\n有 pending 冲突提案：${RERANK_TRIAL_PENDING_CANARY}\n`
  }
]);

export const RERANK_FROZEN_QUESTIONS = Object.freeze([
  {
    id: 'RQ01',
    query: '后端服务重启把数据库客户数打满怎么分流限制',
    expectedId: 'KN-019316a8-3001-7000-8000-000000000003',
    targetMarker: 'RERANK_MARKER_TARGET_PG_STORM',
    // Poor initial ranking: distractor 0001 and 0002 ranked ahead of true target 0003; also mix Channel 2 traps into input pool to assert strict exclusion
    frozenPoolIds: [
      'KN-019316a8-3001-7000-8000-000000000001',
      'KN-019316a8-3001-7000-8000-000000000002',
      'KN-019316a8-3001-7000-8000-000000000003',
      'KN-019316a8-3001-7000-8000-000000000004',
      'KN-019316a8-3001-7000-8000-000000000091',
      'KN-019316a8-3001-7000-8000-000000000092'
    ]
  },
  {
    id: 'RQ02',
    query: '嵌入式文件库打开预写模式后伴生共享页访问漏洞修复',
    expectedId: 'KN-019316a8-3001-7000-8000-000000000005',
    targetMarker: 'RERANK_MARKER_TARGET_WAL_ACL',
    frozenPoolIds: [
      'KN-019316a8-3001-7000-8000-000000000004',
      'KN-019316a8-3001-7000-8000-000000000001',
      'KN-019316a8-3001-7000-8000-000000000005',
      'KN-019316a8-3001-7000-8000-000000000006',
      'KN-019316a8-3001-7000-8000-000000000093'
    ]
  },
  {
    id: 'RQ03',
    query: '阻止外部请求自动重定向带走敏感令牌',
    expectedId: 'KN-019316a8-3001-7000-8000-000000000007',
    targetMarker: 'RERANK_MARKER_TARGET_3XX',
    frozenPoolIds: [
      'KN-019316a8-3001-7000-8000-000000000006',
      'KN-019316a8-3001-7000-8000-000000000008',
      'KN-019316a8-3001-7000-8000-000000000004',
      'KN-019316a8-3001-7000-8000-000000000007',
      'KN-019316a8-3001-7000-8000-000000000094'
    ]
  },
  {
    id: 'RQ04',
    query: '微软盘符安全检查误报权限够不够怎么准确测试',
    expectedId: 'KN-019316a8-3001-7000-8000-000000000008',
    targetMarker: 'RERANK_MARKER_TARGET_NTFS',
    frozenPoolIds: [
      'KN-019316a8-3001-7000-8000-000000000002',
      'KN-019316a8-3001-7000-8000-000000000008',
      'KN-019316a8-3001-7000-8000-000000000006',
      'KN-019316a8-3001-7000-8000-000000000005'
    ]
  }
]);

function buildKnowledgeMarkdown(note, nowIso) {
  const reviewLine = note.review_after ? `review_after: "${note.review_after}"\n` : '';
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
${reviewLine}env: "windows"
aliases:
  - "${note.title}"
sources:
  - "[[20_Evidence_Cards/${TRIAL_EVIDENCE.filename}]]"
created_at: "${nowIso}"
---

${note.body}`;
}

export function initFrozenRerankWorkspace({ workspaceDir }) {
  if (!workspaceDir || typeof workspaceDir !== 'string') {
    throw new Error('workspaceDir is required');
  }
  const root = path.resolve(workspaceDir);
  const vaultDir = path.join(root, 'vault');
  const dataDir = path.join(root, 'data');
  const vectorsDbPath = path.join(root, 'tmp-index', 'vectors.sqlite');
  const reportsDir = path.join(root, 'reports');
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');

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
    if (!db.prepare('SELECT id FROM notes WHERE id = ?').get(TRIAL_SESSION.id)) {
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
> Rerank 冻结池合成对照会话锚点
^event-000001
`;
      const sesPath = path.join(vaultDir, '10_Readable_Sessions', TRIAL_SESSION.filename);
      const stg = stageCandidate({ stagingDir, outputUuid: TRIAL_SESSION.id, content: sesMd });
      publishFile({
        db,
        operationId: 'rerank-ses-1',
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

    if (!db.prepare('SELECT id FROM notes WHERE id = ?').get(TRIAL_EVIDENCE.id)) {
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
        operationId: 'rerank-ev-1',
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
        if (!db.prepare('SELECT id FROM notes WHERE id = ?').get(note.id) && !fs.existsSync(targetPath)) {
          const stg = stageCandidate({ stagingDir, outputUuid: note.id, content: md });
          publishFile({
            db,
            operationId: `rerank-kn-${i + 1}`,
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

      if (note.hasPendingProposal) {
        const propPath = path.join(vaultDir, '40_Review_Queue', `PROP-20261114-300094_${note.id}.md`);
        if (!fs.existsSync(propPath)) {
          fs.writeFileSync(
            propPath,
            `---
schema_version: 1
id: "PROP-019316a8-3001-7000-8000-000000000p94"
note_type: "proposal"
title: "Pending conflict proposal for ${note.id}"
project: "ObsidianOps"
privacy: "sanitized"
proposal_kind: "conflict"
proposal_status: "pending"
target_id: "${note.id}"
created_at: "${nowIso}"
---

Pending review update for trap verification.
`,
            'utf8'
          );
        }
      }
    }
  } finally {
    db.close();
  }

  return {
    schema_version: 1,
    scope_ref: RERANK_TRIAL_SCOPE_REF,
    workspace_dir: root,
    vault_dir: vaultDir,
    data_dir: dataDir,
    vectors_db_path: vectorsDbPath,
    reports_dir: reportsDir,
    state_db_path: dbPath,
    vault_id: identity.vaultId,
    data_id: identity.dataId
  };
}

function scoreRankedIdLists(questions, idLists) {
  let hit1 = 0;
  let hit5 = 0;
  let mrrSum = 0;
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    const rankedIds = idLists[i] || [];
    const rank = rankedIds.indexOf(q.expectedId);
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

export async function runFrozenRerankTrial({
  workspaceDir,
  operatorDb,
  embedDocApprovalId = null,
  embedQueryApprovalId = null,
  rerankApprovalId,
  provider = 'siliconflow',
  baseUrl = null,
  embedEndpointUrl = null,
  rerankEndpointUrl = null,
  embedModel = 'BAAI/bge-m3',
  rerankModel = 'BAAI/bge-reranker-v2-m3',
  apiKeyProvider,
  sentinelReport = null,
  testContext = false,
  fetchFn = globalThis.fetch,
  overallDeadlineMs = 10_000,
  runTwoStageMode2 = false
} = {}) {
  const meta = initFrozenRerankWorkspace({ workspaceDir });
  const { vault_dir: vaultDir, data_dir: dataDir, vectors_db_path: vectorsDbPath, state_db_path: dbPath, reports_dir: reportsDir } = meta;
  const { vaultId, dataId } = readInstanceIdentity({ vaultPath: vaultDir, dataPath: dataDir });

  const outboundBodyAudits = [];
  const auditedFetch = async (url, init) => {
    const urlStr = String(url);
    const bodyText = typeof init?.body === 'string' ? init.body : '';
    const isRerank = urlStr.includes('/rerank');
    outboundBodyAudits.push({
      url: urlStr,
      stage: isRerank ? 'rerank' : 'embed',
      bytes: Buffer.byteLength(bodyText, 'utf8'),
      hasLocalOnlyCanary: bodyText.includes(RERANK_TRIAL_LOCAL_CANARY),
      hasUnregisteredCanary: bodyText.includes(RERANK_TRIAL_UNREG_CANARY),
      hasExpiredCanary: bodyText.includes(RERANK_TRIAL_EXPIRED_CANARY),
      hasPendingProposalCanary: bodyText.includes(RERANK_TRIAL_PENDING_CANARY),
      hasNoteUuid: /KN-019316a8-/i.test(bodyText),
      hasVaultPath: bodyText.includes('30_Knowledge_Notes') || /[A-Za-z]:\\/.test(bodyText)
    });
    return fetchFn(url, init);
  };

  const todayStr = '2026-11-14';
  const stateDb = openDatabase(dbPath, { readOnly: true });
  try {
    const mode0Lists = [];
    const frozenBaselineLists = [];
    const frozenRerankedLists = [];
    const perQuestion = [];

    // 1. Standalone Frozen Channel 1 Pool /rerank (0 embed_query calls)
    for (const q of RERANK_FROZEN_QUESTIONS) {
      const m0 = searchKnowledge({
        db: stateDb,
        vaultDir,
        query: q.query,
        todayStr,
        mode: 'literal',
        topK: 5
      });
      const m0Ids = m0.items.filter((it) => it.actionable).map((it) => it.id);
      mode0Lists.push(m0Ids);

      const baselineChannel1 = q.frozenPoolIds.filter((id) => /^KN-019316a8-3001-7000-8000-00000000000[1-8]$/.test(id));
      frozenBaselineLists.push(baselineChannel1);

      const callsBefore = outboundBodyAudits.length;
      const rr = await rerankFrozenCandidatesAsync({
        db: stateDb,
        vaultDir,
        query: q.query,
        frozenCandidates: q.frozenPoolIds,
        todayStr,
        topK: 5,
        cloudConfig: {
          operatorDb,
          rerankApprovalId,
          provider,
          rerankModel,
          baseUrl,
          rerankEndpointUrl,
          apiKeyProvider,
          vaultId,
          dataId,
          overallDeadlineMs,
          testContext,
          sentinelReport,
          fetchFn: auditedFetch
        }
      });
      const rrIds = rr.items.filter((it) => it.actionable).map((it) => it.id);
      frozenRerankedLists.push(rrIds);

      perQuestion.push({
        id: q.id,
        expectedId: q.expectedId,
        mode0TopIds: m0Ids,
        frozenBaselineTopIds: baselineChannel1,
        frozenRerankTopIds: rrIds,
        outboundRequestsForQuestion: outboundBodyAudits.slice(callsBefore).map((a) => a.url),
        liftedToRank1: baselineChannel1[0] !== q.expectedId && rrIds[0] === q.expectedId,
        fallbackUsed: Boolean(rr.fallbackUsed),
        fallbackReason: rr.fallbackReason || null
      });
    }

    // 2. Optional Two-Stage Mode 2 RunPlan (embed_query + rerank)
    let mode2Summary = null;
    if (runTwoStageMode2 && embedDocApprovalId && embedQueryApprovalId) {
      for (const suffix of ['', '-wal', '-shm']) {
        const p = `${vectorsDbPath}${suffix}`;
        if (fs.existsSync(p)) fs.rmSync(p, { force: true });
      }
      const cleanBase = typeof baseUrl === 'string' ? baseUrl.trim().replace(/\/+$/, '') : null;
      const resolvedEmbedUrl = embedEndpointUrl || (cleanBase ? `${cleanBase}/v1/embeddings` : null);
      await indexSanitizedVaultVectors({
        stateDb,
        vectorsDbPath,
        vaultDir,
        provider,
        model: embedModel,
        embedTextsFn: async (texts) => {
          const res = await callCloudProviderGateway({
            operatorDb,
            cloudApprovalId: embedDocApprovalId,
            provider,
            modelId: embedModel,
            purpose: 'embed_doc',
            baseUrl,
            endpointUrl: resolvedEmbedUrl,
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

      const mode2Lists = [];
      for (const q of RERANK_FROZEN_QUESTIONS) {
        const m2 = await searchKnowledgeAsync({
          db: stateDb,
          vaultDir,
          query: q.query,
          todayStr,
          mode: 'rerank',
          topK: 5,
          cloudConfig: {
            operatorDb,
            embedApprovalId: embedQueryApprovalId,
            rerankApprovalId,
            provider,
            embedModel,
            rerankModel,
            baseUrl,
            embedEndpointUrl: resolvedEmbedUrl,
            rerankEndpointUrl,
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
        mode2Lists.push(m2.items.filter((it) => it.actionable).map((it) => it.id));
      }
      mode2Summary = scoreRankedIdLists(RERANK_FROZEN_QUESTIONS, mode2Lists);
    }

    const rerankAudits = outboundBodyAudits.filter((a) => a.stage === 'rerank');
    const privacyAudit = {
      outboundRequestsCaptured: outboundBodyAudits.length,
      rerankRequestsCaptured: rerankAudits.length,
      localOnlyCanaryLeaked: outboundBodyAudits.some((a) => a.hasLocalOnlyCanary),
      unregisteredCanaryLeaked: outboundBodyAudits.some((a) => a.hasUnregisteredCanary),
      expiredCanaryLeaked: rerankAudits.some((a) => a.hasExpiredCanary),
      pendingProposalCanaryLeaked: rerankAudits.some((a) => a.hasPendingProposalCanary),
      noteUuidLeaked: outboundBodyAudits.some((a) => a.hasNoteUuid),
      vaultPathLeaked: outboundBodyAudits.some((a) => a.hasVaultPath)
    };

    const approvalIds = [embedDocApprovalId, embedQueryApprovalId, rerankApprovalId].filter(Boolean);
    const placeholders = approvalIds.map(() => '?').join(', ');
    const ledgerRows = operatorDb
      .prepare(
        `SELECT request_id, run_plan_id, purpose, reservation_state, outcome, http_status,
                prompt_tokens, billed_cost_micro_cny, egress_bytes
         FROM cloud_egress_usage_ledger
         WHERE cloud_approval_id IN (${placeholders})
         ORDER BY created_at ASC`
      )
      .all(...approvalIds);

    const report = {
      generatedAt: new Date().toISOString(),
      dailyDefaultModeMaintained: 'literal',
      liveVaultMutated: false,
      privacyAudit,
      comparison: {
        mode0Literal: scoreRankedIdLists(RERANK_FROZEN_QUESTIONS, mode0Lists),
        frozenBaselinePool: scoreRankedIdLists(RERANK_FROZEN_QUESTIONS, frozenBaselineLists),
        standaloneFrozenRerank: scoreRankedIdLists(RERANK_FROZEN_QUESTIONS, frozenRerankedLists),
        twoStageMode2RunPlan: mode2Summary,
        perQuestion
      },
      billing: {
        ledgerEntriesCount: ledgerRows.length,
        ledgerRows
      }
    };

    const reportPath = path.join(reportsDir, 'rerank-frozen-trial-latest.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
    report.reportPath = reportPath;
    return report;
  } finally {
    stateDb.close();
  }
}
