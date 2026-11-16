import fs from 'node:fs';
import path from 'node:path';
import { openDatabase } from '../db/sqlite.mjs';
import { initRepository } from '../init.mjs';
import { stageCandidate, publishFile } from '../storage/atomic-publisher.mjs';
import { buildLocalSearchIndex } from '../search/query-engine.mjs';

/**
 * 14 题合成中文试点语料与固定基准题集 (符合 PLAN.md §7.2 / D01 12-15 题探索评测规范)
 */
export const PILOT_QUESTIONS = [
  { id: 'Q01', query: '启动', project: 'WebInfra', expectedIds: ['KN-019316a8-0001-7000-8000-000000000002'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q02', query: 'IP', project: 'ObsidianOps', expectedIds: ['KN-019316a8-0001-7000-8000-000000000004'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q03', query: '401', project: 'WebInfra', expectedIds: ['KN-019316a8-0001-7000-8000-000000000008'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q04', query: '--port=8080', expectedIds: ['KN-019316a8-0001-7000-8000-000000000001'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q05', query: 'netstat -ano | findstr :8080', expectedIds: ['KN-019316a8-0001-7000-8000-000000000001'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q06', query: 'VACUUM INTO', expectedIds: ['KN-019316a8-0001-7000-8000-000000000003'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q07', query: '-Encoding utf8', expectedIds: ['KN-019316a8-0001-7000-8000-000000000005'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q08', query: '.jsonl.zst', expectedIds: ['KN-019316a8-0001-7000-8000-000000000006'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q09', query: 'redis-cli ping', expectedIds: ['KN-019316a8-0001-7000-8000-000000000007'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q10', query: '容器端口绑定失败', expectedIds: ['KN-019316a8-0001-7000-8000-000000000001'], isNoAnswer: false, expectNonActionableOnly: false },
  { id: 'Q11', query: '本地私有银行证书导入', expectedIds: [], isNoAnswer: true, expectNonActionableOnly: false },
  { id: 'Q12', query: 'Kubernetes Ingress TLS 自动续期', expectedIds: [], isNoAnswer: true, expectNonActionableOnly: false },
  { id: 'Q13', query: '旧版同步脚本部署', expectedIds: ['KN-019316a8-0001-7000-8000-000000000009'], isNoAnswer: false, expectNonActionableOnly: true },
  { id: 'Q14', query: '十月旧版发布计划', expectedIds: ['KN-019316a8-0001-7000-8000-000000000010'], isNoAnswer: false, expectNonActionableOnly: true }
];

const SYNTHETIC_PILOT_SESSIONS = [
  {
    id: 'SES-019316a8-0001-7000-8000-000000000s01',
    filename: 'SES-20261110-codex-000s01_Codex试点基础会话.md',
    source_tool: 'codex',
    session_id: 'pilot-codex-001',
    snapshot_id: 'codex-pilot-codex-001-synth',
    project: 'ObsidianOps',
    title: 'Codex 试点容器与备份会话',
    body: '### 事件 #1 · user\n> 排查容器端口 --port=8080 与 SQLite VACUUM INTO\n^event-000001\n'
  },
  {
    id: 'SES-019316a8-0001-7000-8000-000000000s02',
    filename: 'SES-20261110-antigravity-000s02_Antigravity试点规范会话.md',
    source_tool: 'antigravity',
    session_id: 'pilot-agy-001',
    snapshot_id: 'antigravity-pilot-agy-001-synth',
    project: 'ObsidianOps',
    title: 'Antigravity 试点环境与权限会话',
    body: '### 事件 #1 · USER_INPUT\n> 固定内网 IP 白名单与 PowerShell -Encoding utf8 偏好\n^event-000001\n'
  },
  {
    id: 'SES-019316a8-0001-7000-8000-000000000s03',
    filename: 'SES-20261110-dsh-000s03_DSH试点压缩与鉴权会话.md',
    source_tool: 'dsh',
    session_id: 'pilot-dsh-001',
    snapshot_id: 'dsh-pilot-dsh-001-synth',
    project: 'WebInfra',
    title: 'DSH 试点 Zstd 与 401 排障会话',
    body: '### 事件 #1 · assistant/message\n> 处理 .jsonl.zst 解压、redis-cli ping 与 401 鉴权失败\n^event-000001\n'
  }
];

const SYNTHETIC_PILOT_EVIDENCE = [
  {
    id: 'EV-019316a8-0001-7000-8000-000000000e01',
    filename: 'EV-20261110-000e01_Codex容器与备份证据.md',
    source_tool: 'codex',
    project: 'ObsidianOps',
    title: 'Codex 容器端口与备份窗口证据',
    session_file: 'SES-20261110-codex-000s01_Codex试点基础会话.md'
  },
  {
    id: 'EV-019316a8-0001-7000-8000-000000000e02',
    filename: 'EV-20261110-000e02_Antigravity环境与IP证据.md',
    source_tool: 'antigravity',
    project: 'ObsidianOps',
    title: 'Antigravity 环境偏好与 IP 白名单证据',
    session_file: 'SES-20261110-antigravity-000s02_Antigravity试点规范会话.md'
  },
  {
    id: 'EV-019316a8-0001-7000-8000-000000000e03',
    filename: 'EV-20261110-000e03_DSH压缩与鉴权证据.md',
    source_tool: 'dsh',
    project: 'WebInfra',
    title: 'DSH 压缩解压与 401 鉴权证据',
    session_file: 'SES-20261110-dsh-000s03_DSH试点压缩与鉴权会话.md'
  }
];

const SYNTHETIC_NOTES = [
  {
    id: 'KN-019316a8-0001-7000-8000-000000000001',
    folder: 'Playbooks',
    filename: 'KN-20261110-000001_容器端口绑定失败排查.md',
    note_type: 'playbook',
    title: '容器端口绑定失败排查',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'user_confirmed',
    review_state: 'accepted',
    env: 'windows',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e01_Codex容器与备份证据.md]]'],
    body: '## 1. 现象与触发情境\nDocker 启动使用 --port=8080 绑定 127.0.0.1:8080 时报端口冲突。\n## 4. 处理步骤\n运行 netstat -ano | findstr :8080 排查占用进程。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000002',
    folder: 'Playbooks',
    filename: 'KN-20261110-000002_Nginx反向代理502与启动排查.md',
    note_type: 'playbook',
    title: 'Nginx 反向代理 502 与启动排查',
    project: 'WebInfra',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'observed',
    review_state: 'accepted',
    env: 'linux',
    sources: [
      '[[20_Evidence_Cards/EV-20261110-000e01_Codex容器与备份证据.md]]',
      '[[20_Evidence_Cards/EV-20261110-000e03_DSH压缩与鉴权证据.md]]'
    ],
    body: '## 1. 现象与触发情境\n服务启动后反代返回 502。\n## 4. 处理步骤\n先执行 nginx -t 检查配置，确认 proxy_pass http://127.0.0.1:3000 正常启动。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000003',
    folder: 'Decisions',
    filename: 'KN-20261110-000003_SQLiteWAL备份窗口选型.md',
    note_type: 'decision',
    title: 'SQLite WAL 模式选型与备份窗口',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'user_confirmed',
    review_state: 'accepted',
    sources: [
      '[[20_Evidence_Cards/EV-20261110-000e01_Codex容器与备份证据.md]]',
      '[[20_Evidence_Cards/EV-20261110-000e02_Antigravity环境与IP证据.md]]'
    ],
    body: '## 1. 现象与触发情境\nR4 备份必须保证 state.sqlite 与 Vault Markdown 一致性。\n## 4. 处理步骤\n使用 VACUUM INTO 导出一致性 SQLite 备份并执行前后指纹校验。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000004',
    folder: 'Project_States',
    filename: 'KN-20261110-000004_阶段B试点IP白名单状态.md',
    note_type: 'project_state',
    title: '阶段 B 试点当前状态与 IP 白名单',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'user_confirmed',
    review_state: 'accepted',
    as_of: '2026-11-10',
    review_after: '2026-12-31',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e02_Antigravity环境与IP证据.md]]'],
    body: '## 1. 现象与触发情境\n内网试点节点 IP 固定为 10.0.0.12，仅允许内网只读探测。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000005',
    folder: 'Preferences',
    filename: 'KN-20261110-000005_PowerShellUTF8偏好.md',
    note_type: 'preference',
    title: 'PowerShell UTF-8 输出偏好',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'user_confirmed',
    review_state: 'accepted',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e02_Antigravity环境与IP证据.md]]'],
    body: '## 4. 处理步骤\n在 pwsh 中所有文件读写显式指定 -Encoding utf8，防止中文乱码。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000006',
    folder: 'Playbooks',
    filename: 'KN-20261110-000006_Zstd压缩快照解压处理.md',
    note_type: 'playbook',
    title: 'Zstd 压缩快照解压失败处理',
    project: 'DataSync',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'observed',
    review_state: 'accepted',
    env: 'windows',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e03_DSH压缩与鉴权证据.md]]'],
    body: '## 1. 现象与触发情境\n读取 .jsonl.zst 遇到截断时由 zstdDecompressSync 捕获并在会话覆盖清单中明确报告。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000007',
    folder: 'Playbooks',
    filename: 'KN-20261110-000007_Redis连接超时排障.md',
    note_type: 'playbook',
    title: 'Redis 连接超时与密码脱敏',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'observed',
    review_state: 'accepted',
    env: 'linux',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e03_DSH压缩与鉴权证据.md]]'],
    body: '## 4. 处理步骤\n使用 redis-cli ping 检查连通性，排查 ECONNREFUSED 与 --tls 参数。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000008',
    folder: 'Decisions',
    filename: 'KN-20261110-000008_上游API401鉴权排查.md',
    note_type: 'decision',
    title: '上游 API 401 鉴权失败排障',
    project: 'WebInfra',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'user_confirmed',
    review_state: 'accepted',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e03_DSH压缩与鉴权证据.md]]'],
    body: '## 1. 现象与触发情境\n外部接口返回 401 Unauthorized，排查 Authorization 头与服务器时钟偏移。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000009',
    folder: 'Playbooks',
    filename: 'KN-20261110-000009_旧版同步脚本部署.md',
    note_type: 'playbook',
    title: '旧版同步脚本部署',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'observed',
    review_state: 'accepted',
    env: 'windows',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e01_Codex容器与备份证据.md]]'],
    body: '## 4. 处理步骤\n旧版同步脚本部署流程（存在未决冲突提案，不得作为直接操作依据）。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000010',
    folder: 'Project_States',
    filename: 'KN-20261110-000010_十月旧版发布计划.md',
    note_type: 'project_state',
    title: '十月旧版发布计划',
    project: 'ObsidianOps',
    privacy: 'sanitized',
    lifecycle: 'active',
    evidence_level: 'observed',
    review_state: 'accepted',
    as_of: '2026-10-01',
    review_after: '2026-10-15',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e02_Antigravity环境与IP证据.md]]'],
    body: '## 1. 现象与触发情境\n十月旧版发布计划已过复核期，检索必须降入 Channel 2。\n'
  },
  {
    id: 'KN-019316a8-0001-7000-8000-000000000011',
    folder: 'Playbooks',
    filename: 'KN-20261110-000011_本地私有银行证书导入.md',
    note_type: 'playbook',
    title: '本地私有银行证书导入',
    project: 'ObsidianOps',
    privacy: 'local_only',
    lifecycle: 'active',
    evidence_level: 'user_confirmed',
    review_state: 'accepted',
    env: 'windows',
    sources: ['[[20_Evidence_Cards/EV-20261110-000e01_Codex容器与备份证据.md]]'],
    body: '## 1. 现象与触发情境\n本地私有银行证书导入（local_only 严禁进入任何出口或检索结果）。\n'
  }
];

/**
 * 在指定临时沙箱路径中创建完整的 14 题探索评测合成语料库（显式覆盖 codex / antigravity / dsh 三端来源）
 */
export function buildSyntheticPilotCorpus({ vaultDir, dataDir }) {
  initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
  const db = openDatabase(dbPath);
  const stagingDir = path.join(dataDir, 'staging');
  const nowIso = '2026-11-10T12:00:00+08:00';

  try {
    // 1. 写入覆盖三端来源的合成可读会话 (10_Readable_Sessions/)
    for (let i = 0; i < SYNTHETIC_PILOT_SESSIONS.length; i++) {
      const s = SYNTHETIC_PILOT_SESSIONS[i];
      const sesMd = `---
schema_version: 1
id: "${s.id}"
note_type: "session"
title: "${s.title}"
project: "${s.project}"
privacy: "sanitized"
source_tool: "${s.source_tool}"
session_id: "${s.session_id}"
snapshot_id: "${s.snapshot_id}"
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

# ${s.title}

${s.body}`;
      const sesPath = path.join(vaultDir, '10_Readable_Sessions', s.filename);
      const stg = stageCandidate({ stagingDir, outputUuid: s.id, content: sesMd });
      publishFile({
        db,
        operationId: `pilot-ses-${i + 1}`,
        outputUuid: s.id,
        stagingPath: stg.stagingPath,
        vaultTargetPath: sesPath,
        contentSha256: stg.contentSha256,
        metadata: {
          note_type: 'session',
          source_tool: s.source_tool,
          title: s.title,
          project: s.project,
          privacy: 'sanitized',
          created_at: nowIso
        }
      });
    }

    // 2. 写入单来源原子证据卡 (20_Evidence_Cards/)
    for (let i = 0; i < SYNTHETIC_PILOT_EVIDENCE.length; i++) {
      const ev = SYNTHETIC_PILOT_EVIDENCE[i];
      const evMd = `---
schema_version: 1
id: "${ev.id}"
note_type: "evidence"
title: "${ev.title}"
project: "${ev.project}"
privacy: "sanitized"
source_tool: "${ev.source_tool}"
evidence_level: "observed"
sources:
  - "[[10_Readable_Sessions/${ev.session_file}#^event-000001]]"
created_at: "${nowIso}"
---

# ${ev.title}
`;
      const evPath = path.join(vaultDir, '20_Evidence_Cards', ev.filename);
      const stg = stageCandidate({ stagingDir, outputUuid: ev.id, content: evMd });
      publishFile({
        db,
        operationId: `pilot-ev-${i + 1}`,
        outputUuid: ev.id,
        stagingPath: stg.stagingPath,
        vaultTargetPath: evPath,
        contentSha256: stg.contentSha256,
        metadata: {
          note_type: 'evidence',
          source_tool: ev.source_tool,
          title: ev.title,
          project: ev.project,
          privacy: 'sanitized',
          evidence_level: 'observed',
          created_at: nowIso
        }
      });
    }

    // 3. 写入正式知识笔记 (30_Knowledge_Notes/)
    for (let i = 0; i < SYNTHETIC_NOTES.length; i++) {
      const n = SYNTHETIC_NOTES[i];
      const extraYaml = [
        n.env ? `env: "${n.env}"` : '',
        n.as_of ? `as_of: "${n.as_of}"` : '',
        n.review_after ? `review_after: "${n.review_after}"` : ''
      ].filter(Boolean).join('\n');
      const sourcesYaml = (n.sources || ['[[20_Evidence_Cards/EV-20261110-000e01_Codex容器与备份证据.md]]'])
        .map(src => `  - "${src}"`)
        .join('\n');

      const md = `---
schema_version: 1
id: "${n.id}"
note_type: "${n.note_type}"
title: "${n.title}"
project: "${n.project}"
privacy: "${n.privacy}"
lifecycle: "${n.lifecycle}"
evidence_level: "${n.evidence_level}"
review_state: "${n.review_state}"
${extraYaml}
aliases:
  - "${n.title}"
sources:
${sourcesYaml}
created_at: "${nowIso}"
---

${n.body}`;

      const targetPath = path.join(vaultDir, '30_Knowledge_Notes', n.folder, n.filename);
      const staged = stageCandidate({ stagingDir, outputUuid: n.id, content: md });
      publishFile({
        db,
        operationId: `pilot-op-${i + 1}`,
        outputUuid: n.id,
        stagingPath: staged.stagingPath,
        vaultTargetPath: targetPath,
        contentSha256: staged.contentSha256,
        metadata: {
          note_type: n.note_type,
          title: n.title,
          project: n.project,
          privacy: n.privacy,
          lifecycle: n.lifecycle,
          evidence_level: n.evidence_level,
          review_state: n.review_state,
          as_of: n.as_of || null,
          review_after: n.review_after || null,
          created_at: nowIso
        }
      });
    }

    // 为 KN-009 添加一条未决冲突提案 PROP-PILOT-009
    const propPath = path.join(vaultDir, '40_Review_Queue', 'PROP-20261110-000009_旧版同步脚本冲突提案.md');
    fs.writeFileSync(
      propPath,
      `---
schema_version: 1
id: "PROP-019316a8-0001-7000-8000-999999999909"
note_type: "proposal"
title: "旧版同步脚本冲突提案"
project: "ObsidianOps"
privacy: "sanitized"
target_id: "KN-019316a8-0001-7000-8000-000000000009"
target_note: "[[30_Knowledge_Notes/Playbooks/KN-20261110-000009_旧版同步脚本部署.md]]"
base_revision_id: "rev-0001"
proposal_kind: "conflict"
proposal_status: "pending"
created_at: "${nowIso}"
---
冲突提案说明
`,
      'utf8'
    );

    const indexDir = path.join(dataDir, 'runtime', 'index');
    buildLocalSearchIndex({ vaultDir, indexDir });

    return {
      vaultDir,
      dataDir,
      dbPath,
      indexDir,
      questions: PILOT_QUESTIONS
    };
  } finally {
    db.close();
  }
}
