import fs from 'node:fs';
import path from 'node:path';
import { openDatabase } from './db/sqlite.mjs';
import { ensureInstanceIdentity } from './storage/instance-identity.mjs';
import { getDefaultVaultPath, getDefaultDataPath } from './config/paths.mjs';

export const DEFAULT_VAULT_PATH = getDefaultVaultPath();
export const DEFAULT_DATA_PATH = getDefaultDataPath();

export const BASES_VIEWS = {
  '知识总览.base': `filters:
  and:
    - file.inFolder("30_Knowledge_Notes")
    - '!file.inFolder("90_Templates")'
properties:
  note.project:
    displayName: 项目
  note.note_type:
    displayName: 类型
  note.lifecycle:
    displayName: 生命周期
  note.evidence_level:
    displayName: 证据等级
  note.review_state:
    displayName: 审核状态
views:
  - type: table
    name: 全部知识笔记
    order:
      - file.name
      - project
      - note_type
      - lifecycle
      - evidence_level
      - review_state
`,
  '待处理更新.base': `filters:
  and:
    - file.inFolder("40_Review_Queue")
    - '!file.inFolder("90_Templates")'
properties:
  note.project:
    displayName: 项目
  note.proposal_kind:
    displayName: 提案类型
  note.proposal_status:
    displayName: 提案状态
  note.target_note:
    displayName: 目标笔记
  note.base_revision_id:
    displayName: 基准版本
  note.created_at:
    displayName: 提出时间
views:
  - type: table
    name: 待处理更新提案
    filters:
      and:
        - note.proposal_status == "pending"
    order:
      - file.name
      - project
      - proposal_kind
      - target_note
      - base_revision_id
      - created_at
    sort:
      - property: file.name
        direction: ASC
      - property: project
        direction: ASC
      - property: proposal_kind
        direction: ASC
      - property: target_note
        direction: ASC
      - property: base_revision_id
        direction: DESC
      - property: created_at
        direction: ASC
  - type: table
    name: 已标采纳（核对状态见 mem status）
    filters:
      and:
        - note.proposal_status == "accepted"
    order:
      - file.name
      - project
      - proposal_kind
      - target_note
      - base_revision_id
      - created_at
`,
  '到期复核.base': `filters:
  and:
    - file.inFolder("30_Knowledge_Notes")
    - '!file.inFolder("90_Templates")'
    - note.lifecycle == "active"
    - or:
        - note.review_state == "pending"
        - note.review_state == "disputed"
        - and:
            - note.review_after
            - date(note.review_after) <= today()
properties:
  note.project:
    displayName: 项目
  note.review_state:
    displayName: 审核状态
  note.review_after:
    displayName: 计划复核日
  note.evidence_level:
    displayName: 证据等级
views:
  - type: table
    name: 待审与到期复核队列
    order:
      - file.name
      - project
      - review_state
      - review_after
      - evidence_level
`,
  '会话与证据溯源.base': `filters:
  and:
    - '!file.inFolder("90_Templates")'
    - or:
        - file.inFolder("10_Readable_Sessions")
        - file.inFolder("20_Evidence_Cards")
properties:
  note.source_tool:
    displayName: 来源Agent
  note.project:
    displayName: 项目
  note.session_id:
    displayName: 会话ID
  note.snapshot_id:
    displayName: 快照ID
  note.evidence_level:
    displayName: 证据等级
  note.sources:
    displayName: 来源锚点
  note.created_at:
    displayName: 创建时间
views:
  - type: table
    name: 已整理会话台账
    filters:
      and:
        - file.inFolder("10_Readable_Sessions")
    order:
      - file.name
      - source_tool
      - project
      - session_id
      - snapshot_id
      - created_at
  - type: table
    name: 原子证据卡台账
    filters:
      and:
        - file.inFolder("20_Evidence_Cards")
    order:
      - file.name
      - source_tool
      - project
      - evidence_level
      - sources
      - created_at
`
};

export const TEMPLATES = {
  'Template_Session.md': `---
schema_version: 1
id: "{{id}}"
note_type: "session"
title: "{{title}}"
project: "{{project}}"
privacy: "{{privacy}}"
source_tool: "{{source_tool}}"
session_id: "{{session_id}}"
snapshot_id: "{{snapshot_id}}"
coverage:
  total_events: 0
  rendered_events: 0
  omitted_events: 0
  parse_error_events: 0
  backfilled_truncations: 0
  unresolved_truncations: 0
  attachments_count: 0
created_at: "{{created_at}}"
---

# {{title}}

## 会话覆盖清单
- 快照 ID: \`{{snapshot_id}}\`
- 事件总数: 0 | 已渲染: 0 | 已省略: 0

## 会话事件记录
^event-000001
`,
  'Template_Evidence.md': `---
schema_version: 1
id: "{{id}}"
note_type: "evidence"
title: "{{title}}"
project: "{{project}}"
privacy: "{{privacy}}"
source_tool: "{{source_tool}}"
evidence_level: "observed"
sources:
  - "[[10_Readable_Sessions/{{session_file}}#^event-000001]]"
created_at: "{{created_at}}"
---

# {{title}}

## 观察事实
- 来源: [[10_Readable_Sessions/{{session_file}}#^event-000001]]
- 事实描述:
`,
  'Template_Playbook.md': `---
schema_version: 1
id: "{{id}}"
note_type: "playbook"
title: "{{title}}"
project: "{{project}}"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "pending"
env:
  os: "windows"
sources:
  - "[[20_Evidence_Cards/{{evidence_file}}]]"
aliases:
  - "{{title}}"
created_at: "{{created_at}}"
---

# {{title}}

## 1. 现象与触发情境

## 2. 适用环境与约束

## 3. 依据、证据边界与待验证推测

## 4. 处理步骤

## 5. 验证方法与实际结果

## 6. 风险、例外与未决问题
`,
  'Template_Proposal.md': `---
schema_version: 1
id: "{{id}}"
note_type: "proposal"
title: "{{title}}"
project: "{{project}}"
privacy: "sanitized"
target_id: "{{target_id}}"
target_note: "[[30_Knowledge_Notes/{{target_folder}}/{{target_file}}]]"
base_revision_id: "rev-0001"
proposal_kind: "conflict"
proposal_status: "pending"
sources:
  - "[[20_Evidence_Cards/{{evidence_file}}]]"
created_at: "{{created_at}}"
---

# {{title}}

## 1. 更新原因与提案类型

## 2. 新证据来源

## 3. 建议变更内容（与基准版本 {{base_revision_id}} 的差异）

## 4. 采纳指南与影响评估
`
};

export const INDEX_MD = `# MindLoom · Agent × Obsidian 记忆库

欢迎使用本地原生 Agent 记忆库（双目录安全隔离 · 原生 Bases 视图 · 可选零依赖伴侣控制台）。

## 核心视图入口
- [[50_Bases_Views/知识总览.base|知识总览 (全部正式知识)]]
- [[50_Bases_Views/待处理更新.base|待处理更新 (待审提案与已采纳队列)]]
- [[50_Bases_Views/到期复核.base|到期复核 (待审与到期复核队列)]]
- [[50_Bases_Views/会话与证据溯源.base|会话与证据溯源 (会话台账与证据卡)]]

## 目录索引
- \`10_Readable_Sessions/\`: 经脱敏后的可读原始会话
- \`20_Evidence_Cards/\`: 原子证据卡
- \`30_Knowledge_Notes/\`: 正式知识笔记（Playbooks / Decisions / Project_States / Preferences）
- \`40_Review_Queue/\`: 独立更新提案队列（只增不改）
- \`50_Bases_Views/\`: 原生 Bases 中文视图
- \`90_Templates/\`: 模板目录（全局排除在检索与看板外）
`;

function dirHasAnyFiles(dir, extensionFilter = null) {
  if (!fs.existsSync(dir)) return false;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (dirHasAnyFiles(full, extensionFilter)) return true;
    } else if (entry.isFile()) {
      if (!extensionFilter || entry.name.endsWith(extensionFilter)) return true;
    }
  }
  return false;
}

/**
 * 初始化双目录
 * @param {object} options
 * @param {string} [options.vaultPath]
 * @param {string} [options.dataPath]
 * @param {boolean} [options.allowMissingDb]
 */
export function initRepository(options = {}) {
  const vaultPath = options.vaultPath || DEFAULT_VAULT_PATH;
  const dataPath = options.dataPath || DEFAULT_DATA_PATH;
  const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');

  // §2 铁律：若 Vault/Data 已存持久化内容但 state.sqlite 缺失，严禁静默初始化为空库
  if (!fs.existsSync(dbPath) && !options.allowMissingDb) {
    const hasExistingArtifacts =
      dirHasAnyFiles(path.join(dataPath, 'raw')) ||
      dirHasAnyFiles(path.join(dataPath, 'manifests')) ||
      dirHasAnyFiles(path.join(dataPath, 'attachments')) ||
      dirHasAnyFiles(path.join(dataPath, 'runtime', 'revisions')) ||
      dirHasAnyFiles(path.join(vaultPath, '10_Readable_Sessions'), '.md') ||
      dirHasAnyFiles(path.join(vaultPath, '20_Evidence_Cards'), '.md') ||
      dirHasAnyFiles(path.join(vaultPath, '30_Knowledge_Notes'), '.md') ||
      dirHasAnyFiles(path.join(vaultPath, '40_Review_Queue'), '.md');
    if (hasExistingArtifacts) {
      throw new Error(
        `CRITICAL_STATE_DB_MISSING: 检测到已有 Vault/Data 持久化数据但核心状态库 state.sqlite 缺失 (${dbPath})！严禁自动初始化为空库，请从备份恢复。`
      );
    }
  }

  // 独立复审 B1：已初始化或已有内容（含半初始化）时，在首次创建/写入任何文件前直接拒绝
  if (fs.existsSync(dbPath)) {
    throw new Error(
      `INIT_ALREADY_INITIALIZED: 检测到已有核心状态库 (${dbPath})，拒绝重复初始化以保护现有配置、视图、模板与台账。`
    );
  }
  if (dirHasAnyFiles(vaultPath) || dirHasAnyFiles(dataPath)) {
    throw new Error(
      `INIT_ALREADY_INITIALIZED: 检测到 Vault (${vaultPath}) 或 Data (${dataPath}) 已存在文件或半初始化内容，拒绝覆盖或盲目续写。`
    );
  }

  // 1. 创建 Vault 目录结构
  const vaultDirs = [
    vaultPath,
    path.join(vaultPath, '00_MOC'),
    path.join(vaultPath, '10_Readable_Sessions'),
    path.join(vaultPath, '20_Evidence_Cards'),
    path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks'),
    path.join(vaultPath, '30_Knowledge_Notes', 'Decisions'),
    path.join(vaultPath, '30_Knowledge_Notes', 'Project_States'),
    path.join(vaultPath, '30_Knowledge_Notes', 'Preferences'),
    path.join(vaultPath, '40_Review_Queue'),
    path.join(vaultPath, '50_Bases_Views'),
    path.join(vaultPath, '90_Templates'),
    path.join(vaultPath, '.obsidian')
  ];

  for (const dir of vaultDirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  // 2. 写入 Vault 核心文件（保留用户可能已自定义的 首页.md）
  const indexMdPath = path.join(vaultPath, '首页.md');
  if (!fs.existsSync(indexMdPath)) {
    fs.writeFileSync(indexMdPath, INDEX_MD, 'utf8');
  }

  // .obsidian 配置（零第三方社区插件）
  fs.writeFileSync(path.join(vaultPath, '.obsidian', 'community-plugins.json'), '[]\n', 'utf8');
  fs.writeFileSync(path.join(vaultPath, '.obsidian', 'app.json'), JSON.stringify({
    spellcheck: false,
    promptDelete: false,
    showLineNumber: true
  }, null, 2) + '\n', 'utf8');

  // .gitignore
  const vaultGitignore = `.obsidian/workspace.json
.obsidian/workspace-mobile.json
.obsidian/cache/
.obsidian/plugins/
.claudian/
.trash/
`;
  fs.writeFileSync(path.join(vaultPath, '.gitignore'), vaultGitignore, 'utf8');

  // 写入 4 个 Bases 视图
  for (const [filename, content] of Object.entries(BASES_VIEWS)) {
    fs.writeFileSync(path.join(vaultPath, '50_Bases_Views', filename), content, 'utf8');
  }

  // 写入 模板文件
  for (const [filename, content] of Object.entries(TEMPLATES)) {
    fs.writeFileSync(path.join(vaultPath, '90_Templates', filename), content, 'utf8');
  }

  // 3. 创建 Data 目录结构
  const dataDirs = [
    dataPath,
    path.join(dataPath, 'raw'),
    path.join(dataPath, 'raw', 'codex'),
    path.join(dataPath, 'raw', 'antigravity'),
    path.join(dataPath, 'raw', 'dsh'),
    path.join(dataPath, 'attachments'),
    path.join(dataPath, 'manifests'),
    path.join(dataPath, 'staging'),
    path.join(dataPath, 'egress'),
    path.join(dataPath, 'runtime', 'index'),
    path.join(dataPath, 'runtime', 'revisions'),
    path.join(dataPath, 'runtime', 'stale-locks'),
    path.join(dataPath, 'runtime', 'benchmarks'),
    path.join(dataPath, 'runtime', 'logs'),
    path.join(dataPath, 'cli')
  ];

  for (const dir of dataDirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  // 初始化默认 manifests/project-map.json（供三端会话项目归属自动推导）
  const projectMapPath = path.join(dataPath, 'manifests', 'project-map.json');
  if (!fs.existsSync(projectMapPath)) {
    const initialProjects = Array.isArray(options.initialProjects) ? options.initialProjects : [];
    const defaultProjectMap = {
      schema_version: 1,
      default_unmapped_project: 'unmapped',
      projects: initialProjects
    };
    fs.writeFileSync(projectMapPath, JSON.stringify(defaultProjectMap, null, 2) + '\n', 'utf8');
  }

  // Data 目录硬性防上传拦截 .gitignore
  const dataGitignore = `*
!.gitignore
`;
  fs.writeFileSync(path.join(dataPath, '.gitignore'), dataGitignore, 'utf8');

  // 4. 初始化 state.sqlite
  const db = openDatabase(dbPath);
  db.close();

  const instanceIdentity = ensureInstanceIdentity({ vaultPath, dataPath });

  return {
    vaultPath,
    dataPath,
    dbPath,
    instanceIdentity
  };
}

/**
 * 仅补全 90_Templates 下缺失的模板文件，绝不覆盖任何已存在的模板、视图、.obsidian 配置或台账
 */
export function ensureMissingTemplates({ vaultPath }) {
  const templatesDir = path.join(vaultPath, '90_Templates');
  fs.mkdirSync(templatesDir, { recursive: true });
  const created = [];
  const skipped = [];
  for (const [filename, content] of Object.entries(TEMPLATES)) {
    const dest = path.join(templatesDir, filename);
    if (fs.existsSync(dest)) {
      skipped.push(filename);
    } else {
      fs.writeFileSync(dest, content, 'utf8');
      created.push(filename);
    }
  }
  return { templatesDir, created, skipped };
}

/**
 * 只读预览 50_Bases_Views/*.base 与内置模板的差异，绝不自动覆盖用户视图
 */
export function previewBaseViewChanges({ vaultPath }) {
  const viewsDir = path.join(vaultPath, '50_Bases_Views');
  const views = [];
  for (const [filename, expectedContent] of Object.entries(BASES_VIEWS)) {
    const dest = path.join(viewsDir, filename);
    if (!fs.existsSync(dest)) {
      views.push({ filename, status: 'missing', currentContent: null, proposedContent: expectedContent });
      continue;
    }
    const currentContent = fs.readFileSync(dest, 'utf8');
    if (currentContent === expectedContent) {
      views.push({ filename, status: 'unchanged' });
    } else {
      views.push({ filename, status: 'modified_requires_manual_confirm', currentContent, proposedContent: expectedContent });
    }
  }
  return { viewsDir, views };
}
