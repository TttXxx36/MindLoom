import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { formatFileName, findMarkdownFiles } from '../storage/path-sanitizer.mjs';
import { parseMarkdownFrontmatter, formatYamlScalar } from '../schema/frontmatter.mjs';

/**
 * 计算 SHA-256
 * @param {string} text
 * @returns {string}
 */
export function calculateSha256(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * 解析 YAML Frontmatter 与条件列表
 * @param {string} content
 * @returns {object}
 */
export function parseProposalContent(content) {
  const { frontmatter, body } = parseMarkdownFrontmatter(content);

  const normalizeList = (val) => {
    if (Array.isArray(val)) {
      return val.map(v => String(v ?? '').trim()).filter(Boolean);
    }
    return [];
  };

  return {
    frontmatter: {
      id: frontmatter.id ?? null,
      schema_version: frontmatter.schema_version ?? null,
      note_type: frontmatter.note_type ?? null,
      title: frontmatter.title ?? null,
      project: frontmatter.project ?? null,
      privacy: frontmatter.privacy ?? null,
      target_id: frontmatter.target_id ?? null,
      target_note: frontmatter.target_note ?? null,
      base_revision_id: frontmatter.base_revision_id ?? null,
      proposal_kind: frontmatter.proposal_kind ?? null,
      proposal_status: frontmatter.proposal_status ?? null,
      created_at: frontmatter.created_at ?? null,
      pre_conditions: normalizeList(frontmatter.pre_conditions),
      post_conditions: normalizeList(frontmatter.post_conditions),
      sources: normalizeList(frontmatter.sources)
    },
    body
  };
}

/**
 * 只增不改：创建独立更新提案 (PROP-*.md)
 * @param {{
 *   queueDir: string,
 *   proposalUuid: string,
 *   title: string,
 *   project: string,
 *   targetId: string,
 *   targetNoteRef: string,
 *   baseRevisionId: string,
 *   proposalKind: 'supplement' | 'conflict' | 'supersede',
 *   preConditions?: string[],
 *   postConditions?: string[],
 *   reason: string
 * }} options
 * @returns {{ proposalPath: string, proposalUuid: string }}
 */
export function createProposal({
  queueDir,
  proposalUuid,
  title,
  project,
  targetId,
  targetNoteRef,
  baseRevisionId = 'rev-0001',
  proposalKind = 'conflict',
  preConditions = [],
  postConditions = [],
  reason = ''
}) {
  if (!fs.existsSync(queueDir)) {
    fs.mkdirSync(queueDir, { recursive: true });
  }

  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const fileName = formatFileName({
    prefix: 'PROP',
    dateStr,
    uuid: proposalUuid,
    title
  });

  const proposalPath = path.join(queueDir, fileName);

  const preLines = preConditions.map(c => `  - ${formatYamlScalar(c)}`).join('\n');
  const postLines = postConditions.map(c => `  - ${formatYamlScalar(c)}`).join('\n');

  const content = `---
schema_version: 1
id: ${formatYamlScalar(proposalUuid)}
note_type: "proposal"
title: ${formatYamlScalar(title)}
project: ${formatYamlScalar(project)}
privacy: "sanitized"
created_at: ${formatYamlScalar(new Date().toISOString())}
target_id: ${formatYamlScalar(targetId)}
target_note: ${formatYamlScalar(targetNoteRef)}
base_revision_id: ${formatYamlScalar(baseRevisionId)}
proposal_kind: ${formatYamlScalar(proposalKind)}
proposal_status: "pending"
pre_conditions:
${preLines || '  - ""'}
post_conditions:
${postLines || '  - ""'}
---

## 1. 更新原因与提案类型
${reason}

## 2. 新证据来源
- 来源锚点: 现场排查与反馈

## 3. 建议变更内容（与基准版本 ${baseRevisionId} 的差异）
- 建议移除旧步骤，替换为新版操作。

## 4. 采纳指南与影响评估
- 请在审阅合入后运行 mem reconcile 确认。
`;

  fs.writeFileSync(proposalPath, content, 'utf8');

  return {
    proposalPath,
    proposalUuid
  };
}

function normalizeMarkdownRef(ref) {
  return String(ref || '')
    .trim()
    .replace(/^\[\[/, '')
    .replace(/\]\]$/, '')
    .split('|')[0]
    .replace(/\.md(?=(#|$))/i, '')
    .replace(/\\/g, '/')
    .trim();
}

function stripHtmlComments(text) {
  return String(text || '').replace(/<!--[\s\S]*?-->/g, '');
}

function splitFrontmatterRaw(rawText) {
  const norm = String(rawText || '').replace(/\r\n/g, '\n');
  const match = norm.match(/^---\n([\s\S]*?)\n---(?:\n([\s\S]*))?$/);
  if (!match) {
    return { fmRaw: '', bodyRaw: norm };
  }
  return { fmRaw: match[1] || '', bodyRaw: match[2] || '' };
}

function evaluateSingleCondition(rawCond, ctx) {
  const cond = String(rawCond || '').replace(/\r\n/g, '\n').trim();
  if (!cond) {
    return { kind: 'empty', matchedInTarget: false };
  }

  // 1. yaml:<key>=<val> 或 frontmatter:<key>=<val>
  const yamlMatch = cond.match(/^(?:yaml|frontmatter):\s*([a-zA-Z0-9_.-]+)\s*(?:==|=|:)\s*(.+)$/);
  if (yamlMatch) {
    const [, key, expectedRaw] = yamlMatch;
    const expected = expectedRaw.trim().replace(/^['"]|['"]$/g, '');
    const actual = ctx.frontmatter?.[key];
    let matched = false;
    if (Array.isArray(actual)) {
      matched = actual.some(item => String(item).trim() === expected);
    } else if (actual !== undefined && actual !== null) {
      matched = String(actual).trim() === expected;
    }
    return { kind: 'yaml_field', key, matchedInTarget: matched };
  }

  const isSingleLine = !/[\r\n]/.test(cond);

  // 2. section:<heading> 或 heading:<heading> 或单行 Markdown 标题行 (#+ Title)
  const sectionMatch = isSingleLine ? cond.match(/^(?:section|heading):\s*(.+)$/i) : null;
  if (sectionMatch || (isSingleLine && /^#{1,6}\s+\S+$/.test(cond))) {
    const targetHeading = (sectionMatch ? sectionMatch[1] : cond)
      .trim()
      .replace(/^#{1,6}\s+/, '')
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase();
    const matched = ctx.headings.some(h => h === targetHeading);
    return { kind: 'section', matchedInTarget: matched };
  }

  // 3. citation:<ref> 或 link:<ref> 或单行独立 [[wikilink]]
  const citationMatch = isSingleLine ? cond.match(/^(?:citation|link|source):\s*(.+)$/i) : null;
  if (citationMatch || (isSingleLine && /^\[\[[^\]]+\]\]$/.test(cond))) {
    const normWanted = normalizeMarkdownRef(citationMatch ? citationMatch[1] : cond);
    const matched = ctx.normalizedLinks.some(l => l === normWanted || l.endsWith(`/${normWanted}`) || normWanted.endsWith(`/${l}`));
    return { kind: 'citation', matchedInTarget: matched };
  }

  // 4. 单行 YAML 键值声明 key: value（仅当目标无对应正文时同时校验 frontmatter 精确字段）
  const kvMatch = cond.match(/^([a-zA-Z][a-zA-Z0-9_]{1,40}):\s+(.+)$/);
  if (kvMatch) {
    const [, key, expectedRaw] = kvMatch;
    const expected = expectedRaw.trim().replace(/^['"]|['"]$/g, '');
    const actual = ctx.frontmatter?.[key];
    let fmMatched = false;
    if (Array.isArray(actual)) {
      fmMatched = actual.some(item => String(item).trim() === expected);
    } else if (actual !== undefined && actual !== null) {
      fmMatched = String(actual).trim() === expected;
    }
    if (fmMatched || ctx.cleanBody.includes(cond)) {
      return { kind: 'yaml_or_text', matchedInTarget: true };
    }
    return { kind: 'yaml_or_text', matchedInTarget: false };
  }

  // 5. 常规正文文本条件（剥离 HTML 注释并归一化换行；若正文未命中则在非注释 YAML 块内做精确行匹配）
  if (ctx.cleanBody.includes(cond)) {
    return { kind: 'body_text', matchedInTarget: true };
  }
  const fmLines = ctx.cleanFm.split('\n').map(l => l.trim());
  const matchedInFmLine = fmLines.some(line => line === cond || line.includes(cond));
  return { kind: 'body_text', matchedInTarget: matchedInFmLine };
}

/**
 * 统一评估提案的前置消除与后置落地条件（reconcile 与 proposal show 共用）
 * @param {{
 *   targetRaw: string,
 *   preConditions?: string[],
 *   postConditions?: string[]
 * }} params
 */
export function evaluateProposalConditions({ targetRaw, preConditions = [], postConditions = [] }) {
  const { frontmatter } = parseMarkdownFrontmatter(targetRaw);
  const { fmRaw, bodyRaw } = splitFrontmatterRaw(targetRaw);
  const cleanBody = stripHtmlComments(bodyRaw);
  const cleanFm = stripHtmlComments(fmRaw);

  const headings = [];
  for (const line of cleanBody.split('\n')) {
    const m = line.match(/^#{1,6}\s+(.+?)\s*$/);
    if (m) {
      headings.push(m[1].replace(/\s+/g, ' ').trim().toLowerCase());
    }
  }

  const normalizedLinks = [];
  if (Array.isArray(frontmatter?.sources)) {
    for (const s of frontmatter.sources) {
      const n = normalizeMarkdownRef(s);
      if (n) normalizedLinks.push(n);
    }
  }
  for (const match of cleanBody.matchAll(/\[\[([^\]]+)\]\]/g)) {
    const n = normalizeMarkdownRef(match[1]);
    if (n) normalizedLinks.push(n);
  }

  const ctx = { frontmatter, cleanBody, cleanFm, headings, normalizedLinks };

  let preOk = true;
  let failedReason = null;
  const preResults = [];
  for (const cond of preConditions) {
    if (!cond) continue;
    const ev = evaluateSingleCondition(cond, ctx);
    const removed = !ev.matchedInTarget;
    preResults.push({
      text: cond,
      kind: ev.kind,
      matched_in_target: ev.matchedInTarget,
      removed,
      passed: removed
    });
    if (preOk && !removed) {
      preOk = false;
      failedReason = `pre_condition_unmet: obsolete text "${cond}" still present in target note`;
    }
  }

  let postOk = true;
  const postResults = [];
  for (const cond of postConditions) {
    if (!cond) continue;
    const ev = evaluateSingleCondition(cond, ctx);
    const present = ev.matchedInTarget;
    postResults.push({
      text: cond,
      kind: ev.kind,
      matched_in_target: present,
      present,
      passed: present
    });
    if (preOk && postOk && !present) {
      postOk = false;
      failedReason = `post_condition_unmet: required text "${cond}" not found in target note`;
    }
  }

  return {
    preOk,
    postOk,
    passed: preOk && postOk,
    failedReason,
    pre_conditions: preResults,
    post_conditions: postResults
  };
}

function archiveRevisionIfContentChanged(revisionsDir, noteId, contentRaw) {
  if (!revisionsDir || !noteId) return null;
  const noteRevDir = path.join(revisionsDir, noteId);
  if (!fs.existsSync(noteRevDir)) {
    fs.mkdirSync(noteRevDir, { recursive: true });
  }
  const latestPath = path.join(noteRevDir, 'latest.md');
  const currentHash = calculateSha256(contentRaw);
  if (fs.existsSync(latestPath) && calculateSha256(fs.readFileSync(latestPath, 'utf8')) === currentHash) {
    return null;
  }
  const existingRevs = fs.readdirSync(noteRevDir)
    .map(name => {
      const m = name.match(/^rev-(\d+)\.md$/);
      return m ? Number(m[1]) : 0;
    })
    .filter(n => n > 0);
  const nextNum = (existingRevs.length > 0 ? Math.max(...existingRevs) : 0) + 1;
  const revId = `rev-${String(nextNum).padStart(4, '0')}`;
  const revPath = path.join(noteRevDir, `${revId}.md`);
  fs.writeFileSync(revPath, contentRaw, 'utf8');
  fs.writeFileSync(latestPath, contentRaw, 'utf8');
  return { revId, revPath };
}

/**
 * 结构化前后置条件核对 (mem reconcile)
 * @param {{
 *   db: any,
 *   proposalPath: string,
 *   targetPath: string,
 *   revisionsDir?: string | null
 * }} params
 * @returns {{ proposal_id: string, reconcile_state: string, reason: string | null }}
 */
export function reconcileProposal({ db, proposalPath, targetPath, revisionsDir = null }) {
  if (!fs.existsSync(proposalPath)) {
    throw new Error(`提案文件不存在: ${proposalPath}`);
  }
  if (!fs.existsSync(targetPath)) {
    throw new Error(`目标文件不存在: ${targetPath}`);
  }

  const propRaw = fs.readFileSync(proposalPath, 'utf8');
  const targetRaw = fs.readFileSync(targetPath, 'utf8');

  const propParsed = parseProposalContent(propRaw);
  const { id: proposalId, target_id: targetId, proposal_status, pre_conditions, post_conditions } = propParsed.frontmatter;
  const targetParsed = parseMarkdownFrontmatter(targetRaw);
  const actualTargetId = targetParsed.frontmatter?.id;

  const currentPropHash = calculateSha256(propRaw);
  const currentTargetHash = calculateSha256(targetRaw);

  let state = 'unverified';
  let reason = null;
  let conditionChecks = null;

  if (actualTargetId && targetId && actualTargetId !== targetId) {
    state = 'mismatch';
    reason = `target_id_mismatch: expected ${targetId} got ${actualTargetId}`;
  } else if (proposal_status !== 'accepted') {
    state = 'unverified';
    reason = `proposal_status_is_${proposal_status}`;
  } else if (pre_conditions.length === 0 && post_conditions.length === 0) {
    // 防空条件绕过：无任何前置消除或后置落地结构化条件时严禁自动放行 verified_applied
    state = 'mismatch';
    reason = 'missing_structured_conditions';
  } else {
    conditionChecks = evaluateProposalConditions({
      targetRaw,
      preConditions: pre_conditions,
      postConditions: post_conditions
    });
    if (conditionChecks.passed) {
      state = 'verified_applied';
      reason = null;
    } else {
      state = 'unverified';
      reason = conditionChecks.failedReason;
    }
  }

  let archivedRevision = null;
  if (revisionsDir && actualTargetId) {
    archivedRevision = archiveRevisionIfContentChanged(revisionsDir, actualTargetId, targetRaw);
  }

  const nowIso = new Date().toISOString();

  // 持久化到 reconcile_states（仅 reconcile 写入口持久化，查询命令严格只读）
  db.prepare(`
    INSERT INTO reconcile_states (proposal_id, proposal_version_sha256, target_id, target_version_sha256, reconcile_state, reason, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(proposal_id) DO UPDATE SET
      proposal_version_sha256 = excluded.proposal_version_sha256,
      target_id = excluded.target_id,
      target_version_sha256 = excluded.target_version_sha256,
      reconcile_state = excluded.reconcile_state,
      reason = excluded.reason,
      updated_at = excluded.updated_at
  `).run(proposalId, currentPropHash, targetId, currentTargetHash, state, reason, nowIso);

  return {
    proposal_id: proposalId,
    reconcile_state: state,
    reason,
    proposal_version_sha256: currentPropHash,
    target_version_sha256: currentTargetHash,
    condition_checks: conditionChecks,
    archived_revision: archivedRevision ? archivedRevision.revId : null
  };
}

/**
 * 纯只读实时检查双版本哈希绑定状态（失配时实时返回 unverified / version_changed，绝不在查询中写入 SQLite）
 * @param {{
 *   db: any,
 *   proposalPath: string,
 *   targetPath: string
 * }} params
 * @returns {{ reconcile_state: string, reason: string | null }}
 */
export function checkProposalReconcileState({ db, proposalPath, targetPath }) {
  if (!fs.existsSync(proposalPath) || !fs.existsSync(targetPath)) {
    return { reconcile_state: 'unverified', reason: 'file_missing' };
  }

  const propRaw = fs.readFileSync(proposalPath, 'utf8');
  const targetRaw = fs.readFileSync(targetPath, 'utf8');

  const propParsed = parseProposalContent(propRaw);
  const proposalId = propParsed.frontmatter.id;

  const record = db.prepare('SELECT * FROM reconcile_states WHERE proposal_id = ?').get(proposalId);
  if (!record) {
    return { reconcile_state: 'unverified', reason: 'not_reconciled' };
  }

  const currentPropHash = calculateSha256(propRaw);
  const currentTargetHash = calculateSha256(targetRaw);

  // 核心双版本失配检测 (B4: 严格纯只读计算，不在查询中回写状态库)
  if (
    currentPropHash !== record.proposal_version_sha256 ||
    currentTargetHash !== record.target_version_sha256
  ) {
    return {
      reconcile_state: 'unverified',
      reason: 'version_changed'
    };
  }

  return {
    reconcile_state: record.reconcile_state,
    reason: record.reason
  };
}

/**
 * 递归扫描 40_Review_Queue 下的提案文件并统一检测重复 UUID 冲突
 * @param {string} vaultDir
 */
export function scanReviewQueueProposals(vaultDir) {
  const queueDir = path.join(vaultDir, '40_Review_Queue');
  const files = findMarkdownFiles(queueDir, {
    excludeTemplates: true,
    followSymlinks: false,
    boundaryDir: vaultDir
  });
  const byId = new Map();
  const malformed = [];

  for (const filePath of files) {
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = parseProposalContent(raw);
      const propId = parsed.frontmatter?.id ? String(parsed.frontmatter.id).trim() : null;
      const key = propId || `__basename__:${path.basename(filePath, '.md')}::${filePath}`;
      const entry = {
        proposalId: propId,
        effectiveId: propId || path.basename(filePath, '.md'),
        path: filePath,
        raw,
        frontmatter: parsed.frontmatter,
        body: parsed.body
      };
      if (!byId.has(key)) byId.set(key, []);
      byId.get(key).push(entry);
    } catch (err) {
      malformed.push({ path: filePath, error: err?.message || String(err) });
    }
  }

  const uniqueById = new Map();
  const conflictsById = new Map();
  const uniqueEntries = [];

  for (const [, list] of byId.entries()) {
    if (list.length > 1 && list[0].proposalId) {
      const propId = list[0].proposalId;
      conflictsById.set(propId, {
        proposal_id: propId,
        paths: list.map(e => e.path),
        entries: list
      });
    } else {
      for (const item of list) {
        uniqueEntries.push(item);
        if (item.proposalId) {
          uniqueById.set(item.proposalId, item);
        }
      }
    }
  }

  return {
    queueDir,
    files,
    uniqueEntries,
    uniqueById,
    conflictsById,
    conflicts: [...conflictsById.values()],
    malformed
  };
}
