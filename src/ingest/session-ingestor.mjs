import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  SANITIZER_VERSION,
  createSessionSanitizer,
  sanitizeOutputText
} from '../security/sanitizer.mjs';
import { assertSensitivityAllowed } from '../security/isolation-sentinel.mjs';
import { stageCandidate, publishFile } from '../storage/atomic-publisher.mjs';
import {
  formatFileName,
  resolveTargetFilePath,
  findMarkdownFiles,
  assertPathWithinBoundary,
  readFrontmatterIdFast
} from '../storage/path-sanitizer.mjs';
import { calculateItemKey, isFactTombstoned } from '../tombstone/tracker.mjs';
import { validateFrontmatter } from '../schema/validator.mjs';
import { formatYamlScalar } from '../schema/frontmatter.mjs';
import { isZstdBuffer, decompressZstdAllFrames } from './zstd-utils.mjs';
import { extractHumanDigestTurnsFromMarkdown, buildHumanDigestSection } from './human-digest.mjs';
import { discoverCodexSessions, normalizeCodexEvent, CODEX_KNOWN_EVENT_TYPES } from './adapters/codex-adapter.mjs';
import {
  discoverAntigravitySessions,
  readAndStabilizeAntigravityCapture,
  buildAntigravityBackfillIndex,
  applyAntigravityBackfill,
  normalizeAntigravityEvent,
  ANTIGRAVITY_KNOWN_EVENT_TYPES
} from './adapters/antigravity-adapter.mjs';
import {
  discoverDshSessions,
  extractDshPathHints,
  normalizeDshEvent,
  isKnownDshEventType
} from './adapters/dsh-adapter.mjs';

export const PARSER_VERSION = 'v2.4.1';
export const DISTILLER_VERSION = 'v2.4.1';
export const SUPPORTED_SOURCE_TOOLS = ['codex', 'antigravity', 'dsh'];

const KNOWN_EVENT_TYPES = new Set([
  ...CODEX_KNOWN_EVENT_TYPES,
  ...ANTIGRAVITY_KNOWN_EVENT_TYPES
]);

/**
 * 根据显式 --project 参数或 manifests/project-map.json 解析项目归属 (§5.1, 第 5 轮审核兼容修复)
 * - 若显式传入非空且非 'auto' 的 project（如 --project Alpha），直接采用显式值，绝不降级为 unmapped
 * - 若未传或传入 'auto'，按 project-map.json 匹配 cwd / gitRoot / workspaceSlug；未知或多重歧义命中统一归入 'unmapped'
 *
 * @param {{
 *   dataDir?: string,
 *   explicitProject?: string | null,
 *   sessionHints?: { cwd?: string, gitRoot?: string, workspaceSlug?: string, sourcePath?: string }
 * }} params
 * @returns {string}
 */
export function resolveProjectFromMap({
  dataDir = null,
  explicitProject = null,
  sessionHints = {}
} = {}) {
  const mapPath = dataDir ? path.join(dataDir, 'manifests', 'project-map.json') : null;
  let rawMap = null;
  if (mapPath && fs.existsSync(mapPath)) {
    try {
      rawMap = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
    } catch {
      rawMap = null;
    }
  }

  const trimmed = typeof explicitProject === 'string' ? explicitProject.trim() : '';
  if (trimmed && trimmed.toLowerCase() !== 'auto') {
    if (rawMap && Array.isArray(rawMap.projects)) {
      const lowerExplicit = trimmed.toLowerCase();
      for (const item of rawMap.projects) {
        if (!item || !item.project) continue;
        if (String(item.project).toLowerCase() === lowerExplicit) {
          return item.project;
        }
        const aliases = Array.isArray(item.aliases) ? item.aliases : [];
        if (aliases.some(a => String(a || '').trim().toLowerCase() === lowerExplicit)) {
          return item.project;
        }
      }
    }
    return trimmed;
  }

  if (!rawMap) {
    return 'unmapped';
  }

  try {
    const fallbackUnmapped = rawMap.default_unmapped_project || 'unmapped';
    const entries = Array.isArray(rawMap.projects) ? rawMap.projects : [];
    const norm = (p) => String(p || '').replace(/\\/g, '/').toLowerCase().replace(/\/+$/, '');

    const candidatePaths = [
      sessionHints.cwd,
      sessionHints.gitRoot,
      sessionHints.sourcePath
    ].filter(Boolean).map(norm);
    const candidateSlug = String(sessionHints.workspaceSlug || '').trim().toLowerCase();

    const matchedProjects = new Set();
    for (const item of entries) {
      if (!item || !item.project) continue;
      const itemPaths = [
        ...(Array.isArray(item.paths) ? item.paths : []),
        ...(Array.isArray(item.git_roots) ? item.git_roots : [])
      ].map(norm).filter(Boolean);
      const itemSlugs = (Array.isArray(item.workspace_slugs) ? item.workspace_slugs : [])
        .map(s => String(s || '').trim().toLowerCase())
        .filter(Boolean);

      let hit = false;
      for (const cp of candidatePaths) {
        if (itemPaths.some(ip => cp === ip || cp.startsWith(ip + '/'))) {
          hit = true;
          break;
        }
      }
      if (!hit && candidateSlug && itemSlugs.includes(candidateSlug)) {
        hit = true;
      }
      if (hit) {
        matchedProjects.add(item.project);
      }
    }

    if (matchedProjects.size === 1) {
      return [...matchedProjects][0];
    }
    return fallbackUnmapped;
  } catch {
    return 'unmapped';
  }
}

import { getConfiguredSourceRoots } from '../config/paths.mjs';
export { getConfiguredSourceRoots };

/**
 * 扫描并发现本地三端会话 (mem list-sessions [--source codex|antigravity|dsh|all|auto])
 * 默认仅返回已完成主会话（按 §5.1 过滤 subagent、空会话与未闭合活跃会话）；传入 includeFiltered: true 可包含已过滤项。
 *
 * @param {{
 *   sourceTool?: 'codex' | 'antigravity' | 'dsh' | 'all' | 'auto',
 *   codexHome?: string,
 *   codexArchivedDir?: string | null,
 *   antigravityBrainDir?: string,
 *   dshHome?: string,
 *   includeFiltered?: boolean
 * }} [options]
 */
export function listDiscoverableSessions(options = {}) {
  const rawFilter = (options.sourceTool || 'all').toLowerCase();
  const filterTool = rawFilter === 'auto' ? 'all' : rawFilter;
  const includeFiltered = Boolean(options.includeFiltered);
  const { codexRoot, codexArchivedRoot, agyRoot, dshRoot } = getConfiguredSourceRoots(options);

  const results = [];

  if (filterTool === 'all' || filterTool === 'codex') {
    results.push(
      ...discoverCodexSessions({
        codexHome: codexRoot,
        codexArchivedDir: codexArchivedRoot,
        includeFiltered
      })
    );
  }
  if (filterTool === 'all' || filterTool === 'antigravity') {
    results.push(
      ...discoverAntigravitySessions({
        antigravityBrainDir: agyRoot,
        includeFiltered
      })
    );
  }
  if (filterTool === 'all' || filterTool === 'dsh') {
    results.push(
      ...discoverDshSessions({
        dshHome: dshRoot,
        includeFiltered
      })
    );
  }

  results.sort((a, b) => (b.updated_at < a.updated_at ? -1 : b.updated_at > a.updated_at ? 1 : 0));
  return results;
}

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /system\s+override/i,
  /bypass\s+(security|policy|approval|rules)/i,
  /忽略(?:以上|之前|所有)?(?:规则|指令)/,
  /(?:执行|运行).{0,12}(?:命令|脚本|shell|powershell|pwsh)/i,
  /(?:读取|输出|外发|发送).{0,16}(?:其他目录|密钥|私钥|raw\/|\.ssh|全部文件)/i,
  /\b(?:execSync|child_process|Invoke-Expression|iex|Get-Content|rm\s+-rf|curl\s+http)\b/i
];

function canonicalizeObject(val) {
  if (val === null || val === undefined) return val;
  if (Array.isArray(val)) return val.map(canonicalizeObject);
  if (typeof val === 'object') {
    const sorted = {};
    for (const key of Object.keys(val).sort()) {
      sorted[key] = canonicalizeObject(val[key]);
    }
    return sorted;
  }
  return val;
}

function computeCanonicalEventHash(parsedEvent, rawLine) {
  if (parsedEvent && typeof parsedEvent === 'object') {
    const canonicalStr = JSON.stringify(canonicalizeObject(parsedEvent));
    return crypto.createHash('sha256').update(canonicalStr, 'utf8').digest('hex');
  }
  return crypto.createHash('sha256').update(`RAW_LINE::${rawLine}`, 'utf8').digest('hex');
}

function splitUtf8BufferLines(buf) {
  let pos = 0;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    pos = 3;
  }
  const endsWithNewline = buf.length > pos && buf[buf.length - 1] === 0x0a;
  const lines = [];

  while (pos < buf.length) {
    const nlIdx = buf.indexOf(0x0a, pos);
    const segEnd = nlIdx === -1 ? buf.length : nlIdx;
    const lineEnd = segEnd > pos && buf[segEnd - 1] === 0x0d ? segEnd - 1 : segEnd;
    const lineSlice = buf.subarray(pos, lineEnd);
    lines.push({
      text: lineSlice.toString('utf8'),
      byteOffset: pos,
      byteLength: lineEnd - pos
    });
    if (nlIdx === -1) break;
    pos = nlIdx + 1;
  }

  return { lines, endsWithNewline };
}

function isPathStrictlyInside(baseDir, candidatePath) {
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(candidatePath);
  const rel = path.relative(resolvedBase, resolvedTarget);
  if (!rel || rel === '') return false;
  if (rel.startsWith('..') || path.isAbsolute(rel)) return false;

  if (fs.existsSync(resolvedTarget)) {
    try {
      const realBase = fs.realpathSync(resolvedBase);
      const realTarget = fs.realpathSync(resolvedTarget);
      const realRel = path.relative(realBase, realTarget);
      if (!realRel || realRel.startsWith('..') || path.isAbsolute(realRel)) {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function detectInjectionText(text) {
  if (!text) return [];
  const hits = [];
  for (const re of INJECTION_PATTERNS) {
    if (re.test(text)) {
      hits.push(re.source);
    }
  }
  return hits;
}

/**
 * 将事件文本转义为只读引用数据，阻止 YAML frontmatter 逃逸或结构注入 (B06)
 */
function renderSafeQuotedBlock(text) {
  const normalized = String(text || '').replace(/\r\n/g, '\n');
  const escapedLines = normalized.split('\n').map((line) => {
    // 阻断内部出现 --- 或 ``` 伪造分隔符逃逸
    const safeLine = line
      .replace(/^---+/g, '\\---')
      .replace(/```/g, '\\`\\`\\`');
    return `> ${safeLine}`;
  });
  return escapedLines.join('\n');
}

function formatEventAnchor(eventId) {
  return `^event-${String(eventId).padStart(6, '0')}`;
}

function generateDeterministicUuidV7Like(seedStr) {
  const hex = crypto.createHash('sha256').update(seedStr, 'utf8').digest('hex');
  return `SES-019316a8-${hex.slice(0, 4)}-7${hex.slice(4, 7)}-8${hex.slice(7, 10)}-${hex.slice(10, 22)}`;
}

/**
 * 读取并校验原始会话快照（稳定性检查 + 解压 + R5 前缀验证 + 脱敏渲染 + 原子发布）
 * @param {{
 *   db: any,
 *   vaultDir: string,
 *   dataDir: string,
 *   sourcePath: string,
 *   sourceTool?: string,
 *   sessionId: string,
 *   project?: string,
 *   title?: string,
 *   privacy?: 'sanitized' | 'local_only',
 *   sensitivity?: 'synthetic' | 'approved_low_sensitivity' | 'confidential',
 *   isolationReport?: object,
 *   sourceAttachmentsDir?: string,
 *   maxEventChars?: number,
 *   parserVersion?: string,
 *   sanitizerVersion?: string,
 *   dryRun?: boolean,
 *   stabilityHook?: (phase: 'before' | 'after') => void
 * }} params
 */
export function ingestSession({
  db,
  vaultDir,
  dataDir,
  sourcePath,
  companionFullPath = null,
  sourceTool = 'codex',
  sessionId,
  project = null,
  title,
  privacy = 'sanitized',
  sensitivity = 'synthetic',
  isolationReport = null,
  sourceAttachmentsDir = null,
  maxEventChars = 2000,
  parserVersion = PARSER_VERSION,
  sanitizerVersion = SANITIZER_VERSION,
  dryRun = false,
  stabilityHook = null
}) {
  if (!db) {
    throw new Error('ingestSession 必须传入已初始化的 state.sqlite 实例');
  }
  if (!sessionId) {
    throw new Error('ingestSession 必须提供 sessionId');
  }
  if (!sourcePath || !fs.existsSync(sourcePath)) {
    throw new Error(`原始会话文件不存在: ${sourcePath}`);
  }

  // R3 B01 门禁检查：未建立强隔离前严禁处理 confidential 原文
  assertSensitivityAllowed({ sensitivity, isolationReport });

  // 1. 稳定性检查（Antigravity 双轨走专用 adapter，其余来源核对读取前后文件状态）
  let rawBytes;
  let companionBytes = null;
  if (sourceTool === 'antigravity') {
    const capture = readAndStabilizeAntigravityCapture({
      sourcePath,
      companionFullPath,
      sessionId,
      stabilityHook
    });
    if (!capture.stable) {
      return {
        status: 'skipped_unstable_file',
        errorCode: capture.errorCode,
        reason: capture.reason,
        sessionId
      };
    }
    rawBytes = capture.rawBytes;
    companionBytes = capture.companionBytes;
  } else {
    if (stabilityHook) stabilityHook('before');
    const statBefore = fs.statSync(sourcePath);
    const compExistsBefore = Boolean(companionFullPath && fs.existsSync(companionFullPath));
    const compStatBefore = compExistsBefore ? fs.statSync(companionFullPath) : null;

    rawBytes = fs.readFileSync(sourcePath);
    companionBytes = compExistsBefore ? fs.readFileSync(companionFullPath) : null;

    if (stabilityHook) stabilityHook('after');
    const statAfter = fs.statSync(sourcePath);
    const compExistsAfter = Boolean(companionFullPath && fs.existsSync(companionFullPath));
    const compStatAfter = compExistsAfter ? fs.statSync(companionFullPath) : null;

    const primaryUnstable = statBefore.size !== statAfter.size || statBefore.mtimeMs !== statAfter.mtimeMs;
    const companionUnstable =
      compExistsBefore !== compExistsAfter ||
      (compStatBefore && compStatAfter && (compStatBefore.size !== compStatAfter.size || compStatBefore.mtimeMs !== compStatAfter.mtimeMs));

    if (primaryUnstable || companionUnstable) {
      return {
        status: 'skipped_unstable_file',
        errorCode: 'ERR_SOURCE_UNSTABLE',
        reason: 'source_file_still_changing',
        sessionId
      };
    }
  }

  const rawSha256 = crypto.createHash('sha256').update(rawBytes).digest('hex');
  const companionFullSha256 = companionBytes
    ? crypto.createHash('sha256').update(companionBytes).digest('hex')
    : null;
  const snapshotId = sourceTool === 'antigravity' && companionFullSha256
    ? `${sourceTool}-${sessionId}-${rawSha256}-${companionFullSha256.slice(0, 16)}`
    : `${sourceTool}-${sessionId}-${rawSha256}`;
  const compressed = isZstdBuffer(rawBytes, sourcePath);
  const nowIso = new Date().toISOString();

  // 若为 Antigravity 且存在稳定伴随文件 transcript_full.jsonl，构建 4 元组 (step_index, type, source, created_at) 索引
  const antigravityFullMap = sourceTool === 'antigravity' && companionBytes
    ? buildAntigravityBackfillIndex(companionBytes, splitUtf8BufferLines)
    : new Map();

  // 2. 解压与损坏检测 (B04：支持 DSH 多帧串联 Zstd 与单帧 Zstd)
  let decompressedBuf;
  if (compressed) {
    try {
      decompressedBuf = decompressZstdAllFrames(rawBytes);
    } catch (err) {
      const anomaly = {
        event_id: 0,
        type: 'corrupt_compressed_snapshot',
        detail: sanitizeOutputText(err.message)
      };
      const coverage = {
        total_events: 0,
        rendered_events: 0,
        omitted_events: 0,
        parse_error_events: 1,
        unknown_events: 0,
        backfilled_truncations: 0,
        unresolved_truncations: 0,
        attachments_count: 0,
        missing_attachments_count: 0
      };
      if (!dryRun) {
        const manifestsDir = path.join(dataDir, 'manifests');
        if (!fs.existsSync(manifestsDir)) fs.mkdirSync(manifestsDir, { recursive: true });
        fs.writeFileSync(
          path.join(manifestsDir, `${snapshotId}.json`),
          JSON.stringify({ snapshot_id: snapshotId, source_tool: sourceTool, session_id: sessionId, status: 'corrupt_snapshot', coverage, anomalies: [anomaly] }, null, 2),
          'utf8'
        );
      }
      return {
        status: 'corrupt_snapshot',
        reason: 'corrupt_compressed_snapshot',
        snapshotId,
        coverage,
        anomalies: [anomaly]
      };
    }
  } else {
    decompressedBuf = rawBytes;
  }

  // 检查末行换行与完整性（按原始 UTF-8 Buffer 精确切分字节偏移，免疫多字节/CRLF/异常编码偏移漂移）
  const { lines: parsedBufferLines, endsWithNewline } = splitUtf8BufferLines(decompressedBuf);

  // 3. 逐行解析事件（1..N 原始编号绝不重排！）
  const sessionSanitizer = createSessionSanitizer();
  const anomalies = [];
  const lineMap = [];
  const prefixHashes = [];
  const renderedBlocks = [];

  const dshPathHints = sourceTool === 'dsh' ? extractDshPathHints(sourcePath) : { workspaceSlug: null };

  let renderedCount = 0;
  let omittedCount = 0;
  let parseErrorCount = 0;
  let unknownEventsCount = 0;
  let attachmentsCount = 0;
  let missingAttachmentsCount = 0;
  let backfilledTruncationsCount = 0;
  let unresolvedTruncationsCount = 0;
  let injectionSignalsCount = 0;
  let firstDiscoveredCwd = null;
  let firstDiscoveredGitRoot = null;
  let firstDiscoveredSlug = dshPathHints.workspaceSlug || null;

  for (let idx = 0; idx < parsedBufferLines.length; idx++) {
    const eventId = idx + 1;
    const anchor = formatEventAnchor(eventId);
    const { text: lineText, byteOffset, byteLength: lineByteLen } = parsedBufferLines[idx];

    if (lineText.trim() === '') {
      // 保留编号但不作为内容崩溃
      const emptyHash = computeCanonicalEventHash(null, '');
      prefixHashes.push(emptyHash);
      lineMap.push({
        event_id: eventId,
        anchor,
        byte_offset: byteOffset,
        byte_length: lineByteLen,
        type: 'blank',
        status: 'omitted',
        canonical_hash: emptyHash
      });
      omittedCount++;
      renderedBlocks.push(`### 事件 #${eventId} (空行)\n> [空事件行]\n${anchor}`);
      continue;
    }

    let parsedEvent = null;
    try {
      parsedEvent = JSON.parse(lineText);
    } catch {
      parseErrorCount++;
      const isLastIncomplete = idx === parsedBufferLines.length - 1 && !endsWithNewline;
      anomalies.push({
        event_id: eventId,
        type: isLastIncomplete ? 'truncated_tail_line' : 'parse_error',
        detail: isLastIncomplete ? '末行未完整闭合 JSON' : 'JSON 解析失败'
      });
      const errHash = computeCanonicalEventHash(null, lineText);
      prefixHashes.push(errHash);
      lineMap.push({
        event_id: eventId,
        anchor,
        byte_offset: byteOffset,
        byte_length: lineByteLen,
        type: 'parse_error',
        status: 'parse_error',
        canonical_hash: errHash
      });
      renderedBlocks.push(`### 事件 #${eventId} (解析异常)\n> [无法解析的事件行 #${eventId}，已保留原始编号]\n${anchor}`);
      continue;
    }

    if (parsedEvent && typeof parsedEvent === 'object') {
      if (!firstDiscoveredCwd && typeof parsedEvent.cwd === 'string') firstDiscoveredCwd = parsedEvent.cwd;
      if (!firstDiscoveredGitRoot && typeof parsedEvent.git_root === 'string') firstDiscoveredGitRoot = parsedEvent.git_root;
      if (!firstDiscoveredSlug && typeof parsedEvent.workspace_slug === 'string') firstDiscoveredSlug = parsedEvent.workspace_slug;
    }

    // Antigravity 情况 2：存在 truncated_fields 时按 (step_index, type, source, created_at) 4 元组精确合并伴随完整字段
    let truncationUnresolved = false;
    let eventProvenance = {
      source_tool: sourceTool,
      source_role: 'primary',
      primary_line: eventId
    };
    if (sourceTool === 'antigravity') {
      const bfRes = applyAntigravityBackfill(parsedEvent, eventId, antigravityFullMap, Boolean(companionBytes));
      eventProvenance = bfRes.provenance;
      if (bfRes.backfilled) {
        backfilledTruncationsCount++;
      }
      if (bfRes.truncationUnresolved) {
        truncationUnresolved = true;
        unresolvedTruncationsCount++;
        anomalies.push({
          event_id: eventId,
          type: 'truncation_unresolved',
          detail: bfRes.reasonDetail
        });
      }
    }

    const canonicalHash = computeCanonicalEventHash(parsedEvent, lineText);
    prefixHashes.push(canonicalHash);

    // 通过对应端适配器规范化事件字段、已知事件类型与 provenance
    let normalizedEvent;
    if (sourceTool === 'codex') {
      normalizedEvent = normalizeCodexEvent(parsedEvent, eventId);
      eventProvenance = normalizedEvent.provenance;
    } else if (sourceTool === 'antigravity') {
      normalizedEvent = normalizeAntigravityEvent(parsedEvent, eventProvenance);
    } else if (sourceTool === 'dsh') {
      normalizedEvent = normalizeDshEvent(parsedEvent, eventId, firstDiscoveredSlug);
      eventProvenance = normalizedEvent.provenance;
    } else {
      const rawType = parsedEvent.type || 'unknown';
      normalizedEvent = {
        type: rawType,
        isKnownType: KNOWN_EVENT_TYPES.has(rawType) || isKnownDshEventType(rawType),
        role: parsedEvent.role || null,
        timestamp: parsedEvent.timestamp || parsedEvent.created_at || null,
        content:
          parsedEvent.content ??
          parsedEvent.text ??
          parsedEvent.output ??
          parsedEvent.command ??
          JSON.stringify(parsedEvent),
        cwd: typeof parsedEvent.cwd === 'string' ? parsedEvent.cwd : null,
        gitRoot: typeof parsedEvent.git_root === 'string' ? parsedEvent.git_root : null
      };
    }

    if (!firstDiscoveredCwd && normalizedEvent.cwd) firstDiscoveredCwd = normalizedEvent.cwd;
    if (!firstDiscoveredGitRoot && normalizedEvent.gitRoot) firstDiscoveredGitRoot = normalizedEvent.gitRoot;

    const evType = normalizedEvent.type || 'unknown';
    let status = 'rendered';
    if (!normalizedEvent.isKnownType) {
      unknownEventsCount++;
      status = 'unknown_event';
      anomalies.push({
        event_id: eventId,
        type: 'unknown_event',
        eventType: evType
      });
    }

    // 检查附件引用并严格阻断路径穿越越权读取 (B04 / B06)
    const attRefs = [];
    if (typeof parsedEvent.attachment === 'string') attRefs.push(parsedEvent.attachment);
    if (Array.isArray(parsedEvent.attachments)) {
      for (const a of parsedEvent.attachments) {
        if (typeof a === 'string') attRefs.push(a);
        else if (a && typeof a.path === 'string') attRefs.push(a.path);
      }
    }
    const allowedAttachmentRoots = [
      ...(sourceAttachmentsDir ? [sourceAttachmentsDir] : []),
      path.join(dataDir, 'attachments'),
      path.dirname(sourcePath)
    ];
    for (const ref of attRefs) {
      if (!ref || String(ref).includes('\0')) {
        missingAttachmentsCount++;
        anomalies.push({ event_id: eventId, type: 'blocked_attachment_traversal', ref: '[INVALID_REF]' });
        continue;
      }

      let existingAtt = null;
      let traversalBlocked = false;
      for (const rootDir of allowedAttachmentRoots) {
        if (!fs.existsSync(rootDir)) continue;
        const resolvedCandidate = path.resolve(rootDir, ref);
        if (!isPathStrictlyInside(rootDir, resolvedCandidate)) {
          traversalBlocked = true;
          continue;
        }
        if (fs.existsSync(resolvedCandidate) && fs.statSync(resolvedCandidate).isFile()) {
          existingAtt = resolvedCandidate;
          break;
        }
      }

      if (existingAtt) {
        attachmentsCount++;
        if (!dryRun) {
          const destAttDir = path.join(dataDir, 'attachments');
          if (!fs.existsSync(destAttDir)) fs.mkdirSync(destAttDir, { recursive: true });
          const safeBase = path.basename(ref);
          const destAttPath = path.join(destAttDir, safeBase);
          if (!fs.existsSync(destAttPath)) {
            fs.copyFileSync(existingAtt, destAttPath);
          }
        }
      } else {
        missingAttachmentsCount++;
        anomalies.push({
          event_id: eventId,
          type: traversalBlocked && (path.isAbsolute(ref) || String(ref).includes('..'))
            ? 'blocked_attachment_traversal'
            : 'missing_attachment',
          ref: path.basename(ref)
        });
      }
    }

    // 提取并脱敏文本内容
    const rawBody = normalizedEvent.content;

    const injectionHits = detectInjectionText(String(rawBody));
    if (injectionHits.length > 0) {
      injectionSignalsCount++;
    }

    let displayText = sanitizeOutputText(String(rawBody), {
      sanitizer: sessionSanitizer,
      scrubRawPaths: true
    });
    let wasTruncated = false;
    if (displayText.length > maxEventChars) {
      displayText = displayText.slice(0, maxEventChars) + `\n... [已省略 ${displayText.length - maxEventChars} 字符，原始编号保持不变]`;
      omittedCount++;
      wasTruncated = true;
    } else {
      renderedCount++;
    }

    lineMap.push({
      event_id: eventId,
      anchor,
      byte_offset: byteOffset,
      byte_length: lineByteLen,
      type: evType,
      status: wasTruncated ? 'omitted' : status,
      canonical_hash: canonicalHash,
      truncation_unresolved: truncationUnresolved,
      injection_flagged: injectionHits.length > 0,
      provenance: eventProvenance
    });

    const roleTag = normalizedEvent.role ? ` (${normalizedEvent.role})` : '';
    const inertBadge = injectionHits.length > 0 ? ' [UNTRUSTED_TEXT_INERT]' : '';
    const unresolvedBadge = truncationUnresolved ? ' [TRUNCATION_UNRESOLVED]' : '';
    renderedBlocks.push(
      `### 事件 #${eventId} · ${evType}${roleTag}${inertBadge}${unresolvedBadge}\n` +
      `${renderSafeQuotedBlock(displayText)}\n` +
      `${anchor}`
    );
  }

  const effectiveProject = resolveProjectFromMap({
    dataDir,
    explicitProject: project,
    sessionHints: {
      cwd: firstDiscoveredCwd,
      gitRoot: firstDiscoveredGitRoot,
      workspaceSlug: firstDiscoveredSlug,
      sourcePath
    }
  });

  const coverage = {
    total_events: parsedBufferLines.length,
    rendered_events: renderedCount,
    omitted_events: omittedCount,
    parse_error_events: parseErrorCount,
    unknown_events: unknownEventsCount,
    backfilled_truncations: backfilledTruncationsCount,
    unresolved_truncations: unresolvedTruncationsCount,
    attachments_count: attachmentsCount,
    missing_attachments_count: missingAttachmentsCount
  };

  // 4. 同快照幂等 & 版本升级隔离 & R5 前缀校验 (B03)
  const existingExact = db
    .prepare('SELECT * FROM session_snapshots WHERE snapshot_id = ?')
    .get(snapshotId);

  if (existingExact) {
    if (existingExact.status === 'needs_reaudit') {
      return {
        status: 'needs_reaudit',
        reason: existingExact.reason,
        snapshotId,
        sessionId,
        incrementalRange: null,
        coverage,
        anomalies
      };
    }

    const sameParser = existingExact.parser_version === parserVersion;
    const sameSanitizer = existingExact.sanitizer_version === sanitizerVersion;
    if (sameParser && sameSanitizer) {
      return {
        status: 'idempotent_skip',
        snapshotId,
        sessionId,
        incrementalRange: null,
        readableSessionPath: existingExact.readable_session_path,
        coverage,
        anomalies
      };
    }
    if (dryRun) {
      return {
        status: 'dry_run_rebuild_derived_session',
        snapshotId,
        sessionId,
        incrementalRange: null,
        derivedOnly: true,
        coverage,
        anomalies,
        injectionSignalsCount
      };
    }
    // 解析器或脱敏器版本升级：仅重建派生可读会话，绝不静默改写既有证据卡与知识笔记 (§5.1)
    const rebuiltUuid = generateDeterministicUuidV7Like(`${snapshotId}::${parserVersion}::${sanitizerVersion}`);
    const rebuiltContent = buildReadableSessionMarkdown({
      id: rebuiltUuid,
      snapshotId,
      sourceTool,
      sessionId,
      project: effectiveProject,
      workspaceSlug: firstDiscoveredSlug,
      title: title || `会话 ${sessionId}`,
      privacy,
      coverage,
      anomalies,
      renderedBlocks,
      parserVersion,
      sanitizerVersion,
      createdAt: nowIso
    });
    const stagingDir = path.join(dataDir, 'staging');
    const sessionsDir = path.join(vaultDir, '10_Readable_Sessions');
    const resolved = resolveTargetFilePath({
      targetDir: sessionsDir,
      prefix: 'SES',
      dateStr: nowIso.slice(0, 10).replace(/-/g, ''),
      sourceTool,
      uuid: rebuiltUuid,
      title: title || `会话_${sessionId}_${parserVersion}`
    });
    const staged = stageCandidate({ stagingDir, outputUuid: rebuiltUuid, content: rebuiltContent });
    const rebuildOperationId = `rebuild-${snapshotId.slice(0, 24)}-${Date.now()}`;
    const pub = publishFile({
      db,
      operationId: rebuildOperationId,
      outputUuid: rebuiltUuid,
      stagingPath: staged.stagingPath,
      vaultTargetPath: resolved.targetPath,
      contentSha256: staged.contentSha256,
      revisionsDir: path.join(dataDir, 'runtime', 'revisions'),
      metadata: {
        note_type: 'session',
        source_tool: sourceTool,
        title: title || `会话 ${sessionId}`,
        project: effectiveProject,
        privacy,
        created_at: nowIso
      }
    });

    db.prepare(`
      UPDATE session_snapshots
      SET parser_version = ?, sanitizer_version = ?, readable_session_path = ?, updated_at = ?
      WHERE snapshot_id = ?
    `).run(parserVersion, sanitizerVersion, pub.vaultTargetPath, nowIso, snapshotId);

    return {
      status: 'rebuilt_derived_session',
      operationId: rebuildOperationId,
      contentSha256: staged.contentSha256,
      snapshotId,
      sessionId,
      incrementalRange: null,
      readableSessionPath: pub.vaultTargetPath,
      derivedOnly: true,
      coverage,
      anomalies
    };
  }

  // 检查同一 (source_tool, session_id) 的最近已知前缀快照
  const prevSnapshots = db
    .prepare(`
      SELECT * FROM session_snapshots
      WHERE source_tool = ? AND session_id = ? AND status != 'corrupt_snapshot'
      ORDER BY created_at DESC, rowid DESC
    `)
    .all(sourceTool, sessionId);

  let previousSnapshotId = null;
  let incrementalRange = { start: 1, end: parsedBufferLines.length };

  if (prevSnapshots.length > 0) {
    // 选择最近一次非 needs_reaudit 的基线快照（若全部为 needs_reaudit，则与最早/最新基线比对）
    const baseline = prevSnapshots.find(s => s.status === 'ingested') || prevSnapshots[0];
    previousSnapshotId = baseline.snapshot_id;
    const prevHashes = JSON.parse(baseline.prefix_hashes_json || '[]');
    const K = prevHashes.length;
    const N = prefixHashes.length;

    if (N < K) {
      // 快照截断：严禁猜测增量，标为 needs_reaudit
      if (!dryRun) {
        recordSnapshotRow(db, {
          snapshotId,
          sourceTool,
          sessionId,
          rawSha256,
          rawPath: '[PROTECTED_RAW]',
          compressed: compressed ? 1 : 0,
          eventCount: N,
          prefixHashesJson: JSON.stringify(prefixHashes),
          parserVersion,
          sanitizerVersion,
          status: 'needs_reaudit',
          reason: 'snapshot_truncated',
          anomaliesJson: JSON.stringify(anomalies),
          readableSessionPath: null,
          nowIso
        });
      }
      return {
        status: 'needs_reaudit',
        reason: 'snapshot_truncated',
        previousSnapshotId,
        previousEventCount: K,
        currentEventCount: N,
        snapshotId,
        sessionId,
        incrementalRange: null,
        coverage,
        anomalies
      };
    }

    // 逐条核对 1..K 前缀哈希
    for (let i = 0; i < K; i++) {
      if (prefixHashes[i] !== prevHashes[i]) {
        const mismatchEventId = i + 1;
        if (!dryRun) {
          recordSnapshotRow(db, {
            snapshotId,
            sourceTool,
            sessionId,
            rawSha256,
            rawPath: '[PROTECTED_RAW]',
            compressed: compressed ? 1 : 0,
            eventCount: N,
            prefixHashesJson: JSON.stringify(prefixHashes),
            parserVersion,
            sanitizerVersion,
            status: 'needs_reaudit',
            reason: `prefix_hash_mismatch_at_event_${mismatchEventId}`,
            anomaliesJson: JSON.stringify(anomalies),
            readableSessionPath: null,
            nowIso
          });
        }
        return {
          status: 'needs_reaudit',
          reason: 'prefix_hash_mismatch',
          mismatchEventId,
          previousSnapshotId,
          snapshotId,
          sessionId,
          incrementalRange: null,
          coverage,
          anomalies
        };
      }
    }

    // 1..K 100% 一致：仅对 K+1..N 做增量提炼
    incrementalRange = N > K ? { start: K + 1, end: N } : null;
  }

  // 5. Dry-run 返回，不写磁盘与台账
  if (dryRun) {
    return {
      status: 'dry_run_ok',
      sourceTool,
      snapshotId,
      sessionId,
      project: effectiveProject,
      ...(firstDiscoveredSlug ? { workspaceSlug: firstDiscoveredSlug } : {}),
      previousSnapshotId,
      incrementalRange,
      coverage,
      anomalies,
      injectionSignalsCount
    };
  }

  // 6. 归档不可变 raw/<source_tool>/ 副本 + 写入 manifests/ + 原子发布 10_Readable_Sessions/
  const rawToolSubdir = String(sourceTool || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
  const rawDir = path.join(dataDir, 'raw');
  const rawToolDir = path.join(rawDir, rawToolSubdir);
  const manifestsDir = path.join(dataDir, 'manifests');
  const stagingDir = path.join(dataDir, 'staging');
  const sessionsDir = path.join(vaultDir, '10_Readable_Sessions');

  for (const d of [rawDir, rawToolDir, manifestsDir, stagingDir, sessionsDir]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }

  const rawExt = compressed
    ? (String(sourcePath).toLowerCase().endsWith('.zstd') ? '.jsonl.zstd' : '.jsonl.zst')
    : '.jsonl';
  const archivedRawFile = path.join(
    rawToolDir,
    `${sourceTool}-${sessionId}-${rawSha256.slice(0, 16)}${rawExt}`
  );
  if (!fs.existsSync(archivedRawFile)) {
    fs.writeFileSync(archivedRawFile, rawBytes);
  }

  let archivedCompanionFile = null;
  if (companionBytes && companionFullSha256) {
    archivedCompanionFile = path.join(
      rawToolDir,
      `${sourceTool}-${sessionId}-${companionFullSha256.slice(0, 16)}-full.jsonl`
    );
    if (!fs.existsSync(archivedCompanionFile)) {
      fs.writeFileSync(archivedCompanionFile, companionBytes);
    }
  }

  const manifestPath = path.join(manifestsDir, `${snapshotId}.json`);
  const manifestObj = {
    snapshot_id: snapshotId,
    source_tool: sourceTool,
    session_id: sessionId,
    project: effectiveProject,
    ...(firstDiscoveredSlug ? { workspace_slug: firstDiscoveredSlug } : {}),
    previous_snapshot_id: previousSnapshotId,
    raw_sha256: rawSha256,
    raw_archive_file: path.posix.join(rawToolSubdir, path.basename(archivedRawFile)),
    companion_full_sha256: companionFullSha256,
    companion_full_archive_file: archivedCompanionFile
      ? path.posix.join(rawToolSubdir, path.basename(archivedCompanionFile))
      : null,
    compressed,
    parser_version: parserVersion,
    sanitizer_version: sanitizerVersion,
    coverage,
    anomalies,
    injection_signals_count: injectionSignalsCount,
    decompressed_line_map: lineMap,
    created_at: nowIso
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifestObj, null, 2), 'utf8');

  const sessionUuid = generateDeterministicUuidV7Like(snapshotId);
  const sessionTitle = title || `会话 ${sessionId}`;
  const sessionContent = buildReadableSessionMarkdown({
    id: sessionUuid,
    snapshotId,
    sourceTool,
    sessionId,
    project: effectiveProject,
    workspaceSlug: firstDiscoveredSlug,
    title: sessionTitle,
    privacy,
    coverage,
    anomalies,
    renderedBlocks,
    parserVersion,
    sanitizerVersion,
    createdAt: nowIso
  });

  const targetResolved = resolveTargetFilePath({
    targetDir: sessionsDir,
    prefix: 'SES',
    dateStr: nowIso.slice(0, 10).replace(/-/g, ''),
    sourceTool,
    uuid: sessionUuid,
    title: sessionTitle
  });

  const staged = stageCandidate({
    stagingDir,
    outputUuid: sessionUuid,
    content: sessionContent
  });

  const ingestOperationId = `ingest-${snapshotId.slice(0, 24)}-${Date.now()}`;
  const pubResult = publishFile({
    db,
    operationId: ingestOperationId,
    outputUuid: sessionUuid,
    stagingPath: staged.stagingPath,
    vaultTargetPath: targetResolved.targetPath,
    contentSha256: staged.contentSha256,
    revisionsDir: path.join(dataDir, 'runtime', 'revisions'),
    metadata: {
      note_type: 'session',
      source_tool: sourceTool,
      title: sessionTitle,
      project: effectiveProject,
      privacy,
      created_at: nowIso
    }
  });

  // 7. 登记 snapshot_lineage 与 session_snapshots
  db.prepare(`
    INSERT INTO snapshot_lineage (snapshot_id, source_tool, session_id, previous_snapshot_id, created_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(snapshot_id) DO NOTHING
  `).run(snapshotId, sourceTool, sessionId, previousSnapshotId, nowIso);

  recordSnapshotRow(db, {
    snapshotId,
    sourceTool,
    sessionId,
    rawSha256,
    rawPath: archivedRawFile,
    compressed: compressed ? 1 : 0,
    eventCount: parsedBufferLines.length,
    prefixHashesJson: JSON.stringify(prefixHashes),
    parserVersion,
    sanitizerVersion,
    status: 'ingested',
    reason: null,
    anomaliesJson: JSON.stringify(anomalies),
    readableSessionPath: pubResult.vaultTargetPath,
    nowIso
  });

  return {
    status: 'ingested',
    operationId: ingestOperationId,
    contentSha256: staged.contentSha256,
    snapshotId,
    sessionId,
    project: effectiveProject,
    previousSnapshotId,
    incrementalRange,
    readableSessionPath: pubResult.vaultTargetPath,
    manifestPath,
    coverage,
    anomalies,
    injectionSignalsCount,
    redactionStats: sessionSanitizer.getStats()
  };
}

function recordSnapshotRow(db, row) {
  db.prepare(`
    INSERT INTO session_snapshots (
      snapshot_id, source_tool, session_id, raw_sha256, raw_path, compressed,
      event_count, prefix_hashes_json, parser_version, sanitizer_version,
      status, reason, anomalies_json, readable_session_path, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(snapshot_id) DO UPDATE SET
      parser_version = excluded.parser_version,
      sanitizer_version = excluded.sanitizer_version,
      status = excluded.status,
      reason = excluded.reason,
      anomalies_json = excluded.anomalies_json,
      readable_session_path = COALESCE(excluded.readable_session_path, session_snapshots.readable_session_path),
      updated_at = excluded.updated_at
  `).run(
    row.snapshotId,
    row.sourceTool,
    row.sessionId,
    row.rawSha256,
    row.rawPath,
    row.compressed,
    row.eventCount,
    row.prefixHashesJson,
    row.parserVersion,
    row.sanitizerVersion,
    row.status,
    row.reason,
    row.anomaliesJson,
    row.readableSessionPath,
    row.nowIso,
    row.nowIso
  );
}

function buildReadableSessionMarkdown({
  id,
  snapshotId,
  sourceTool,
  sessionId,
  project,
  workspaceSlug = null,
  title,
  privacy,
  coverage,
  anomalies,
  renderedBlocks,
  parserVersion,
  sanitizerVersion,
  createdAt
}) {
  const effectiveId = id || generateDeterministicUuidV7Like(snapshotId);
  const safeTitle = String(title || '').replace(/[\r\n]+/g, ' ').trim();
  const safeProject = String(project || '').replace(/[\r\n]+/g, ' ').trim();
  const fmCheck = validateFrontmatter({
    schema_version: 1,
    id: effectiveId,
    note_type: 'session',
    title: safeTitle,
    project: safeProject,
    privacy,
    source_tool: sourceTool,
    session_id: sessionId,
    snapshot_id: snapshotId,
    coverage,
    created_at: createdAt
  });
  if (!fmCheck.valid) {
    throw new Error(`生成的会话 Frontmatter 校验失败: ${fmCheck.errors.join('; ')}`);
  }

  const anomalyLines = anomalies.length > 0
    ? anomalies.map(a => {
        const detail = sanitizeOutputText(String(a.detail || a.eventType || a.ref || '').replace(/[\r\n]+/g, ' '));
        return `- [异常] 事件 #${a.event_id} (${a.type}): ${detail}`;
      }).join('\n')
    : '- 无覆盖或解析异常';

  const workspaceSlugLine = workspaceSlug ? `workspace_slug: ${formatYamlScalar(workspaceSlug)}\n` : '';
  const backfilledCount = coverage.backfilled_truncations ?? 0;
  const unresolvedCount = coverage.unresolved_truncations ?? 0;

  const eventsSection = renderedBlocks.join('\n\n');
  const digestTurns = extractHumanDigestTurnsFromMarkdown(
    `---\nid: "tmp"\n---\n\n## 会话事件记录\n\n${eventsSection}\n`
  );
  const digestSection = buildHumanDigestSection(digestTurns);

  return `---
schema_version: 1
id: ${formatYamlScalar(effectiveId)}
note_type: "session"
title: ${formatYamlScalar(safeTitle)}
project: ${formatYamlScalar(safeProject)}
privacy: ${formatYamlScalar(privacy)}
source_tool: ${formatYamlScalar(sourceTool)}
session_id: ${formatYamlScalar(sessionId)}
snapshot_id: ${formatYamlScalar(snapshotId)}
${workspaceSlugLine}parser_version: ${formatYamlScalar(parserVersion)}
sanitizer_version: ${formatYamlScalar(sanitizerVersion)}
coverage:
  total_events: ${coverage.total_events}
  rendered_events: ${coverage.rendered_events}
  omitted_events: ${coverage.omitted_events}
  parse_error_events: ${coverage.parse_error_events}
  unknown_events: ${coverage.unknown_events}
  backfilled_truncations: ${backfilledCount}
  unresolved_truncations: ${unresolvedCount}
  attachments_count: ${coverage.attachments_count}
  missing_attachments_count: ${coverage.missing_attachments_count}
created_at: ${formatYamlScalar(createdAt)}
---

# ${safeTitle}

## 会话覆盖清单
- 快照 ID: \`${snapshotId}\`
- 解析器 / 脱敏器版本: \`${parserVersion}\` / \`${sanitizerVersion}\`
- 事件总数: ${coverage.total_events} | 已渲染: ${coverage.rendered_events} | 已省略: ${coverage.omitted_events} | 解析失败: ${coverage.parse_error_events} | 未知事件: ${coverage.unknown_events} | 已验证回填: ${backfilledCount} | 未消解截断: ${unresolvedCount} | 附件: ${coverage.attachments_count} | 缺失附件: ${coverage.missing_attachments_count}

### 覆盖与异常明细
${anomalyLines}

${digestSection}
## 会话事件记录

${eventsSection}
`;
}

/**
 * 确定性候选提炼与跨快照墓碑抑制 (B03 & B06)
 * - 严格在允许区间 (K+1..N 或显式重审) 内执行
 * - 不得把 transcript 内容当指令执行；仅包装为不可信引用资料
 * - 计算跨快照稳定 item_key（绝不含 snapshot_id），并过滤 tombstones 表已删除事实
 *
 * @param {{
 *   db: any,
 *   snapshotId: string,
 *   facts: Array<{ eventId: number, factType: string, normalizedSubject: string, title: string, summary: string }>,
 *   range?: { start: number, end: number } | null,
 *   distillerVersion?: string,
 *   explicitReaudit?: boolean
 * }} params
 */
export function distillSnapshotFacts({
  db,
  snapshotId,
  facts = [],
  range = null,
  distillerVersion = DISTILLER_VERSION,
  explicitReaudit = false
}) {
  const snap = db.prepare('SELECT * FROM session_snapshots WHERE snapshot_id = ?').get(snapshotId);
  if (!snap) {
    throw new Error(`未找到快照台账记录: ${snapshotId}`);
  }
  if (snap.status === 'needs_reaudit' && !explicitReaudit) {
    return {
      status: 'blocked_needs_reaudit',
      reason: snap.reason,
      acceptedFacts: [],
      suppressedFacts: [],
      skippedOutOfRange: []
    };
  }

  // 版本隔离检查：若 distillerVersion 升级且未显式发起重审作业，禁止静默改写既有卡片
  const prevRun = db
    .prepare('SELECT * FROM distillation_runs WHERE session_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1')
    .get(snap.session_id);
  if (prevRun && prevRun.distiller_version !== distillerVersion && !explicitReaudit) {
    return {
      status: 'reaudit_required_version_upgrade',
      previousDistillerVersion: prevRun.distiller_version,
      requestedDistillerVersion: distillerVersion,
      acceptedFacts: [],
      suppressedFacts: [],
      skippedOutOfRange: []
    };
  }

  let effectiveRange = range;
  if (!effectiveRange && !explicitReaudit && prevRun && prevRun.snapshot_id !== snapshotId && snap.status === 'ingested') {
    const startEvt = Math.max(1, Number(prevRun.processed_through_event || 0) + 1);
    effectiveRange = { start: startEvt, end: snap.event_count };
  }

  const acceptedFacts = [];
  const suppressedFacts = [];
  const skippedOutOfRange = [];

  for (const fact of facts) {
    if (effectiveRange && (fact.eventId < effectiveRange.start || fact.eventId > effectiveRange.end)) {
      skippedOutOfRange.push({ eventId: fact.eventId, title: fact.title });
      continue;
    }

    const anchor = formatEventAnchor(fact.eventId);
    // ADR-004 / D2: item_key 绝不包含 snapshot_id
    const itemKey = calculateItemKey({
      sourceTool: snap.source_tool,
      sessionId: snap.session_id,
      canonicalEventAnchor: anchor,
      factType: fact.factType || 'fact',
      normalizedSubject: fact.normalizedSubject || fact.title
    });

    if (isFactTombstoned({ db, itemKey })) {
      suppressedFacts.push({
        itemKey,
        eventId: fact.eventId,
        anchor,
        title: fact.title,
        reason: 'suppressed_by_tombstone'
      });
      continue;
    }

    // B06 防注入：所有来源引文仅包装为不可信引用块，绝不执行
    const safeQuotedEvidence = `<untrusted_session_transcript_data anchor="${anchor}">\n${sanitizeOutputText(fact.summary || '')}\n</untrusted_session_transcript_data>`;

    acceptedFacts.push({
      itemKey,
      eventId: fact.eventId,
      anchor,
      factType: fact.factType || 'fact',
      normalizedSubject: fact.normalizedSubject || fact.title,
      title: sanitizeOutputText(fact.title),
      quotedEvidence: safeQuotedEvidence
    });
  }

  const nowIso = new Date().toISOString();
  const runId = `DR-${crypto.randomBytes(6).toString('hex')}`;
  db.prepare(`
    INSERT INTO distillation_runs (
      run_id, snapshot_id, session_id, parser_version, sanitizer_version,
      distiller_version, processed_through_event, mode, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
  `).run(
    runId,
    snapshotId,
    snap.session_id,
    snap.parser_version,
    snap.sanitizer_version,
    distillerVersion,
    effectiveRange ? effectiveRange.end : snap.event_count,
    explicitReaudit ? 'reaudit' : (effectiveRange && effectiveRange.start > 1 ? 'incremental' : 'initial'),
    nowIso
  );

  return {
    status: 'completed',
    runId,
    acceptedFacts,
    suppressedFacts,
    skippedOutOfRange
  };
}

/**
 * 证据卡 #^event-NNNNNN 跨压缩快照精确定位器 (B04)
 * 解析如 `[[10_Readable_Sessions/SES-...#^event-000005]]` 或带别名的 `[[...#^event-000005|别名]]` 并定位到解压流中对应原始行
 *
 * @param {{
 *   vaultDir: string,
 *   dataDir: string,
 *   sourceLink: string
 * }} params
 */
export function locateSnapshotEvent({ vaultDir, dataDir, sourceLink }) {
  const cleaned = String(sourceLink || '').replace(/^\[\[/, '').replace(/\]\]$/, '').trim();
  const withoutAlias = cleaned.split('|')[0].trim();
  const hashIdx = withoutAlias.indexOf('#');
  if (hashIdx === -1) {
    throw new Error(`来源链接缺少锚点 (#^event-NNNNNN): ${sourceLink}`);
  }

  const noteRef = withoutAlias.slice(0, hashIdx).trim();
  const anchor = withoutAlias.slice(hashIdx + 1).trim();
  const anchorMatch = anchor.match(/^\^event-(\d+)$/);
  if (!anchorMatch) {
    throw new Error(`锚点格式非法 (应为 ^event-NNNNNN): ${anchor}`);
  }
  const eventId = parseInt(anchorMatch[1], 10);

  // 在 10_Readable_Sessions 内按明确相对路径 > UUID > 唯一裸文件名优先级受控查找目标可读会话文件
  const sessionsDir = path.join(vaultDir, '10_Readable_Sessions');
  const rawRef = String(noteRef || '').trim();
  if (!rawRef) {
    throw new Error('来源链接缺少目标会话引用');
  }
  if (path.isAbsolute(rawRef) || /^[a-zA-Z]:/.test(rawRef) || rawRef.startsWith('/') || rawRef.startsWith('\\')) {
    throw new Error(`ERR_SESSION_PATH_OUTSIDE_SCOPE: 禁止使用绝对路径定位会话 (${path.basename(rawRef)})`);
  }

  const normRef = rawRef.replace(/\\/g, '/').replace(/^\.\//, '');
  const refSegments = normRef.split('/');
  if (refSegments.some(seg => !seg || seg === '..' || seg === '.')) {
    throw new Error('ERR_SESSION_PATH_OUTSIDE_SCOPE: 会话引用包含非法路径片段');
  }
  const blockedScopes = new Set(['20_Evidence_Cards', '30_Knowledge_Notes', '40_Review_Queue', '50_Bases_Views', '90_Templates', '.git', '.obsidian']);
  if (blockedScopes.has(refSegments[0]) || refSegments.includes('90_Templates')) {
    throw new Error('ERR_SESSION_PATH_OUTSIDE_SCOPE: locateSnapshotEvent 仅限受控定位 10_Readable_Sessions 会话锚点');
  }

  if (!fs.existsSync(sessionsDir)) {
    throw new Error('未找到可读会话目录: 10_Readable_Sessions');
  }
  assertPathWithinBoundary(sessionsDir, vaultDir, { followSymlinks: false });

  const allSessionFiles = findMarkdownFiles(sessionsDir, {
    excludeTemplates: true,
    followSymlinks: false,
    boundaryDir: vaultDir
  });
  const filesByUuid = new Map();
  for (const fp of allSessionFiles) {
    const fmId = readFrontmatterIdFast(fp);
    if (fmId) {
      if (!filesByUuid.has(fmId)) filesByUuid.set(fmId, []);
      filesByUuid.get(fmId).push(fp);
    }
  }

  const hasExplicitPrefix = normRef.startsWith('10_Readable_Sessions/');
  const relWithinSessions = hasExplicitPrefix ? normRef.slice('10_Readable_Sessions/'.length) : normRef;
  const isExplicitRelativePath = hasExplicitPrefix || normRef.includes('/');
  const isExplicitUuid = !isExplicitRelativePath && /^SES-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/i.test(normRef);

  let sessionFilePath = null;
  if (isExplicitRelativePath) {
    if (!relWithinSessions) {
      throw new Error('ERR_SESSION_PATH_OUTSIDE_SCOPE: 明确会话相对路径不能为空');
    }
    const relWithExt = relWithinSessions.toLowerCase().endsWith('.md') ? relWithinSessions : `${relWithinSessions}.md`;
    const candidatePath = path.resolve(sessionsDir, relWithExt);
    assertPathWithinBoundary(candidatePath, sessionsDir, { followSymlinks: false });
    if (!fs.existsSync(candidatePath) || !fs.lstatSync(candidatePath).isFile()) {
      throw new Error(`未找到对应的可读会话文件: ${relWithExt}`);
    }
    const fmId = readFrontmatterIdFast(candidatePath);
    if (fmId && (filesByUuid.get(fmId)?.length || 0) > 1) {
      throw new Error(`ERR_AMBIGUOUS_SESSION_ID: 发现多个同 UUID 会话文件 (${fmId})`);
    }
    sessionFilePath = candidatePath;
  } else if (isExplicitUuid) {
    const uuidMatches = filesByUuid.get(normRef) || [];
    if (uuidMatches.length === 0) {
      throw new Error(`未找到 UUID 对应的可读会话文件: ${normRef}`);
    }
    if (uuidMatches.length > 1) {
      throw new Error(`ERR_AMBIGUOUS_SESSION_ID: 发现多个同 UUID 会话文件 (${normRef})`);
    }
    sessionFilePath = uuidMatches[0];
  } else {
    const uuidMatches = filesByUuid.get(normRef) || [];
    if (uuidMatches.length > 1) {
      throw new Error(`ERR_AMBIGUOUS_SESSION_ID: 发现多个同 UUID 会话文件 (${normRef})`);
    }
    if (uuidMatches.length === 1) {
      sessionFilePath = uuidMatches[0];
    } else {
      const targetBase = normRef.toLowerCase().endsWith('.md') ? normRef : `${normRef}.md`;
      const exactMatches = allSessionFiles.filter(f => path.basename(f) === targetBase);
      if (exactMatches.length > 1) {
        throw new Error(`ERR_AMBIGUOUS_SESSION_FILE: 存在多个同名会话文件 (${targetBase})，请使用明确相对路径或 UUID`);
      }
      if (exactMatches.length === 1) {
        const fmId = readFrontmatterIdFast(exactMatches[0]);
        if (fmId && (filesByUuid.get(fmId)?.length || 0) > 1) {
          throw new Error(`ERR_AMBIGUOUS_SESSION_ID: 发现多个同 UUID 会话文件 (${fmId})`);
        }
        sessionFilePath = exactMatches[0];
      } else {
        const prefixMatches = allSessionFiles.filter(f => path.basename(f).startsWith(normRef));
        if (prefixMatches.length > 1) {
          throw new Error(`ERR_AMBIGUOUS_SESSION_FILE: 存在多个匹配前缀的会话文件 (${normRef})，请使用明确相对路径或 UUID`);
        }
        if (prefixMatches.length === 1) {
          const fmId = readFrontmatterIdFast(prefixMatches[0]);
          if (fmId && (filesByUuid.get(fmId)?.length || 0) > 1) {
            throw new Error(`ERR_AMBIGUOUS_SESSION_ID: 发现多个同 UUID 会话文件 (${fmId})`);
          }
          sessionFilePath = prefixMatches[0];
        } else {
          throw new Error(`未找到对应的可读会话文件: ${targetBase}`);
        }
      }
    }
  }

  assertPathWithinBoundary(sessionFilePath, sessionsDir, { followSymlinks: false });

  const mdContent = fs.readFileSync(sessionFilePath, 'utf8').replace(/^\uFEFF/, '');
  const snapshotMatch = mdContent.match(/(?:^|\n)[ \t]*snapshot_id:[ \t]*["']?([^"'\r\n]+)["']?/);
  if (!snapshotMatch) {
    throw new Error(`可读会话文件缺少 snapshot_id: ${path.basename(sessionFilePath)}`);
  }
  const snapshotId = snapshotMatch[1].trim();

  // 仅匹配独立成行的块引用锚点（绝不被引用块 `> ...` 正文内的伪造 ^event- 字符串劫持）
  const anchorLineRe = new RegExp(`(?:^|\\r?\\n)(${anchor.replace('^', '\\^')})(?=\\r?\\n|$)`);
  const anchorLineMatch = anchorLineRe.exec(mdContent);
  if (!anchorLineMatch) {
    throw new Error(`可读会话中未找到锚点 ${anchor}`);
  }
  const leadLen = anchorLineMatch[0].length - anchorLineMatch[1].length;
  const anchorIdx = anchorLineMatch.index + leadLen;
  const sectionStart = mdContent.lastIndexOf('### 事件 #', anchorIdx);
  const readableExcerpt = sectionStart !== -1
    ? mdContent.slice(sectionStart, anchorIdx + anchor.length)
    : mdContent.slice(Math.max(0, anchorIdx - 200), anchorIdx + anchor.length);

  // 读取 manifest 并定位压缩快照或原始快照字节范围
  const manifestPath = path.join(dataDir, 'manifests', `${snapshotId}.json`);
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`未找到快照台账文件: ${snapshotId}.json`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const entry = (manifest.decompressed_line_map || []).find(item => item.event_id === eventId);
  if (!entry) {
    throw new Error(`台账中未记录事件 #${eventId} (${anchor})`);
  }

  let archivedRawPath = path.join(dataDir, 'raw', manifest.raw_archive_file);
  if (!fs.existsSync(archivedRawPath) && manifest.source_tool) {
    const legacyFlat = path.join(dataDir, 'raw', path.basename(manifest.raw_archive_file));
    const subDirPath = path.join(dataDir, 'raw', manifest.source_tool, path.basename(manifest.raw_archive_file));
    if (fs.existsSync(subDirPath)) archivedRawPath = subDirPath;
    else if (fs.existsSync(legacyFlat)) archivedRawPath = legacyFlat;
  }
  if (!fs.existsSync(archivedRawPath)) {
    throw new Error('归档原始快照文件不存在');
  }
  const archivedBytes = fs.readFileSync(archivedRawPath);
  let decompressed;
  try {
    decompressed = manifest.compressed ? decompressZstdAllFrames(archivedBytes) : archivedBytes;
  } catch (err) {
    throw new Error(`归档压缩快照解压失败: ${sanitizeOutputText(err.message)}`);
  }
  const lineSlice = decompressed.subarray(entry.byte_offset, entry.byte_offset + entry.byte_length).toString('utf8');

  let parsedRaw = null;
  try {
    parsedRaw = JSON.parse(lineSlice);
  } catch {
    parsedRaw = null;
  }

  return {
    found: true,
    snapshotId,
    eventId,
    anchor,
    compressed: Boolean(manifest.compressed),
    byteOffset: entry.byte_offset,
    byteLength: entry.byte_length,
    eventType: entry.type,
    status: entry.status,
    readableSessionFile: path.basename(sessionFilePath),
    readableSessionRelPath: path.relative(vaultDir, sessionFilePath).replace(/\\/g, '/'),
    readableExcerpt: sanitizeOutputText(readableExcerpt),
    rawEventSanitized: sanitizeOutputText(lineSlice),
    rawEventIdCheck: parsedRaw ? parsedRaw.type || entry.type : entry.type
  };
}
