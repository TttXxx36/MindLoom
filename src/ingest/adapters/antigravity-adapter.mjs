import fs from 'node:fs';
import path from 'node:path';

export const ANTIGRAVITY_KNOWN_EVENT_TYPES = new Set([
  'user',
  'assistant',
  'tool_use',
  'tool_result',
  'system',
  'summary',
  'message',
  'thinking',
  'USER_INPUT',
  'PLANNER_RESPONSE',
  'TOOL_CALL',
  'TOOL_RESPONSE',
  'CHECKPOINT',
  'TASK_BOUNDARY',
  'SYSTEM_MESSAGE',
  'EPHEMERAL_MESSAGE',
  'GENERIC',
  'ERROR_MESSAGE'
]);

const AGY_METADATA_CACHE = new Map();
const MAX_AGY_META_CACHE = 2048;

function normalizeAgyCachePathKey(filePath) {
  const resolved = path.resolve(filePath);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function getCachedAgyMeta(cacheKey, sig) {
  const cached = AGY_METADATA_CACHE.get(cacheKey);
  if (!cached || cached.sig !== sig) return null;
  AGY_METADATA_CACHE.delete(cacheKey);
  AGY_METADATA_CACHE.set(cacheKey, cached);
  return { ...cached.meta };
}

function setCachedAgyMeta(cacheKey, sig, meta) {
  if (AGY_METADATA_CACHE.has(cacheKey)) {
    AGY_METADATA_CACHE.delete(cacheKey);
  } else if (AGY_METADATA_CACHE.size >= MAX_AGY_META_CACHE) {
    const oldestKey = AGY_METADATA_CACHE.keys().next().value;
    if (oldestKey !== undefined) AGY_METADATA_CACHE.delete(oldestKey);
  }
  AGY_METADATA_CACHE.set(cacheKey, { sig, meta: { ...meta } });
}

function detectAntigravitySubagentFirstLine(firstLine) {
  if (!firstLine) return false;
  try {
    const first = JSON.parse(firstLine);
    if (!first || typeof first !== 'object') return false;
    const src = String(first.source || '').trim().toUpperCase();
    if (src === 'SYSTEM_SDK') {
      return true;
    }
    if (first.type === 'SYSTEM_MESSAGE') {
      if (src === 'SYSTEM' || src === 'SYSTEM_SDK') {
        return true;
      }
      const content = String(first.content || '');
      if (!src && (content.includes('<SYSTEM_MESSAGE>') || content.includes('<Identity>'))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

function readAntigravityHeadAndTailMeta(filePath, size) {
  if (size === 0) {
    return { isEmpty: true, isSubagent: false, isActive: false };
  }
  const fd = fs.openSync(filePath, 'r');
  try {
    const HEAD_INITIAL_CHUNK = 16384;
    const HEAD_NEXT_CHUNK = 65536;
    const TAIL_INITIAL_CHUNK = 8192;
    const TAIL_NEXT_CHUNK = 65536;
    const MAX_SCAN = 32 * 1024 * 1024;

    // 1. 前向分块读取首个非空 JSONL 行（分片数组避免长首行 O(L^2) 复制）
    let firstLine = null;
    let offset = 0;
    let carryChunks = [];
    let firstHead = true;
    while (offset < size && offset < MAX_SCAN && firstLine === null) {
      const targetLen = firstHead ? HEAD_INITIAL_CHUNK : HEAD_NEXT_CHUNK;
      firstHead = false;
      const toRead = Math.min(targetLen, size - offset);
      const buf = Buffer.allocUnsafe(toRead);
      let n = 0;
      while (n < toRead) {
        const readNow = fs.readSync(fd, buf, n, toRead - n, offset + n);
        if (readNow <= 0) break;
        n += readNow;
      }
      if (n <= 0) break;
      offset += n;

      const chunk = n === toRead ? buf : buf.subarray(0, n);
      let start = 0;
      while (start < chunk.length) {
        const nl = chunk.indexOf(0x0a, start);
        if (nl === -1) break;
        let lineBuf;
        if (carryChunks.length > 0) {
          carryChunks.push(chunk.subarray(start, nl));
          lineBuf = Buffer.concat(carryChunks);
          carryChunks = [];
        } else {
          lineBuf = chunk.subarray(start, nl);
        }
        const lineStr = lineBuf.toString('utf8').replace(/^\uFEFF/, '').replace(/\r$/, '');
        if (lineStr.trim() !== '') {
          firstLine = lineStr;
          break;
        }
        start = nl + 1;
      }
      if (firstLine === null && start < chunk.length) {
        carryChunks.push(chunk.subarray(start));
      }
    }
    if (firstLine === null && offset >= size && carryChunks.length > 0) {
      const tailBuf = carryChunks.length === 1 ? carryChunks[0] : Buffer.concat(carryChunks);
      const rem = tailBuf.toString('utf8').replace(/^\uFEFF/, '').replace(/\r$/, '');
      if (rem.trim() !== '') firstLine = rem;
    }

    if (firstLine === null) {
      return { isEmpty: true, isSubagent: false, isActive: false };
    }

    const isSubagent = detectAntigravitySubagentFirstLine(firstLine);

    // 2. 后向分块读取末行非空 JSONL，检查末行 JSON 闭合性（分片数组避免长末行 O(L^2) 复制）
    let pos = size;
    const tailChunks = [];
    let seenNonWs = false;
    let firstTail = true;
    let lastLineText = null;

    while (pos > 0 && size - pos < MAX_SCAN) {
      const targetLen = firstTail ? TAIL_INITIAL_CHUNK : TAIL_NEXT_CHUNK;
      firstTail = false;
      const readLen = Math.min(targetLen, pos);
      pos -= readLen;
      const chunk = Buffer.allocUnsafe(readLen);
      let r = 0;
      while (r < readLen) {
        const readNow = fs.readSync(fd, chunk, r, readLen - r, pos + r);
        if (readNow <= 0) break;
        r += readNow;
      }
      if (r <= 0) break;
      const view = r === readLen ? chunk : chunk.subarray(0, r);

      let chunkSlice = view;
      if (!seenNonWs) {
        let scanIdx = view.length - 1;
        while (
          scanIdx >= 0 &&
          (view[scanIdx] === 0x0a || view[scanIdx] === 0x0d || view[scanIdx] === 0x20 || view[scanIdx] === 0x09)
        ) {
          scanIdx--;
        }
        if (scanIdx < 0) {
          continue;
        }
        seenNonWs = true;
        chunkSlice = view.subarray(0, scanIdx + 1);
      }

      const prevNl = chunkSlice.lastIndexOf(0x0a);
      if (prevNl !== -1) {
        const parts = [chunkSlice.subarray(prevNl + 1)];
        for (let i = tailChunks.length - 1; i >= 0; i--) {
          parts.push(tailChunks[i]);
        }
        lastLineText = (parts.length === 1 ? parts[0] : Buffer.concat(parts))
          .toString('utf8')
          .replace(/^\uFEFF/, '')
          .trim();
        break;
      }

      tailChunks.push(chunkSlice);
    }

    if (lastLineText === null && seenNonWs && tailChunks.length > 0) {
      const parts = [];
      for (let i = tailChunks.length - 1; i >= 0; i--) {
        parts.push(tailChunks[i]);
      }
      lastLineText = (parts.length === 1 ? parts[0] : Buffer.concat(parts))
        .toString('utf8')
        .replace(/^\uFEFF/, '')
        .trim();
    }

    let isActive = false;
    if (lastLineText) {
      try {
        JSON.parse(lastLineText);
      } catch {
        isActive = true;
      }
    }

    return { isEmpty: false, isSubagent, isActive };
  } finally {
    fs.closeSync(fd);
  }
}

function checkTailJsonClosed(buf) {
  if (!buf || buf.length === 0) return { closed: true, reason: null };
  let text = buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const endsWithNewline = text.endsWith('\n');
  const nonEmptyLines = text.split(/\r?\n/).filter(l => l.trim() !== '');
  if (nonEmptyLines.length === 0) return { closed: true, reason: null };
  const lastLine = nonEmptyLines[nonEmptyLines.length - 1];
  try {
    JSON.parse(lastLine);
    return { closed: true, reason: null };
  } catch {
    return {
      closed: false,
      reason: endsWithNewline ? 'unclosed_or_incomplete_tail_json' : 'unclosed_trailing_line_without_newline'
    };
  }
}

/**
 * 扫描 Antigravity 本地会话目录
 * 过滤：空会话、subagent/SDK 编排子会话（首个事件为 SYSTEM_MESSAGE + SYSTEM/SYSTEM_SDK）、以及末行未闭合的活跃会话。
 * 使用有界头尾分块读取与 (path, size, mtimeMs, ino, ctimeMs) 元数据缓存，避免将大日志全量读入内存。
 * @param {{ antigravityBrainDir: string, includeFiltered?: boolean }} params
 */
export function discoverAntigravitySessions({ antigravityBrainDir, includeFiltered = false }) {
  const results = [];
  if (!antigravityBrainDir || !fs.existsSync(antigravityBrainDir)) return results;

  const entries = fs.readdirSync(antigravityBrainDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const convDir = path.join(antigravityBrainDir, entry.name);
    const agyTranscript = path.join(convDir, '.system_generated', 'logs', 'transcript.jsonl');
    const directTranscript = path.join(convDir, 'transcript.jsonl');
    const primary = fs.existsSync(agyTranscript)
      ? agyTranscript
      : (fs.existsSync(directTranscript) ? directTranscript : null);
    if (!primary) continue;

    const st = fs.statSync(primary);
    const companion = path.join(path.dirname(primary), 'transcript_full.jsonl');
    const hasCompanion = fs.existsSync(companion);
    const sig = `${st.size}\0${st.mtimeMs}\0${st.ino}\0${st.ctimeMs}`;
    const cacheKey = normalizeAgyCachePathKey(primary);
    let meta = getCachedAgyMeta(cacheKey, sig);
    if (!meta) {
      meta = readAntigravityHeadAndTailMeta(primary, st.size);
      setCachedAgyMeta(cacheKey, sig, meta);
    }

    const filteredReason = meta.isEmpty
      ? 'empty_session'
      : meta.isSubagent
        ? 'subagent_session'
        : meta.isActive
          ? 'active_unclosed_session'
          : null;
    if (!includeFiltered && filteredReason) continue;

    results.push({
      source_tool: 'antigravity',
      session_id: entry.name,
      has_companion_full: hasCompanion,
      ...(filteredReason ? { filtered_reason: filteredReason } : {}),
      updated_at: new Date(st.mtimeMs).toISOString(),
      _internal_source_path: primary
    });
  }

  return results;
}

/**
 * Antigravity 双轨同批次稳定性采样 (PLAN.md §5.1 情况 1)
 * - 本次读取前后核对主/辅文件存在性、大小、mtime 与 inode 轮换
 * - 核对主/辅文件末行 JSON 闭合性；任一不稳定立即中止捕获 (ERR_SOURCE_UNSTABLE)
 *
 * @param {{
 *   sourcePath: string,
 *   companionFullPath?: string | null,
 *   sessionId: string,
 *   stabilityHook?: (phase: 'before' | 'after') => void
 * }} params
 */
export function readAndStabilizeAntigravityCapture({
  sourcePath,
  companionFullPath = null,
  sessionId,
  stabilityHook = null
}) {
  const resolvedCompanionPath = companionFullPath || (
    path.basename(sourcePath).toLowerCase() === 'transcript.jsonl'
      ? path.join(path.dirname(sourcePath), 'transcript_full.jsonl')
      : null
  );

  if (stabilityHook) stabilityHook('before');
  const statBefore = fs.statSync(sourcePath);
  const compExistsBefore = Boolean(resolvedCompanionPath && fs.existsSync(resolvedCompanionPath));
  const compStatBefore = compExistsBefore ? fs.statSync(resolvedCompanionPath) : null;

  const rawBytes = fs.readFileSync(sourcePath);
  const companionBytes = compExistsBefore ? fs.readFileSync(resolvedCompanionPath) : null;

  if (stabilityHook) stabilityHook('after');
  const statAfter = fs.statSync(sourcePath);
  const compExistsAfter = Boolean(resolvedCompanionPath && fs.existsSync(resolvedCompanionPath));
  const compStatAfter = compExistsAfter ? fs.statSync(resolvedCompanionPath) : null;

  const primaryUnstable =
    statBefore.size !== statAfter.size ||
    statBefore.mtimeMs !== statAfter.mtimeMs ||
    (statBefore.ino && statAfter.ino && statBefore.ino !== statAfter.ino);

  const companionUnstable =
    compExistsBefore !== compExistsAfter ||
    (compStatBefore && compStatAfter && (
      compStatBefore.size !== compStatAfter.size ||
      compStatBefore.mtimeMs !== compStatAfter.mtimeMs ||
      (compStatBefore.ino && compStatAfter.ino && compStatBefore.ino !== compStatAfter.ino)
    ));

  if (primaryUnstable || companionUnstable) {
    return {
      stable: false,
      errorCode: 'ERR_SOURCE_UNSTABLE',
      reason: 'source_file_still_changing',
      sessionId
    };
  }

  const primaryTail = checkTailJsonClosed(rawBytes);
  if (!primaryTail.closed) {
    return {
      stable: false,
      errorCode: 'ERR_SOURCE_UNSTABLE',
      reason: `primary_${primaryTail.reason}`,
      sessionId
    };
  }

  if (companionBytes) {
    const compTail = checkTailJsonClosed(companionBytes);
    if (!compTail.closed) {
      return {
        stable: false,
        errorCode: 'ERR_SOURCE_UNSTABLE',
        reason: `companion_${compTail.reason}`,
        sessionId
      };
    }
  }

  return {
    stable: true,
    rawBytes,
    companionBytes,
    resolvedCompanionPath
  };
}

function makeTupleKey(obj) {
  return JSON.stringify([
    obj.step_index ?? null,
    obj.type ?? null,
    obj.source ?? null,
    obj.created_at ?? null
  ]);
}

function extractEventIdentifier(obj) {
  if (!obj || typeof obj !== 'object') return null;
  return obj.id ?? obj.event_id ?? obj.uuid ?? null;
}

/**
 * 构建 transcript_full.jsonl 的 4 元组 (step_index, type, source, created_at) 索引并保留原始行号
 * @param {Buffer | null} companionBytes
 * @param {(buf: Buffer) => { lines: Array<{ text: string }> }} splitLinesFn
 */
export function buildAntigravityBackfillIndex(companionBytes, splitLinesFn) {
  const fullMap = new Map();
  if (!companionBytes) return fullMap;

  const { lines: fullLines } = splitLinesFn(companionBytes);
  for (let fIdx = 0; fIdx < fullLines.length; fIdx++) {
    const fText = fullLines[fIdx].text.trim();
    if (!fText) continue;
    try {
      const fObj = JSON.parse(fText);
      if (fObj && typeof fObj === 'object') {
        const tupleKey = makeTupleKey(fObj);
        const existing = fullMap.get(tupleKey);
        if (!existing) {
          fullMap.set(tupleKey, {
            count: 1,
            event: fObj,
            backfillLine: fIdx + 1,
            eventIdentifier: extractEventIdentifier(fObj)
          });
        } else {
          existing.count += 1;
        }
      }
    } catch {
      // ignore unparseable line in companion backfill index
    }
  }
  return fullMap;
}

const IDENTITY_FIELDS = new Set(['step_index', 'type', 'source', 'created_at', 'id', 'event_id', 'uuid']);

/**
 * Antigravity 情况 2 同一事件证明与字段白名单回填 (PLAN.md §5.1)
 * @param {object} parsedEvent
 * @param {number} eventId
 * @param {Map<string, any>} antigravityFullMap
 * @param {boolean} hasCompanionBytes
 */
export function applyAntigravityBackfill(parsedEvent, eventId, antigravityFullMap, hasCompanionBytes) {
  const hasTruncated =
    parsedEvent &&
    typeof parsedEvent === 'object' &&
    Array.isArray(parsedEvent.truncated_fields) &&
    parsedEvent.truncated_fields.length > 0;

  if (!hasTruncated) {
    return {
      backfilled: false,
      truncationUnresolved: false,
      reasonDetail: null,
      provenance: {
        source_tool: 'antigravity',
        source_role: 'primary',
        primary_line: eventId,
        backfill_line: null,
        step_index: parsedEvent?.step_index ?? null,
        backfilled_fields: []
      }
    };
  }

  const tupleKey = makeTupleKey(parsedEvent);
  const matchEntry = antigravityFullMap.get(tupleKey);
  const primaryIdentifier = extractEventIdentifier(parsedEvent);
  const identifierOk =
    !primaryIdentifier ||
    !matchEntry?.eventIdentifier ||
    primaryIdentifier === matchEntry.eventIdentifier;

  const allFieldsPresent =
    Boolean(matchEntry) &&
    matchEntry.count === 1 &&
    Boolean(matchEntry.event) &&
    identifierOk &&
    parsedEvent.truncated_fields.every(field => Object.prototype.hasOwnProperty.call(matchEntry.event, field));

  if (allFieldsPresent) {
    const copiedFields = [];
    for (const field of parsedEvent.truncated_fields) {
      if (IDENTITY_FIELDS.has(field)) continue;
      parsedEvent[field] = matchEntry.event[field];
      copiedFields.push(field);
    }
    parsedEvent.truncation_resolved = true;
    return {
      backfilled: true,
      truncationUnresolved: false,
      reasonDetail: null,
      provenance: {
        source_tool: 'antigravity',
        source_role: 'backfill',
        primary_line: eventId,
        backfill_line: matchEntry.backfillLine,
        step_index: parsedEvent.step_index ?? null,
        backfilled_fields: copiedFields
      }
    };
  }

  parsedEvent.truncation_unresolved = true;
  const reasonDetail = !hasCompanionBytes
    ? 'missing_transcript_full'
    : !matchEntry
      ? 'missing_step_match_in_transcript_full'
      : matchEntry.count > 1
        ? 'duplicate_step_identity_in_transcript_full'
        : !identifierOk
          ? 'event_identifier_mismatch_in_transcript_full'
          : 'missing_truncated_field_in_transcript_full';

  return {
    backfilled: false,
    truncationUnresolved: true,
    reasonDetail,
    provenance: {
      source_tool: 'antigravity',
      source_role: 'primary',
      primary_line: eventId,
      backfill_line: null,
      step_index: parsedEvent.step_index ?? null,
      backfilled_fields: []
    }
  };
}

/**
 * 规范化 Antigravity 事件结构
 * @param {object} parsedEvent
 * @param {object} provenance
 */
export function normalizeAntigravityEvent(parsedEvent, provenance) {
  const evType = parsedEvent?.type || 'unknown';
  let role = parsedEvent?.role || null;
  if (!role) {
    if (evType === 'USER_INPUT') role = 'user';
    else if (evType === 'PLANNER_RESPONSE') role = 'assistant';
    else if (evType === 'TOOL_CALL') role = 'tool_use';
    else if (evType === 'TOOL_RESPONSE') role = 'tool_result';
    else if (evType === 'SYSTEM_MESSAGE') role = 'system';
  }

  const content =
    parsedEvent?.content ??
    parsedEvent?.text ??
    parsedEvent?.output ??
    parsedEvent?.command ??
    JSON.stringify(parsedEvent);

  return {
    type: evType,
    isKnownType: ANTIGRAVITY_KNOWN_EVENT_TYPES.has(evType),
    role,
    timestamp: parsedEvent?.created_at || parsedEvent?.timestamp || null,
    content: String(content),
    toolCalls: [],
    cwd: typeof parsedEvent?.cwd === 'string' ? parsedEvent.cwd : null,
    gitRoot: typeof parsedEvent?.git_root === 'string' ? parsedEvent.git_root : null,
    provenance
  };
}

function extractStringsFromJsonValue(val, out = []) {
  if (typeof val === 'string') {
    out.push(val);
  } else if (Array.isArray(val)) {
    for (const item of val) extractStringsFromJsonValue(item, out);
  } else if (val && typeof val === 'object') {
    for (const v of Object.values(val)) extractStringsFromJsonValue(v, out);
  }
  return out;
}

function matchWorkingDirectoryHint(text) {
  const m = String(text || '').match(
    /Command Working Directory:\s*([A-Za-z]:[\\/][^\r\n<>"|*?\x00]{1,220}|\/[^\r\n<>"|*?\x00]{1,220})/i
  );
  return m && m[1] ? m[1].trim() : null;
}

/**
 * 从 Antigravity transcript.jsonl 头部可靠提取工作目录线索 (Setup 与 auto-sync 共享单一真源)
 * 若无法可靠提取则返回 null，绝不猜测项目归属
 * @param {string} filePath
 * @returns {string | null}
 */
export function extractAntigravityCwdHint(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  try {
    const fd = fs.openSync(filePath, 'r');
    try {
      const buf = Buffer.allocUnsafe(262144);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      if (n <= 0) return null;
      const head = buf.subarray(0, n).toString('utf8');

      // 1. Prefer proper JSON line parsing so escaped \\ and \n are decoded cleanly
      for (const line of head.split(/\r?\n/)) {
        const trimmed = line.replace(/^\uFEFF/, '').trim();
        if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) continue;
        try {
          const parsed = JSON.parse(trimmed);
          if (parsed && typeof parsed.cwd === 'string' && parsed.cwd.trim()) {
            return parsed.cwd.trim();
          }
          const strings = extractStringsFromJsonValue(parsed);
          for (const s of strings) {
            const hit = matchWorkingDirectoryHint(s);
            if (hit) return hit;
          }
        } catch {
          // ignore partial/malformed JSON line
        }
      }

      // 2. Fallback for truncated/raw text: stop before unescaped JSON \n, \r, \t, \"
      const rawMatch = head.match(
        /Command Working Directory:\s*([A-Za-z]:(?:\\\\|[\\/])(?:(?!(?<!\\)\\[nrt"]).){1,220}|\/(?:(?!(?<!\\)\\[nrt"]).){1,220})/i
      );
      if (rawMatch && rawMatch[1]) {
        return rawMatch[1].replace(/\\\\/g, '\\').trim();
      }
      return matchWorkingDirectoryHint(head);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}
