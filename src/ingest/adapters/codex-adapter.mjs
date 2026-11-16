import fs from 'node:fs';
import path from 'node:path';
import { readZstdPrefixLinesFromFile } from '../zstd-utils.mjs';

export const CODEX_KNOWN_EVENT_TYPES = new Set([
  'user',
  'assistant',
  'tool_use',
  'tool_result',
  'system',
  'summary',
  'message',
  'thinking',
  'session_meta',
  'response_item',
  'event_msg',
  'turn_context',
  'world_state',
  'token_usage_record',
  'realtime_item',
  'compacted',
  'inter_agent_communication_metadata',
  'retained_context'
]);

const CODEX_METADATA_CACHE = new Map();
const MAX_CODEX_META_CACHE = 2048;

function normalizeCachePathKey(filePath) {
  const resolved = path.resolve(filePath);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function getCachedCodexMeta(cacheKey, sig) {
  const cached = CODEX_METADATA_CACHE.get(cacheKey);
  if (!cached || cached.sig !== sig) return null;
  CODEX_METADATA_CACHE.delete(cacheKey);
  CODEX_METADATA_CACHE.set(cacheKey, cached);
  return { ...cached.res };
}

function setCachedCodexMeta(cacheKey, sig, res) {
  if (CODEX_METADATA_CACHE.has(cacheKey)) {
    CODEX_METADATA_CACHE.delete(cacheKey);
  } else if (CODEX_METADATA_CACHE.size >= MAX_CODEX_META_CACHE) {
    const oldestKey = CODEX_METADATA_CACHE.keys().next().value;
    if (oldestKey !== undefined) CODEX_METADATA_CACHE.delete(oldestKey);
  }
  CODEX_METADATA_CACHE.set(cacheKey, { sig, res });
}

function readPrefixHeadLinesFromZst(filePath, maxLines = 4, existingStat = null) {
  const st = existingStat || fs.statSync(filePath);
  if (st.size === 0) {
    return { lines: [], hasMoreFrames: false, corrupt: false };
  }
  try {
    const zPrefix = readZstdPrefixLinesFromFile(filePath, maxLines, st);
    return {
      lines: zPrefix.lines,
      hasMoreFrames: zPrefix.hasMoreFrames,
      corrupt: false
    };
  } catch {
    return { lines: [], hasMoreFrames: false, corrupt: true };
  }
}

function readPrefixHeadLinesFromPlain(filePath, maxLines = 4, existingStat = null) {
  const st = existingStat || fs.statSync(filePath);
  if (st.size === 0) return { lines: [], endsWithNewline: true, lastLineValidJson: true, size: 0 };
  const fd = fs.openSync(filePath, 'r');
  try {
    // 1. 按块向前读取完整换行闭合行（初始 16KB、后续 64KB + 分片数组避免长行 O(L^2) 复制）
    const HEAD_INITIAL_CHUNK = 16384;
    const HEAD_NEXT_CHUNK = 65536;
    const MAX_HEAD_SCAN = 32 * 1024 * 1024;
    const lines = [];
    let offset = 0;
    let carryChunks = [];
    let firstHead = true;

    while (offset < st.size && offset < MAX_HEAD_SCAN && lines.length < maxLines) {
      const targetLen = firstHead ? HEAD_INITIAL_CHUNK : HEAD_NEXT_CHUNK;
      firstHead = false;
      const toRead = Math.min(targetLen, st.size - offset);
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
          lines.push(lineStr);
          if (lines.length >= maxLines) break;
        }
        start = nl + 1;
      }
      if (lines.length < maxLines && start < chunk.length) {
        carryChunks.push(chunk.subarray(start));
      }
    }
    if (offset >= st.size && lines.length < maxLines && carryChunks.length > 0) {
      const tailBuf = carryChunks.length === 1 ? carryChunks[0] : Buffer.concat(carryChunks);
      const tailStr = tailBuf.toString('utf8').replace(/^\uFEFF/, '').replace(/\r$/, '');
      if (tailStr.trim() !== '') lines.push(tailStr);
    }

    // 2. 向后按块扫描完整末行（初始 8KB、后续 64KB + 分片数组避免超长末行 O(L^2) 复制）
    const TAIL_INITIAL_CHUNK = 8192;
    const TAIL_NEXT_CHUNK = 65536;
    const MAX_TAIL_SCAN = 32 * 1024 * 1024;
    let pos = st.size;
    const tailChunks = [];
    let seenNonWs = false;
    let endsWithNewline = true;
    let firstTail = true;
    let foundLastLineStart = false;
    let lastLineText = '';

    while (pos > 0 && st.size - pos < MAX_TAIL_SCAN && !foundLastLineStart) {
      const targetLen = firstTail ? TAIL_INITIAL_CHUNK : TAIL_NEXT_CHUNK;
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
      if (firstTail) {
        firstTail = false;
        endsWithNewline = view[view.length - 1] === 0x0a;
      }

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
        foundLastLineStart = true;
        break;
      }

      tailChunks.push(chunkSlice);
    }

    if (!foundLastLineStart && seenNonWs && tailChunks.length > 0) {
      const parts = [];
      for (let i = tailChunks.length - 1; i >= 0; i--) {
        parts.push(tailChunks[i]);
      }
      lastLineText = (parts.length === 1 ? parts[0] : Buffer.concat(parts))
        .toString('utf8')
        .replace(/^\uFEFF/, '')
        .trim();
    }

    let lastLineValidJson = true;
    if (lastLineText) {
      try {
        JSON.parse(lastLineText);
      } catch {
        lastLineValidJson = false;
      }
    }
    return { lines, endsWithNewline, lastLineValidJson, size: st.size };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * 检查 Codex 会话文件元信息并判定是否属于已完成主会话 (PLAN.md §5.1)
 * 过滤：subagent 会话、空/仅元信息会话、以及末行未闭合的活跃写入会话。
 * 注：兼容合成测试中单行 `{ type: "user", ... }` 样本（不被误判为空会话）。
 *
 * @param {string} filePath
 */
export function inspectCodexSessionMetadata(filePath, existingStat = null) {
  const st = existingStat || fs.statSync(filePath);
  const sig = `${st.size}\0${st.mtimeMs}\0${st.ino}\0${st.ctimeMs}`;
  const cacheKey = normalizeCachePathKey(filePath);
  const cached = getCachedCodexMeta(cacheKey, sig);
  if (cached) return cached;

  const lower = filePath.toLowerCase();
  const isZst = lower.endsWith('.zst') || lower.endsWith('.zstd');
  let headLines = [];
  let hasMoreFrames = false;
  let isActive = false;
  let corrupt = false;

  if (isZst) {
    const zInfo = readPrefixHeadLinesFromZst(filePath, 4, st);
    headLines = zInfo.lines;
    hasMoreFrames = zInfo.hasMoreFrames;
    corrupt = zInfo.corrupt;
  } else {
    const info = readPrefixHeadLinesFromPlain(filePath, 4, st);
    headLines = info.lines;
    if (info.size > 0 && (!info.endsWithNewline || !info.lastLineValidJson)) {
      isActive = true;
    }
  }

  let isSubagent = false;
  let isEmpty = !corrupt && headLines.length === 0;
  let cwd = null;
  let sessionMetaId = null;

  if (headLines.length > 0) {
    try {
      const first = JSON.parse(headLines[0]);
      if (first && first.type === 'session_meta') {
        const payload = first.payload || {};
        cwd = typeof payload.cwd === 'string' ? payload.cwd : null;
        sessionMetaId = payload.session_id || payload.id || null;
        const src = payload.source;
        if (src && typeof src === 'object' && src.subagent) {
          isSubagent = true;
        }
        if (typeof src === 'string' && src.toLowerCase().includes('subagent')) {
          isSubagent = true;
        }
        if (headLines.length === 1 && !hasMoreFrames) {
          isEmpty = true;
        }
      }
    } catch {
      // ignore malformed head line
    }
  }

  let filteredReason = null;
  if (corrupt) filteredReason = 'corrupt_session';
  else if (isSubagent) filteredReason = 'subagent_session';
  else if (isEmpty) filteredReason = 'empty_session';
  else if (isActive) filteredReason = 'active_unclosed_session';

  const res = {
    isSubagent,
    isEmpty,
    isActive,
    corrupt,
    isMainCompleted: !filteredReason,
    filteredReason,
    cwd,
    sessionMetaId
  };
  setCachedCodexMeta(cacheKey, sig, res);
  return { ...res };
}

/**
 * 扫描 Codex 本地主会话目录 (sessions + archived_sessions)
 * @param {{ codexHome: string, codexArchivedDir?: string | null, includeFiltered?: boolean }} params
 */
export function discoverCodexSessions({ codexHome, codexArchivedDir = null, includeFiltered = false }) {
  const results = [];
  const seenDirs = new Set();

  function walk(rootDir) {
    if (!rootDir || !fs.existsSync(rootDir)) return;
    const dirKey = normalizeCachePathKey(rootDir);
    if (seenDirs.has(dirKey)) return;
    seenDirs.add(dirKey);
    const entries = fs.readdirSync(rootDir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(rootDir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && /\.(?:jsonl|jsonl\.zst|jsonl\.zstd)$/i.test(entry.name)) {
        if (entry.name === 'transcript_full.jsonl' || entry.name === 'transcript.jsonl') continue;
        const st = fs.statSync(full);
        const meta = inspectCodexSessionMetadata(full, st);
        if (!includeFiltered && !meta.isMainCompleted) {
          continue;
        }
        const baseId = entry.name.replace(/\.jsonl(?:\.zstd?)?$/i, '');
        results.push({
          source_tool: 'codex',
          session_id: baseId,
          ...(meta.sessionMetaId && meta.sessionMetaId !== baseId ? { session_meta_id: meta.sessionMetaId } : {}),
          ...(meta.cwd ? { cwd: meta.cwd } : {}),
          ...(meta.filteredReason ? { filtered_reason: meta.filteredReason } : {}),
          has_companion_full: false,
          updated_at: new Date(st.mtimeMs).toISOString(),
          _internal_source_path: full
        });
      }
    }
  }

  walk(codexHome);
  if (codexArchivedDir) {
    walk(codexArchivedDir);
  }
  return results;
}

function extractCodexContentParts(contentVal) {
  if (typeof contentVal === 'string') return contentVal;
  if (Array.isArray(contentVal)) {
    const parts = [];
    for (const item of contentVal) {
      if (typeof item === 'string') {
        parts.push(item);
      } else if (item && typeof item === 'object') {
        if (typeof item.text === 'string') parts.push(item.text);
        else if (typeof item.content === 'string') parts.push(item.content);
        else if (typeof item.output === 'string') parts.push(item.output);
        else parts.push(JSON.stringify(item));
      }
    }
    return parts.join('\n');
  }
  if (contentVal && typeof contentVal === 'object') {
    if (typeof contentVal.text === 'string') return contentVal.text;
    return JSON.stringify(contentVal);
  }
  return null;
}

/**
 * 将 Codex 原生事件或合成样本规范化为统一内部事件字段
 * @param {object} parsedEvent
 * @param {number} eventId
 */
export function normalizeCodexEvent(parsedEvent, eventId) {
  const topType = parsedEvent?.type || 'unknown';
  const payload = parsedEvent?.payload && typeof parsedEvent.payload === 'object' ? parsedEvent.payload : null;
  const subType = payload?.type || null;

  let cwd = typeof parsedEvent?.cwd === 'string' ? parsedEvent.cwd : null;
  let gitRoot = typeof parsedEvent?.git_root === 'string' ? parsedEvent.git_root : null;
  if (!cwd && payload && typeof payload.cwd === 'string') {
    cwd = payload.cwd;
  }
  if (!gitRoot && payload && typeof payload.git_root === 'string') {
    gitRoot = payload.git_root;
  }

  let role = parsedEvent?.role || null;
  let body = null;
  const toolCalls = [];

  if (topType === 'session_meta' && payload) {
    role = 'system';
    body = `session_meta id=${payload.session_id || payload.id || ''} cwd=${payload.cwd || ''} originator=${payload.originator || ''} cli=${payload.cli_version || ''}`.trim();
  } else if (topType === 'response_item' && payload) {
    role = payload.role || (subType === 'reasoning' ? 'thinking' : 'assistant');
    if (subType === 'message') {
      body = extractCodexContentParts(payload.content);
    } else if (subType === 'function_call' || subType === 'custom_tool_call') {
      role = 'tool_use';
      const toolName = payload.name || subType;
      const args = typeof payload.arguments === 'string' ? payload.arguments : JSON.stringify(payload.arguments ?? payload.input ?? '');
      toolCalls.push({ name: toolName, call_id: payload.call_id || null });
      body = `[${toolName}] ${args}`;
    } else if (subType === 'function_call_output' || subType === 'custom_tool_call_output') {
      role = 'tool_result';
      body = extractCodexContentParts(payload.output ?? payload.content);
    } else if (subType === 'reasoning') {
      body = extractCodexContentParts(payload.summary ?? payload.content) || '[reasoning]';
    } else {
      body = extractCodexContentParts(payload.content ?? payload.output ?? payload.text) || JSON.stringify(payload);
    }
  } else if (topType === 'event_msg' && payload) {
    if (subType === 'user_message') {
      role = 'user';
      body = extractCodexContentParts(payload.message ?? payload.content ?? payload.text);
    } else if (subType === 'agent_message') {
      role = 'assistant';
      body = extractCodexContentParts(payload.message ?? payload.content ?? payload.text);
    } else if (subType === 'task_complete') {
      role = 'assistant';
      body = payload.last_agent_message || `task_complete turn=${payload.turn_id || ''}`;
    } else if (subType === 'item_completed') {
      role = 'assistant';
      body = extractCodexContentParts(payload.item?.content ?? payload.item?.text) || JSON.stringify(payload);
    } else {
      role = 'system';
      body = `${subType || 'event_msg'}: ${JSON.stringify(payload)}`;
    }
  } else if (topType === 'inter_agent_communication_metadata') {
    role = 'system';
    body = `inter_agent_communication_metadata: ${JSON.stringify(payload ?? parsedEvent)}`;
  } else if (topType === 'retained_context') {
    role = 'system';
    body = `retained_context (${subType || 'context'}): ${JSON.stringify(payload ?? parsedEvent)}`;
  } else {
    body =
      parsedEvent?.content ??
      parsedEvent?.text ??
      parsedEvent?.output ??
      parsedEvent?.command ??
      JSON.stringify(parsedEvent);
  }

  return {
    type: topType,
    subType,
    isKnownType: CODEX_KNOWN_EVENT_TYPES.has(topType),
    role,
    timestamp: parsedEvent?.timestamp || parsedEvent?.created_at || payload?.timestamp || null,
    content: body === null || body === undefined ? JSON.stringify(parsedEvent) : String(body),
    toolCalls,
    cwd,
    gitRoot,
    provenance: {
      source_tool: 'codex',
      source_role: 'primary',
      primary_line: eventId,
      ...(subType ? { event_subtype: subType } : {})
    }
  };
}
