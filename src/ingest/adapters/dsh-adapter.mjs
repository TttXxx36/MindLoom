import fs from 'node:fs';
import path from 'node:path';
import { readZstdPrefixLinesFromFile, isZstdBuffer } from '../zstd-utils.mjs';

export const DSH_KNOWN_EVENT_TYPES = new Set([
  'user',
  'assistant',
  'tool_use',
  'tool_result',
  'system',
  'summary',
  'message',
  'thinking',
  'session',
  'permission/preset',
  'sandbox/mode',
  'approval/policy',
  'session/end-seed',
  'agent-preset/selected',
  'subagent/catalog',
  'subagent/descriptor',
  'agent/inbox/spliced',
  'turn/start',
  'turn/end',
  'step/start',
  'step/end',
  'system/message',
  'developer/message',
  'user/message',
  'assistant/message',
  'assistant/attempt',
  'request/header',
  'request/context',
  'session/title',
  'session/title-llm-request',
  'tool/call',
  'tool/result',
  'tool/ptc-dispatch-start',
  'tool/ptc-dispatch',
  'session-log-deepseek/delivery-accepted',
  'command/run',
  'command/done',
  'job/registered',
  'job/settled',
  'llm/retry',
  'llm/retry-started',
  'workspace/changes',
  'model/selection',
  'deliverables/presented',
  'approval/asked',
  'approval/decided',
  'web/deepseek-search-llm-request',
  'todo/write',
  'compaction/start',
  'compaction/summary',
  'compaction/end',
  'compaction/prune',
  'plan/mode',
  'goal/change'
]);

export function isKnownDshEventType(evType) {
  if (!evType) return false;
  if (DSH_KNOWN_EVENT_TYPES.has(evType)) return true;
  return String(evType).startsWith('plugin:');
}

/**
 * 从 DSH 会话物理路径提取 <workspace-slug> 提示信息
 * 支持: ~/.dsh/sessions/<workspace-slug>/<session-uuid>/session.v4.jsonl.zstd
 *
 * @param {string} sourcePath
 * @returns {{ workspaceSlug: string | null, sessionUuidFromPath: string | null }}
 */
export function extractDshPathHints(sourcePath) {
  if (!sourcePath) return { workspaceSlug: null, sessionUuidFromPath: null };
  const fileName = path.basename(sourcePath);
  const baseId = fileName.replace(/\.jsonl(?:\.zstd?)?$/i, '');
  if (/^session\.v\d+$/i.test(baseId)) {
    const sessionDir = path.dirname(sourcePath);
    const slugDir = path.dirname(sessionDir);
    return {
      sessionUuidFromPath: path.basename(sessionDir),
      workspaceSlug: path.basename(slugDir)
    };
  }
  const parentName = path.basename(path.dirname(sourcePath));
  return {
    sessionUuidFromPath: baseId,
    workspaceSlug: parentName.startsWith('--') ? parentName : null
  };
}

const DSH_METADATA_CACHE = new Map();
const MAX_DSH_META_CACHE = 2048;

function normalizeDshCachePathKey(filePath) {
  const resolved = path.resolve(filePath);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function getCachedDshMeta(cacheKey, sig) {
  const cached = DSH_METADATA_CACHE.get(cacheKey);
  if (!cached || cached.sig !== sig) return null;
  DSH_METADATA_CACHE.delete(cacheKey);
  DSH_METADATA_CACHE.set(cacheKey, cached);
  return { ...cached.res };
}

function setCachedDshMeta(cacheKey, sig, res) {
  if (DSH_METADATA_CACHE.has(cacheKey)) {
    DSH_METADATA_CACHE.delete(cacheKey);
  } else if (DSH_METADATA_CACHE.size >= MAX_DSH_META_CACHE) {
    const oldestKey = DSH_METADATA_CACHE.keys().next().value;
    if (oldestKey !== undefined) DSH_METADATA_CACHE.delete(oldestKey);
  }
  DSH_METADATA_CACHE.set(cacheKey, { sig, res: { ...res } });
}

function readPlainPrefixLines(filePath, maxLines = 4, existingStat = null) {
  const st = existingStat || fs.statSync(filePath);
  if (st.size === 0) return [];
  const fd = fs.openSync(filePath, 'r');
  try {
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
    return lines;
  } finally {
    fs.closeSync(fd);
  }
}

function readHeaderProbeBytes(filePath, size) {
  if (size === 0) return Buffer.alloc(0);
  const fd = fs.openSync(filePath, 'r');
  try {
    const len = Math.min(4, size);
    const buf = Buffer.allocUnsafe(len);
    const n = fs.readSync(fd, buf, 0, len, 0);
    return buf.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * 检查 DSH 会话文件元信息（过滤委派子代理会话与仅含 1 行 session 头部的空会话）
 * @param {string} filePath
 */
export function inspectDshSessionMetadata(filePath, existingStat = null) {
  const st = existingStat || fs.statSync(filePath);
  const sig = `${st.size}\0${st.mtimeMs}\0${st.ino}\0${st.ctimeMs}`;
  const cacheKey = normalizeDshCachePathKey(filePath);
  const cached = getCachedDshMeta(cacheKey, sig);
  if (cached) return cached;

  const lowerPath = String(filePath || '').toLowerCase();
  const compressed =
    lowerPath.endsWith('.zst') || lowerPath.endsWith('.zstd')
      ? true
      : isZstdBuffer(readHeaderProbeBytes(filePath, st.size), filePath);
  let lines = [];
  let hasMoreFrames = false;

  if (compressed) {
    try {
      const zPrefix = readZstdPrefixLinesFromFile(filePath, 4, st);
      lines = zPrefix.lines;
      hasMoreFrames = zPrefix.hasMoreFrames;
    } catch {
      const corruptRes = {
        isSubagent: false,
        isEmpty: false,
        isMainCompleted: false,
        filteredReason: 'corrupt_session',
        corrupt: true,
        cwd: null
      };
      setCachedDshMeta(cacheKey, sig, corruptRes);
      return { ...corruptRes };
    }
  } else {
    lines = readPlainPrefixLines(filePath, 4, st);
  }

  let isSubagent = false;
  let isEmpty = lines.length === 0 && !hasMoreFrames;
  let cwd = null;

  if (lines.length > 0) {
    try {
      const first = JSON.parse(lines[0]);
      if (first && first.type === 'session') {
        if (typeof first.cwd === 'string') cwd = first.cwd;
        if (Number(first.delegationDepth || 0) > 0 || Boolean(first.parentSession)) {
          isSubagent = true;
        }
        if (lines.length === 1 && !hasMoreFrames) {
          isEmpty = true;
        }
      }
    } catch {
      // ignore malformed head line
    }
  }

  const filteredReason = isSubagent ? 'delegated_subagent_session' : (isEmpty ? 'empty_session' : null);
  const res = {
    isSubagent,
    isEmpty,
    isMainCompleted: !filteredReason,
    filteredReason,
    cwd
  };
  setCachedDshMeta(cacheKey, sig, res);
  return { ...res };
}

/**
 * 扫描 DSH 本地会话目录 (~/.dsh/sessions/<workspace-slug>/<session-uuid>/session.v4.jsonl.zstd)
 * @param {{ dshHome: string, includeFiltered?: boolean }} params
 */
export function discoverDshSessions({ dshHome, includeFiltered = false }) {
  const results = [];

  function walk(rootDir) {
    if (!rootDir || !fs.existsSync(rootDir)) return;
    const entries = fs.readdirSync(rootDir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(rootDir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && /\.(?:jsonl|jsonl\.zst|jsonl\.zstd)$/i.test(entry.name)) {
        const st = fs.statSync(full);
        const { sessionUuidFromPath, workspaceSlug } = extractDshPathHints(full);
        const meta = inspectDshSessionMetadata(full, st);
        if (!includeFiltered && !meta.isMainCompleted) {
          continue;
        }
        results.push({
          source_tool: 'dsh',
          session_id: sessionUuidFromPath,
          ...(workspaceSlug ? { workspace_slug: workspaceSlug } : {}),
          ...(meta.cwd ? { cwd: meta.cwd } : {}),
          ...(meta.filteredReason ? { filtered_reason: meta.filteredReason } : {}),
          has_companion_full: false,
          updated_at: new Date(st.mtimeMs).toISOString(),
          _internal_source_path: full
        });
      }
    }
  }

  walk(dshHome);
  return results;
}

function extractDshMessageContent(msgOrContent) {
  if (msgOrContent === null || msgOrContent === undefined) return null;
  if (typeof msgOrContent === 'string') return msgOrContent;
  if (Array.isArray(msgOrContent)) {
    const parts = [];
    for (const part of msgOrContent) {
      if (typeof part === 'string') parts.push(part);
      else if (part && typeof part === 'object') {
        if (typeof part.text === 'string') parts.push(part.text);
        else if (typeof part.content === 'string') parts.push(part.content);
        else if (typeof part.thinking === 'string') parts.push(`[thinking] ${part.thinking}`);
        else parts.push(JSON.stringify(part));
      }
    }
    return parts.join('\n');
  }
  if (typeof msgOrContent === 'object') {
    if ('content' in msgOrContent) return extractDshMessageContent(msgOrContent.content);
    if (typeof msgOrContent.text === 'string') return msgOrContent.text;
    return JSON.stringify(msgOrContent);
  }
  return String(msgOrContent);
}

/**
 * 规范化 DSH session.v4 事件结构
 * @param {object} parsedEvent
 * @param {number} eventId
 * @param {string | null} [workspaceSlug]
 */
export function normalizeDshEvent(parsedEvent, eventId, workspaceSlug = null) {
  const evType = parsedEvent?.type || 'unknown';
  const data = parsedEvent?.data && typeof parsedEvent.data === 'object' ? parsedEvent.data : {};

  let cwd = typeof parsedEvent?.cwd === 'string' ? parsedEvent.cwd : null;
  if (!cwd && typeof data.cwd === 'string') cwd = data.cwd;

  let role = parsedEvent?.role || data.role || null;
  let body = null;
  const toolCalls = [];

  if (evType === 'session') {
    role = 'system';
    body = `session v${parsedEvent.version ?? ''} id=${parsedEvent.id || ''} cwd=${parsedEvent.cwd || ''}`.trim();
  } else if (evType === 'user/message') {
    role = 'user';
    body = extractDshMessageContent(data.content ?? data.message);
  } else if (evType === 'assistant/message') {
    role = 'assistant';
    body = extractDshMessageContent(data.message ?? data.content);
  } else if (evType === 'system/message' || evType === 'developer/message') {
    role = 'system';
    body = extractDshMessageContent(data.message ?? data.content);
  } else if (evType === 'tool/call') {
    role = 'tool_use';
    const toolName = data.name || 'tool';
    const args = typeof data.arguments === 'string' ? data.arguments : JSON.stringify(data.arguments ?? {});
    toolCalls.push({ name: toolName, call_id: data.callId || null });
    body = `[${toolName}] ${args}`;
  } else if (evType === 'tool/result') {
    role = 'tool_result';
    body = extractDshMessageContent(data.message ?? data.result ?? data.content);
  } else if (evType === 'session/title') {
    role = 'system';
    body = `title: ${data.title || ''}`;
  } else if (evType === 'command/run' || evType === 'command/done') {
    role = 'system';
    body = `${evType}: ${JSON.stringify(data)}`;
  } else {
    body =
      parsedEvent?.content ??
      parsedEvent?.text ??
      parsedEvent?.output ??
      parsedEvent?.command ??
      extractDshMessageContent(data.content ?? data.message) ??
      JSON.stringify(parsedEvent);
  }

  let ts = parsedEvent?.timestamp || parsedEvent?.created_at || null;
  if (!ts && typeof parsedEvent?.time === 'number') {
    ts = new Date(parsedEvent.time).toISOString();
  } else if (!ts && typeof parsedEvent?.createdAt === 'number') {
    ts = new Date(parsedEvent.createdAt).toISOString();
  }

  return {
    type: evType,
    isKnownType: isKnownDshEventType(evType),
    role,
    timestamp: ts,
    content: body === null || body === undefined ? JSON.stringify(parsedEvent) : String(body),
    toolCalls,
    cwd,
    gitRoot: typeof parsedEvent?.git_root === 'string' ? parsedEvent.git_root : null,
    provenance: {
      source_tool: 'dsh',
      source_role: 'primary',
      primary_line: eventId,
      ...(workspaceSlug ? { workspace_slug: workspaceSlug } : {})
    }
  };
}
