import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { parseProposalContent, checkProposalReconcileState } from '../reconcile/engine.mjs';
import { sanitizeOutputText } from '../security/sanitizer.mjs';
import { verifyEgressApproval } from '../security/trusted-approvals.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { findMarkdownFiles } from '../storage/path-sanitizer.mjs';
import { callCloudProviderGateway } from '../providers/api-gateway.mjs';
import { queryVectorIndex } from './vector-index.mjs';
import { sanitizePayloadForExitA } from '../egress/egress-controller.mjs';
import {
  reserveCloudEgressBudget,
  reserveRunPlanBudgets,
  releasePrecheckFailedReservation
} from '../security/cloud-approvals.mjs';

export const DEFAULT_SEARCH_MODE = 'literal';

const RETRIEVAL_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /system\s+override/i,
  /bypass\s+(security|policy|approval|rules)/i,
  /忽略(?:以上|之前|所有)?(?:规则|指令)/,
  /(?:执行|运行|自动执行|自动运行).{0,12}(?:命令|脚本|shell|powershell|pwsh|export-egress)/i,
  /(?:读取|外发|上传|发送).{0,16}(?:raw\/|\.ssh|密钥|私钥|全部文件)/i,
  /\b(?:execSync|Invoke-Expression|Get-Content|rm\s+-rf|curl\s+http|mem\s+export-egress)\b/i
];

/**
 * 获取北京时间 (UTC+8) 当天日期字符串 YYYY-MM-DD (PLAN.md §8.1)
 * @param {Date} [date]
 * @returns {string}
 */
export function getBeijingTodayStr(date = new Date()) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(date);
}

function stringifyEnvValue(envVal) {
  if (!envVal) return '';
  if (typeof envVal === 'string') return envVal;
  if (typeof envVal === 'object') {
    return Object.entries(envVal)
      .map(([k, v]) => `${k}:${v}`)
      .join(' ');
  }
  return String(envVal);
}

function parseFrontmatter(content) {
  const { frontmatter, body } = parseMarkdownFrontmatter(content);
  const toList = (val) => (Array.isArray(val) ? val.map(v => String(v ?? '').trim()).filter(Boolean) : []);

  return {
    frontmatter: {
      id: frontmatter.id ?? null,
      schema_version: frontmatter.schema_version ?? null,
      note_type: frontmatter.note_type ?? null,
      title: frontmatter.title ?? null,
      project: frontmatter.project ?? null,
      privacy: frontmatter.privacy ?? null,
      source_tool: frontmatter.source_tool ?? null,
      derived_source_tools: toList(frontmatter.derived_source_tools),
      lifecycle: frontmatter.lifecycle ?? null,
      evidence_level: frontmatter.evidence_level ?? null,
      review_state: frontmatter.review_state ?? null,
      as_of: frontmatter.as_of ?? null,
      review_after: frontmatter.review_after ?? null,
      env: stringifyEnvValue(frontmatter.env) || null,
      aliases: toList(frontmatter.aliases),
      sources: toList(frontmatter.sources)
    },
    body
  };
}

/**
 * 构建 Vault 内证据链来源工具映射表 (10_Readable_Sessions + 20_Evidence_Cards)
 * 使 30_Knowledge_Notes 无需冗余手填 source_tool 即可通过 sources 链精确推导 derived_source_tools (§3.1, §5.1)
 */
function parseProposalFrontmatterForQueue(content) {
  return parseProposalContent(content);
}

/**
 * 单次安全扫描构建检索上下文（合并四目录读取、YAML 解析、提案映射、ID 计数与来源链接索引）
 * - 严格保留符号链接拦截与 boundaryDir 越界防护
 * - 预先一次性读取 SQLite notes / session_snapshots，避免热循环内重复 prepare/get
 * - 事件块锚点 (^event-NNNNNN) 采用按需懒解析并缓存，仅对最终进入结果集的来源触发读取
 */
function collectVaultSearchContext(vaultDir, db = null) {
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes');
  const queueDir = path.join(vaultDir, '40_Review_Queue');

  const sessionToolByKey = new Map();
  const evidenceSourcesByKey = new Map();
  const evidenceDirectToolByKey = new Map();
  const tokenToFiles = new Map();
  const tokenToFilesLower = new Map();
  const fileMetaByRel = new Map();
  const proposalsByTargetId = new Map();
  const managedIdCounts = new Map();
  const knowledgeDocs = [];
  const fileRawCache = new Map();

  const dbNoteById = new Map();
  const dbNoteByPath = new Map();
  const normFsPath = (p) => {
    const r = path.resolve(String(p || ''));
    return process.platform === 'win32' ? r.toLowerCase() : r;
  };

  if (db) {
    try {
      const noteRows = db.prepare('SELECT id, status, privacy, path FROM notes').all();
      for (const r of noteRows) {
        if (r.id) dbNoteById.set(r.id, r);
        if (r.path) dbNoteByPath.set(normFsPath(r.path), r);
      }
    } catch {
      // ignore if notes table missing in unit mock
    }
    try {
      const snapRows = db.prepare('SELECT session_id, source_tool, readable_session_path FROM session_snapshots').all();
      for (const r of snapRows) {
        if (r.source_tool) {
          const tool = String(r.source_tool).toLowerCase();
          if (r.session_id) sessionToolByKey.set(r.session_id, tool);
          if (r.readable_session_path) {
            sessionToolByKey.set(path.basename(r.readable_session_path, '.md'), tool);
            sessionToolByKey.set(path.basename(r.readable_session_path), tool);
          }
        }
      }
    } catch {
      // ignore
    }
  }

  const registerKeys = (map, filePath, fmId, value) => {
    const baseNoExt = path.basename(filePath, '.md');
    const baseWithExt = path.basename(filePath);
    map.set(baseNoExt, value);
    map.set(baseWithExt, value);
    if (fmId) map.set(fmId, value);
  };

  const addLookupToken = (tok, relPath) => {
    if (!tok) return;
    if (!tokenToFiles.has(tok)) tokenToFiles.set(tok, new Set());
    tokenToFiles.get(tok).add(relPath);
    const low = tok.toLowerCase();
    if (!tokenToFilesLower.has(low)) tokenToFilesLower.set(low, new Set());
    tokenToFilesLower.get(low).add(relPath);
  };

  const isDbNoteSanitizedActive = (fmId, filePath) => {
    if (!db) return true;
    const r = (fmId ? dbNoteById.get(fmId) : null) || (filePath ? dbNoteByPath.get(normFsPath(filePath)) : null);
    if (!r) return true;
    return r.status !== 'missing' && r.status !== 'deleted' && (!r.privacy || r.privacy === 'sanitized');
  };

  const indexGroups = ['10_Readable_Sessions', '20_Evidence_Cards', '30_Knowledge_Notes', '40_Review_Queue'];
  for (const dirGroup of indexGroups) {
    const groupDir = path.join(vaultDir, dirGroup);
    for (const fp of findMarkdownFiles(groupDir, { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir })) {
      try {
        const raw = fs.readFileSync(fp, 'utf8');
        const resolvedFp = path.resolve(fp);
        fileRawCache.set(resolvedFp, raw);

        let frontmatter;
        let body = '';
        if (dirGroup === '40_Review_Queue') {
          const propParsed = parseProposalFrontmatterForQueue(raw);
          frontmatter = {
            ...propParsed.frontmatter,
            sources: Array.isArray(propParsed.frontmatter?.sources) ? propParsed.frontmatter.sources : []
          };
          if (frontmatter.target_id) {
            if (!proposalsByTargetId.has(frontmatter.target_id)) {
              proposalsByTargetId.set(frontmatter.target_id, []);
            }
            proposalsByTargetId.get(frontmatter.target_id).push({
              propPath: fp,
              frontmatter
            });
          }
        } else {
          const parsed = parseFrontmatter(raw);
          frontmatter = parsed.frontmatter;
          body = parsed.body;
        }

        if (frontmatter && frontmatter.id) {
          managedIdCounts.set(frontmatter.id, (managedIdCounts.get(frontmatter.id) || 0) + 1);
        }

        const relPath = path.relative(vaultDir, fp).replace(/\\/g, '/');
        const relNoExt = relPath.endsWith('.md') ? relPath.slice(0, -3) : relPath;
        const baseWithExt = path.basename(fp);
        const baseNoExt = path.basename(fp, '.md');
        const prefixMatch = baseNoExt.match(/^((?:SES|EV|KN|PROP)-[0-9a-fA-F-]+)/);

        for (const tok of [relPath, relNoExt, baseWithExt, baseNoExt, frontmatter.id, prefixMatch?.[1]]) {
          addLookupToken(tok, relPath);
        }

        const allowed = frontmatter.privacy === 'sanitized' && isDbNoteSanitizedActive(frontmatter.id, fp);
        fileMetaByRel.set(relPath, { relPath, filePath: fp, dirGroup, frontmatter, allowed });

        if (dirGroup === '10_Readable_Sessions') {
          if (frontmatter.source_tool) {
            registerKeys(sessionToolByKey, fp, frontmatter.id, String(frontmatter.source_tool).toLowerCase());
          }
        } else if (dirGroup === '20_Evidence_Cards') {
          registerKeys(evidenceSourcesByKey, fp, frontmatter.id, frontmatter.sources || []);
          if (frontmatter.source_tool) {
            registerKeys(evidenceDirectToolByKey, fp, frontmatter.id, String(frontmatter.source_tool).toLowerCase());
          }
        } else if (dirGroup === '30_Knowledge_Notes') {
          knowledgeDocs.push({ filePath: fp, raw, frontmatter, body });
        }
      } catch {
        // ignore unreadable/unparseable markdown
      }
    }
  }

  function extractTargetTokensFromWikiLink(linkStr) {
    const clean = String(linkStr || '').replace(/^\[\[/, '').replace(/\]\]$/, '').split('|')[0].split('#')[0].trim();
    if (!clean) return [];
    const base = path.basename(clean);
    const noExt = base.endsWith('.md') ? base.slice(0, -3) : base;
    const prefixMatch = noExt.match(/^((?:SES|EV|KN|PROP)-[0-9a-fA-F-]+)/);
    return [clean, base, noExt, ...(prefixMatch ? [prefixMatch[1]] : [])];
  }

  function lookupUniqueVaultFile(targetPart) {
    const cleanTarget = String(targetPart || '').replace(/\\/g, '/').replace(/^\.\//, '').trim();
    if (!cleanTarget || cleanTarget.startsWith('/') || /^[A-Za-z]:/.test(cleanTarget)) {
      return null;
    }
    if (cleanTarget.split('/').includes('..')) {
      return null;
    }

    const candidates = [cleanTarget];
    if (cleanTarget.endsWith('.md')) candidates.push(cleanTarget.slice(0, -3));
    else candidates.push(`${cleanTarget}.md`);

    const exactMatches = new Set();
    for (const c of candidates) {
      const set = tokenToFiles.get(c);
      if (set) {
        for (const rel of set) exactMatches.add(rel);
      }
    }
    let matchedSet = exactMatches;
    if (matchedSet.size === 0 && process.platform === 'win32') {
      const lowerMatches = new Set();
      for (const c of candidates) {
        const set = tokenToFilesLower.get(c.toLowerCase());
        if (set) {
          for (const rel of set) lowerMatches.add(rel);
        }
      }
      matchedSet = lowerMatches;
    }

    if (matchedSet.size !== 1) {
      return null;
    }
    const [resolvedRel] = matchedSet;
    return fileMetaByRel.get(resolvedRel) || null;
  }

  const blockCountCache = new Map();
  function getEventBlockCounts(meta) {
    if (!meta) return null;
    if (blockCountCache.has(meta.relPath)) {
      return blockCountCache.get(meta.relPath);
    }
    const counts = new Map();
    try {
      const rawText = fileRawCache.get(path.resolve(meta.filePath)) ?? fs.readFileSync(meta.filePath, 'utf8');
      const { body } = parseMarkdownFrontmatter(rawText);
      const lines = String(body || '').split(/\r?\n/);
      let inFence = false;
      let fenceChar = '';
      let openFenceLen = 0;
      for (const line of lines) {
        if (!inFence) {
          const openMatch = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
          if (openMatch) {
            const char = openMatch[1][0];
            const info = openMatch[2] || '';
            if (char === '~' || !info.includes('`')) {
              inFence = true;
              fenceChar = char;
              openFenceLen = openMatch[1].length;
              continue;
            }
          }
        } else {
          const closeMatch = line.match(/^ {0,3}(`+|~+)\s*$/);
          if (closeMatch && closeMatch[1][0] === fenceChar && closeMatch[1].length >= openFenceLen) {
            inFence = false;
            fenceChar = '';
            openFenceLen = 0;
          }
          continue;
        }
        if (/^\s*>/.test(line)) continue;
        const anchorMatch = line.trim().match(/^(?:.*\s)?(\^event-\d+)$/i);
        if (anchorMatch && anchorMatch[1]) {
          const key = anchorMatch[1].toLowerCase();
          counts.set(key, (counts.get(key) || 0) + 1);
        }
      }
    } catch {
      // unreadable file -> keep empty map
    }
    blockCountCache.set(meta.relPath, counts);
    return counts;
  }

  function resolveVerifiedVaultLink(rawLink) {
    const stripped = String(rawLink || '').replace(/^\[\[/, '').replace(/\]\]$/, '').split('|')[0].trim();
    if (!stripped) return null;
    const hashIdx = stripped.indexOf('#');
    const targetPart = (hashIdx === -1 ? stripped : stripped.slice(0, hashIdx)).trim();
    const subpathPart = (hashIdx === -1 ? '' : stripped.slice(hashIdx + 1)).trim();
    if (!targetPart) return null;

    const meta = lookupUniqueVaultFile(targetPart);
    if (!meta || !meta.allowed) return null;

    if (subpathPart) {
      if (!/^\^event-\d+$/i.test(subpathPart)) {
        return null;
      }
      const blockCounts = getEventBlockCounts(meta);
      if (!blockCounts || blockCounts.get(subpathPart.toLowerCase()) !== 1) {
        return null;
      }
      return {
        link: sanitizeOutputText(`${meta.relPath}#${subpathPart}`),
        isEventAnchor: true,
        meta
      };
    }

    return {
      link: sanitizeOutputText(meta.relPath),
      isEventAnchor: false,
      meta
    };
  }

  const deriveSourceToolsForNote = function deriveSourceToolsForNote(frontmatter) {
    const tools = new Set();
    if (frontmatter.source_tool) {
      tools.add(String(frontmatter.source_tool).toLowerCase());
    }
    for (const t of frontmatter.derived_source_tools || []) {
      if (t) tools.add(String(t).toLowerCase());
    }

    for (const srcLink of frontmatter.sources || []) {
      const tokens = extractTargetTokensFromWikiLink(srcLink);
      for (const tok of tokens) {
        if (sessionToolByKey.has(tok)) {
          tools.add(sessionToolByKey.get(tok));
        }
        if (evidenceDirectToolByKey.has(tok)) {
          tools.add(evidenceDirectToolByKey.get(tok));
        }
        if (evidenceSourcesByKey.has(tok)) {
          const evLinks = evidenceSourcesByKey.get(tok) || [];
          for (const evLink of evLinks) {
            for (const subTok of extractTargetTokensFromWikiLink(evLink)) {
              if (sessionToolByKey.has(subTok)) {
                tools.add(sessionToolByKey.get(subTok));
              }
            }
          }
        }
      }
    }

    return [...tools];
  };

  deriveSourceToolsForNote.deriveOpenableLinks = function deriveOpenableLinks(frontmatter) {
    const eventAnchors = new Set();
    const openableLinks = new Set();
    for (const srcLink of frontmatter.sources || []) {
      const direct = resolveVerifiedVaultLink(srcLink);
      if (!direct) continue;
      openableLinks.add(direct.link);
      if (direct.isEventAnchor) {
        eventAnchors.add(direct.link);
      }
      if (direct.meta.dirGroup === '20_Evidence_Cards') {
        for (const evLink of direct.meta.frontmatter.sources || []) {
          const indirect = resolveVerifiedVaultLink(evLink);
          if (!indirect) continue;
          openableLinks.add(indirect.link);
          if (indirect.isEventAnchor) {
            eventAnchors.add(indirect.link);
          }
        }
      }
    }
    return {
      eventAnchors: [...eventAnchors],
      openableLinks: [...openableLinks]
    };
  };

  deriveSourceToolsForNote.deriveEventAnchors = function deriveEventAnchors(frontmatter) {
    return deriveSourceToolsForNote.deriveOpenableLinks(frontmatter).eventAnchors;
  };

  return {
    notesDir,
    queueDir,
    proposalsByTargetId,
    managedIdCounts,
    knowledgeDocs,
    fileRawCache,
    dbNoteById,
    dbNoteByPath,
    deriveSourceToolsForNote
  };
}

/**
 * 中英混合字面＋二元分词器（用于 Mode 1 混合检索可重建索引与相似度打分）
 */
function tokenizeForHybrid(text) {
  const clean = String(text || '').toLowerCase();
  const tokens = [];
  // 1. ASCII 词/数字/带连字符参数
  const asciiMatches = clean.match(/[a-z0-9_.:/=-]+/g) || [];
  for (const t of asciiMatches) {
    tokens.push(t);
  }
  // 2. 中文单字与双字切片 (确保 1-2 字短词与长句均可召回)
  const cjkRuns = clean.match(/[\u4e00-\u9fff]+/g) || [];
  for (const run of cjkRuns) {
    for (let i = 0; i < run.length; i++) {
      tokens.push(run[i]);
      if (i + 1 < run.length) {
        tokens.push(run.slice(i, i + 2));
      }
    }
  }
  return tokens;
}

function computeCosineSimilarity(tokensA, tokensB) {
  if (tokensA.length === 0 || tokensB.length === 0) return 0;
  const freqA = new Map();
  const freqB = new Map();
  for (const t of tokensA) freqA.set(t, (freqA.get(t) || 0) + 1);
  for (const t of tokensB) freqB.set(t, (freqB.get(t) || 0) + 1);

  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (const [t, c] of freqA) {
    normA += c * c;
    if (freqB.has(t)) {
      dot += c * freqB.get(t);
    }
  }
  for (const c of freqB.values()) {
    normB += c * c;
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

function extractMatchSnippet(body, queryTerms) {
  if (!body) return '';
  const lines = body.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (queryTerms.some(term => lower.includes(term))) {
      return line.slice(0, 180);
    }
  }
  return lines.slice(0, 2).join(' ').slice(0, 180);
}

function hasInjectionSignal(text) {
  if (!text) return false;
  return RETRIEVAL_INJECTION_PATTERNS.some(re => re.test(text));
}

/**
 * 构建或重建可丢弃的本地检索索引 (runtime/index/lexical-index.json)
 * 严格排除 90_Templates/ 与非 sanitized 笔记
 * @param {{ vaultDir: string, indexDir: string }} params
 * @returns {{ indexPath: string, indexedCount: number }}
 */
export function buildLocalSearchIndex({ vaultDir, indexDir }) {
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes');
  const files = findMarkdownFiles(notesDir, { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir });
  const docs = [];

  for (const filePath of files) {
    if (filePath.replace(/\\/g, '/').includes('90_Templates/')) continue;
    const raw = fs.readFileSync(filePath, 'utf8');
    const { frontmatter, body } = parseFrontmatter(raw);
    if (frontmatter.privacy !== 'sanitized') continue;

    const fullText = [frontmatter.title || '', ...(frontmatter.aliases || []), frontmatter.env || '', body || ''].join('\n');
    const docSha256 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
    docs.push({
      id: frontmatter.id,
      project: frontmatter.project,
      title: sanitizeOutputText(frontmatter.title || ''),
      path: filePath,
      doc_sha256: docSha256,
      tokens: tokenizeForHybrid(sanitizeOutputText(fullText))
    });
  }

  if (!fs.existsSync(indexDir)) {
    fs.mkdirSync(indexDir, { recursive: true });
  }
  const indexPath = path.join(indexDir, 'lexical-index.json');
  fs.writeFileSync(
    indexPath,
    JSON.stringify({
      built_at: new Date().toISOString(),
      doc_count: docs.length,
      docs
    }, null, 2),
    'utf8'
  );

  return { indexPath, indexedCount: docs.length };
}

function validateRerankOrderedIds(orderedIds, candidateIdSet) {
  if (!Array.isArray(orderedIds)) {
    return { valid: false, reason: 'not_array' };
  }
  if (candidateIdSet.size > 0 && orderedIds.length === 0) {
    return { valid: false, reason: 'empty_array' };
  }
  const seen = new Set();
  for (const id of orderedIds) {
    if (typeof id !== 'string' || !id.trim()) {
      return { valid: false, reason: 'invalid_id_entry' };
    }
    if (!candidateIdSet.has(id)) {
      return { valid: false, reason: 'out_of_candidate_set' };
    }
    if (seen.has(id)) {
      return { valid: false, reason: 'duplicate_id' };
    }
    seen.add(id);
  }
  return { valid: true, reason: null };
}

function sameFsPath(a, b) {
  if (!a || !b) return false;
  const ra = path.resolve(a);
  const rb = path.resolve(b);
  return process.platform === 'win32' ? ra.toLowerCase() === rb.toLowerCase() : ra === rb;
}

function evaluateNoteChannelAndSafety({
  db,
  filePath,
  frontmatter,
  body,
  noteRow,
  managedIdCounts,
  proposalsByTargetId,
  env,
  todayStr,
  queryTerms
}) {
  const effectiveToday = todayStr || getBeijingTodayStr();
  const lowerEnv = (frontmatter.env || '').toLowerCase();
  let actionable = true;
  let reason = null;
  const reviewDate = frontmatter.review_after ? String(frontmatter.review_after).slice(0, 10) : null;
  const hasDuplicateId = Boolean(frontmatter.id && (managedIdCounts.get(frontmatter.id) || 0) > 1);

  if (hasDuplicateId) {
    actionable = false;
    reason = 'duplicate_id_conflict';
  } else if (db && (!frontmatter.id || !noteRow)) {
    actionable = false;
    reason = 'unregistered_note_pending_enrollment';
  } else if (db && noteRow && noteRow.path && !sameFsPath(noteRow.path, filePath) && fs.existsSync(noteRow.path)) {
    actionable = false;
    reason = 'note_path_mismatch_pending_reconcile';
  } else if (frontmatter.lifecycle !== 'active') {
    actionable = false;
    reason = `lifecycle: ${frontmatter.lifecycle}`;
  } else if (frontmatter.review_state !== 'accepted') {
    actionable = false;
    reason = `review_state: ${frontmatter.review_state}`;
  } else if (reviewDate && /^\d{4}-\d{2}-\d{2}$/.test(reviewDate) && reviewDate <= effectiveToday) {
    actionable = false;
    reason = `review_expired: ${frontmatter.review_after}`;
  } else if (env && lowerEnv && !lowerEnv.includes(String(env).toLowerCase())) {
    actionable = false;
    reason = `env_mismatch: note=${frontmatter.env}, requested=${env}`;
  }

  const targetProposals = proposalsByTargetId.get(frontmatter.id) || [];
  for (const prop of targetProposals) {
    const pFm = prop.frontmatter;
    if (pFm.id && (managedIdCounts.get(pFm.id) || 0) > 1) {
      actionable = false;
      reason = 'duplicate_proposal_id_conflict';
      break;
    }
    const isConflictOrSupersede = pFm.proposal_kind === 'conflict' || pFm.proposal_kind === 'supersede' || !pFm.proposal_kind;
    if (!isConflictOrSupersede) continue;

    if (pFm.proposal_status === 'rejected' || pFm.proposal_status === 'obsolete') {
      continue;
    }

    if (pFm.proposal_status === 'accepted') {
      const check = checkProposalReconcileState({
        db,
        proposalPath: prop.propPath,
        targetPath: filePath
      });

      const isVerified = check.reconcile_state === 'verified_applied' || check.reconcile_state === 'user_confirmed_rewrite';
      if (!isVerified) {
        actionable = false;
        reason = `reconcile_state: ${check.reconcile_state} (reason: ${check.reason || 'unverified'})`;
        break;
      }
    } else {
      actionable = false;
      reason = pFm.proposal_status === 'pending'
        ? `pending_${pFm.proposal_kind || 'conflict'}_proposal`
        : `unsettled_${pFm.proposal_kind || 'conflict'}_proposal:${pFm.proposal_status || 'missing'}`;
      break;
    }
  }

  const rawSnippet = extractMatchSnippet(body, queryTerms);
  const safeTitle = sanitizeOutputText(frontmatter.title || '');
  const safeSnippet = sanitizeOutputText(rawSnippet);
  const safeReason = reason ? sanitizeOutputText(reason) : null;
  const injectionDetected = hasInjectionSignal(frontmatter.title) || hasInjectionSignal(rawSnippet) || hasInjectionSignal(body);

  return {
    actionable,
    reason: safeReason,
    safeTitle,
    safeSnippet,
    injectionDetected
  };
}

/**
 * 知识笔记检索（Mode 0 默认字面匹配 + Mode 1 混合 + Mode 2 重排序 + 双通道分层 + 全通道脱敏）
 * @param {{
 *   db: any,
 *   approvalDb?: any,
 *   vaultDir: string,
 *   query: string,
 *   project?: string,
 *   todayStr?: string,
 *   mode?: 'literal' | 'hybrid' | 'rerank',
 *   topK?: number,
 *   indexDir?: string,
 *   egressApprovalId?: string,
 *   provider?: string,
 *   externalRerankFn?: (params: { query: string, candidates: Array<object> }) => Array<string>
 * }} params
 */
export function searchKnowledge({
  db,
  approvalDb = null,
  vaultDir,
  query,
  project,
  sourceTool = null,
  env = null,
  todayStr = getBeijingTodayStr(),
  mode = DEFAULT_SEARCH_MODE,
  topK = 20,
  indexDir = null,
  egressApprovalId = null,
  egressSnapshotId = 'benchmark-or-search',
  provider = 'local',
  externalRerankFn = null
}) {
  const effectiveQuery = String(query || '').trim();
  if (!effectiveQuery) {
    return {
      mode,
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      noAnswer: true,
      fallbackUsed: false,
      fallbackReason: null,
      egressBytes: 0,
      items: []
    };
  }

  const effApprovalDb = approvalDb || db;
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes');
  const queueDir = path.join(vaultDir, '40_Review_Queue');

  const matched = [];
  const normalizedSourceFilter = sourceTool && String(sourceTool).toLowerCase() !== 'all'
    ? String(sourceTool).trim().toLowerCase()
    : null;

  const lowerQuery = effectiveQuery.toLowerCase();
  const queryTerms = lowerQuery.split(/\s+/).filter(Boolean);
  const queryTokens = tokenizeForHybrid(effectiveQuery);

  let activeMode = mode || DEFAULT_SEARCH_MODE;
  let fallbackUsed = false;
  let fallbackReason = null;
  let egressBytes = 0;

  // 若使用外部重排器，强制检查 Exit A 批准凭据；失败时安全回退至 Mode 0 (literal)
  let canRunExternalRerank = false;
  if (activeMode === 'rerank' && externalRerankFn) {
    if (!effApprovalDb || !egressApprovalId) {
      activeMode = 'literal';
      fallbackUsed = true;
      fallbackReason = 'missing_egress_approval_fallback_to_mode0';
    } else {
      const check = verifyEgressApproval({
        db: effApprovalDb,
        egressApprovalId,
        snapshotId: egressSnapshotId,
        provider,
        purpose: 'rerank'
      });
      if (!check.valid) {
        activeMode = 'literal';
        fallbackUsed = true;
        fallbackReason = `egress_denied_${check.reason}_fallback_to_mode0`;
      } else {
        canRunExternalRerank = true;
      }
    }
  }

  // 加载可重建索引（Mode 1 / 2 可用）
  const indexDocsById = new Map();
  if ((activeMode === 'hybrid' || activeMode === 'rerank') && indexDir) {
    const idxFile = path.join(indexDir, 'lexical-index.json');
    if (fs.existsSync(idxFile)) {
      try {
        const parsedIdx = JSON.parse(fs.readFileSync(idxFile, 'utf8'));
        for (const d of parsedIdx.docs || []) {
          if (d && d.id) {
            indexDocsById.set(d.id, {
              docSha256: typeof d.doc_sha256 === 'string' ? d.doc_sha256 : null,
              tokens: Array.isArray(d.tokens) ? d.tokens : null
            });
          }
        }
      } catch {
        // 忽略损坏的可重建索引，即时回退现场分词
      }
    }
  }

  // 1. 单次安全扫描全库上下文（同时构建提案映射、ID 计数、DB 状态映射与来源链接索引）
  const {
    proposalsByTargetId,
    managedIdCounts,
    knowledgeDocs,
    dbNoteById,
    deriveSourceToolsForNote
  } = collectVaultSearchContext(vaultDir, db);
  const effectiveTodayStr = todayStr || getBeijingTodayStr();

  for (const { filePath, raw, frontmatter, body } of knowledgeDocs) {
    // Exit B 铁律 (§3.2): 仅允许 privacy === 'sanitized' 进入任何返回通道；local_only / 缺失 / 非法一律剥离
    if (frontmatter.privacy !== 'sanitized') {
      continue;
    }

    // 检查 SQLite notes 表状态与真实隐私登记 (O(1) 内存映射查表，防止通过篡改 YAML privacy 绕过 Exit B)
    let noteRow = null;
    if (db) {
      if (frontmatter.id) {
        noteRow = dbNoteById.get(frontmatter.id) || null;
      }
      if (noteRow && (noteRow.status === 'missing' || noteRow.status === 'deleted' || (noteRow.privacy && noteRow.privacy !== 'sanitized'))) {
        continue;
      }
    }

    // 项目过滤（防跨项目误用 C01）
    if (project && frontmatter.project !== project) {
      continue;
    }

    // 证据链来源工具推导与 --source 过滤 (§3.1, §5.1)
    const derivedSourceTools = deriveSourceToolsForNote(frontmatter);
    if (normalizedSourceFilter && !derivedSourceTools.includes(normalizedSourceFilter)) {
      continue;
    }

    const lowerTitle = (frontmatter.title || '').toLowerCase();
    const lowerAliases = (frontmatter.aliases || []).map(a => a.toLowerCase());
    const lowerBody = (body || '').toLowerCase();
    const lowerEnv = (frontmatter.env || '').toLowerCase();
    const combinedLower = `${lowerTitle}\n${lowerAliases.join('\n')}\n${lowerEnv}\n${lowerBody}`;

    // Mode 0 精确字面子串匹配 + 多词 AND 匹配 (保留短词如 "启动"/"IP"/"401" 及带标点参数)
    const exactInTitle = lowerTitle.includes(lowerQuery);
    const exactInAlias = lowerAliases.some(a => a.includes(lowerQuery));
    const exactInBody = lowerBody.includes(lowerQuery) || lowerEnv.includes(lowerQuery);
    const allTermsMatch = queryTerms.length > 1 && queryTerms.every(term => combinedLower.includes(term));

    let literalScore = 0;
    if (exactInTitle) literalScore += 10;
    if (exactInAlias) literalScore += 8;
    if (exactInBody) literalScore += 4;
    if (!exactInTitle && !exactInAlias && !exactInBody && allTermsMatch) {
      literalScore += 3;
    }

    let hybridScore = 0;
    if (activeMode === 'hybrid' || activeMode === 'rerank') {
      const cachedEntry = frontmatter.id ? indexDocsById.get(frontmatter.id) : null;
      const rawSha256 = cachedEntry?.docSha256
        ? crypto.createHash('sha256').update(raw, 'utf8').digest('hex')
        : null;
      const useCachedTokens = Boolean(
        cachedEntry &&
        cachedEntry.docSha256 &&
        cachedEntry.docSha256 === rawSha256 &&
        Array.isArray(cachedEntry.tokens)
      );
      const liveFullText = [frontmatter.title || '', ...(frontmatter.aliases || []), frontmatter.env || '', body || ''].join('\n');
      const docTokens = useCachedTokens ? cachedEntry.tokens : tokenizeForHybrid(sanitizeOutputText(liveFullText));
      hybridScore = computeCosineSimilarity(queryTokens, docTokens) * 10;
    }

    const totalScore = activeMode === 'literal'
      ? literalScore
      : literalScore * 1.2 + hybridScore;

    if (activeMode === 'literal' && literalScore === 0) {
      continue;
    }
    if ((activeMode === 'hybrid' || activeMode === 'rerank') && literalScore === 0 && hybridScore < 1.2) {
      continue;
    }

    // 2-4. 双通道判定 (Channel 1 vs Channel 2) + 关联提案哈希校验 + Exit B 实时脱敏 + C03 检索期防注入边界
    const {
      actionable,
      reason: safeReason,
      safeTitle,
      safeSnippet,
      injectionDetected
    } = evaluateNoteChannelAndSafety({
      db,
      filePath,
      frontmatter,
      body,
      noteRow,
      managedIdCounts,
      proposalsByTargetId,
      env,
      todayStr: effectiveTodayStr,
      queryTerms
    });

    matched.push({
      id: frontmatter.id,
      title: safeTitle,
      project: frontmatter.project,
      derived_source_tools: derivedSourceTools,
      path: filePath,
      actionable,
      reason: safeReason,
      lifecycle: frontmatter.lifecycle,
      review_state: frontmatter.review_state,
      sources: (frontmatter.sources || []).map(s => sanitizeOutputText(s)),
      _frontmatter: frontmatter,
      snippet: safeSnippet,
      score: Number(totalScore.toFixed(4)),
      trustBoundary: 'untrusted_memory_data',
      injectionDetected
    });
  }

  // 默认排序：Channel 1 (actionable: true) 优先，其次按匹配分降序
  matched.sort((a, b) => {
    if (a.actionable !== b.actionable) return a.actionable ? -1 : 1;
    return b.score - a.score;
  });

  // Mode 2 结构化重排序或受控外部 API 重排
  if (activeMode === 'rerank' && matched.length > 0) {
    if (canRunExternalRerank && externalRerankFn) {
      try {
        const candidatesPayload = matched.slice(0, Math.max(topK, 10)).map(m => ({
          id: m.id,
          title: m.title,
          snippet: m.snippet
        }));
        const candidateIdSet = new Set(candidatesPayload.map(c => c.id));
        egressBytes = Buffer.byteLength(JSON.stringify({ query: sanitizeOutputText(effectiveQuery), candidates: candidatesPayload }), 'utf8');
        const orderedIds = externalRerankFn({ query: sanitizeOutputText(effectiveQuery), candidates: candidatesPayload });
        const validation = validateRerankOrderedIds(orderedIds, candidateIdSet);
        if (!validation.valid) {
          const literalFallback = searchKnowledge({
            db,
            approvalDb,
            vaultDir,
            query: effectiveQuery,
            project,
            sourceTool,
            env,
            todayStr,
            mode: 'literal',
            topK,
            indexDir: null
          });
          return {
            ...literalFallback,
            mode: 'literal',
            dailyDefaultMode: DEFAULT_SEARCH_MODE,
            fallbackUsed: true,
            fallbackReason: `invalid_rerank_output_fallback_to_mode0:${validation.reason}`,
            egressBytes
          };
        }
        const rankMap = new Map(orderedIds.map((id, i) => [id, i]));
        matched.sort((a, b) => {
          if (a.actionable !== b.actionable) return a.actionable ? -1 : 1;
          const ra = rankMap.has(a.id) ? rankMap.get(a.id) : Number.MAX_SAFE_INTEGER;
          const rb = rankMap.has(b.id) ? rankMap.get(b.id) : Number.MAX_SAFE_INTEGER;
          if (ra !== rb) return ra - rb;
          return b.score - a.score;
        });
      } catch (err) {
        const literalFallback = searchKnowledge({
          db,
          approvalDb,
          vaultDir,
          query: effectiveQuery,
          project,
          sourceTool,
          env,
          todayStr,
          mode: 'literal',
          topK,
          indexDir: null
        });
        return {
          ...literalFallback,
          mode: 'literal',
          dailyDefaultMode: DEFAULT_SEARCH_MODE,
          fallbackUsed: true,
          fallbackReason: `external_rerank_error_fallback_to_mode0:${sanitizeOutputText(err.message)}`,
          egressBytes
        };
      }
    } else {
      // 本地确定性重排：标题完全命中与命令参数密度加权
      matched.sort((a, b) => {
        if (a.actionable !== b.actionable) return a.actionable ? -1 : 1;
        const boostA = a.title.toLowerCase().includes(lowerQuery) ? 2 : 0;
        const boostB = b.title.toLowerCase().includes(lowerQuery) ? 2 : 0;
        return (b.score + boostB) - (a.score + boostA);
      });
    }
  }

  const sliced = matched.slice(0, topK).map(({ _frontmatter, ...item }) => {
    const { eventAnchors, openableLinks } = deriveSourceToolsForNote.deriveOpenableLinks(_frontmatter);
    return {
      ...item,
      event_anchors: eventAnchors,
      openable_links: openableLinks
    };
  });

  return {
    mode: activeMode,
    dailyDefaultMode: DEFAULT_SEARCH_MODE,
    noAnswer: sliced.length === 0,
    fallbackUsed,
    fallbackReason,
    egressBytes,
    items: sliced
  };
}

function estimateTokenBudget(text) {
  const bytes = Buffer.byteLength(String(text || ''), 'utf8');
  return Math.max(16, bytes + 8);
}

function buildActionableStatusForFile({
  db,
  vaultDir,
  deriveSourceToolsForNote,
  filePath,
  parsed,
  project,
  sourceTool,
  env,
  todayStr,
  managedIdCounts,
  proposalsByTargetId,
  queryTerms = []
}) {
  const fm = parsed?.frontmatter || {};
  if (fm.privacy !== 'sanitized') {
    return null;
  }
  if (project && fm.project !== project) {
    return null;
  }
  const derivedSourceTools = deriveSourceToolsForNote ? deriveSourceToolsForNote(fm) : [];
  if (sourceTool && !derivedSourceTools.includes(String(sourceTool).trim().toLowerCase())) {
    return null;
  }

  const noteRow = db && fm.id
    ? db.prepare('SELECT id, status, privacy, path FROM notes WHERE id = ?').get(fm.id) || null
    : null;
  if (noteRow && (noteRow.status !== 'active' || noteRow.privacy !== 'sanitized')) {
    return null;
  }

  const evaluated = evaluateNoteChannelAndSafety({
    db,
    filePath,
    frontmatter: fm,
    body: parsed?.body || '',
    noteRow,
    managedIdCounts,
    proposalsByTargetId,
    env,
    todayStr: todayStr || getBeijingTodayStr(),
    queryTerms
  });

  const derivedLinks = deriveSourceToolsForNote?.deriveOpenableLinks
    ? deriveSourceToolsForNote.deriveOpenableLinks(fm)
    : { eventAnchors: [], openableLinks: [] };

  return {
    id: fm.id || null,
    title: evaluated.safeTitle || sanitizeOutputText(path.basename(filePath, '.md')),
    project: fm.project || null,
    derived_source_tools: derivedSourceTools,
    path: filePath,
    actionable: evaluated.actionable,
    reason: evaluated.reason,
    lifecycle: fm.lifecycle || null,
    review_state: fm.review_state || null,
    sources: (fm.sources || []).map((s) => sanitizeOutputText(s)),
    event_anchors: derivedLinks.eventAnchors,
    openable_links: derivedLinks.openableLinks,
    snippet: evaluated.safeSnippet,
    trustBoundary: 'untrusted_memory_data',
    injectionDetected: evaluated.injectionDetected
  };
}

function createMode0FallbackRunner({
  db,
  approvalDb,
  vaultDir,
  query,
  project,
  sourceTool,
  env,
  effectiveTodayStr,
  topK
}) {
  return (fallbackReason, extra = {}) => {
    const mode0 = searchKnowledge({
      db,
      approvalDb,
      vaultDir,
      query,
      project,
      sourceTool,
      env,
      todayStr: effectiveTodayStr,
      mode: 'literal',
      topK,
      indexDir: null
    });
    return {
      ...mode0,
      mode: 'literal',
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      fallbackUsed: true,
      fallbackReason: sanitizeOutputText(String(fallbackReason)),
      cloudUsed: false,
      ...extra
    };
  };
}

function buildSafeReleaseReservationFn(operatorDb, reservation) {
  return () => {
    if (reservation) {
      try {
        releasePrecheckFailedReservation(operatorDb, {
          requestId: reservation.requestId
        });
      } catch {
        // Best-effort release if not already settled/released/retained
      }
    }
  };
}

async function executeCloudRerankOnCandidates({
  db,
  operatorDb,
  rerankApprovalId,
  rerankReservation,
  runPlanId,
  provider,
  rerankModel,
  baseUrl,
  resolvedRerankEndpoint,
  apiKeyProvider,
  vaultId,
  dataId,
  safeQueryText,
  channel1Candidates,
  channel2Candidates,
  overallDeadlineMs,
  startedAt,
  initialEgressBytes = 0,
  topK,
  resultMode = 'rerank',
  spaceId = null,
  invalidatedDocs = [],
  testContext = false,
  sentinelReport = null,
  fetchFn = globalThis.fetch,
  releaseUnusedRerank,
  fallbackToMode0
}) {
  let egressBytes = initialEgressBytes;
  const queryBudget = estimateTokenBudget(safeQueryText);
  const availableDocTokens = Math.max(0, rerankReservation.reservedInputTokens - queryBudget);
  const submittedChannel1 = [];
  const unsubmittedChannel1 = [];
  let usedDocTokens = 0;

  for (const item of channel1Candidates) {
    const docTokens = estimateTokenBudget(`${item.title}\n${item.snippet}`);
    if (usedDocTokens + docTokens <= availableDocTokens) {
      usedDocTokens += docTokens;
      submittedChannel1.push(item);
    } else {
      unsubmittedChannel1.push(item);
    }
  }

  if (submittedChannel1.length === 0) {
    releaseUnusedRerank();
    if (channel1Candidates.length > 0) {
      return fallbackToMode0('rerank_budget_insufficient_fallback_to_mode0', { egressBytes });
    }
    const sliced = channel2Candidates.slice(0, topK);
    return {
      mode: resultMode,
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      noAnswer: sliced.length === 0,
      fallbackUsed: false,
      fallbackReason: null,
      cloudUsed: false,
      spaceId,
      invalidatedDocs,
      egressBytes,
      items: sliced
    };
  }

  try {
    const remainingMsBeforeRerank = overallDeadlineMs - (Date.now() - startedAt);
    if (remainingMsBeforeRerank <= 0) {
      releaseUnusedRerank();
      return fallbackToMode0('overall_deadline_exceeded_fallback_to_mode0', { egressBytes });
    }

    // Rerank payload strictly includes registered sanitized Channel 1 notes; ZERO Channel 2, ZERO unregistered notes, ZERO UUIDs or paths
    const sanitizedDocs = sanitizePayloadForExitA({
      db,
      requireRegisteredSanitized: true,
      items: submittedChannel1.map((item, idx) => ({
        noteId: item.id,
        privacy: 'sanitized',
        ephemeralId: idx,
        text: `${item.title}\n${item.snippet}`
      })),
      allowedFields: ['ephemeralId', 'text']
    });
    egressBytes += sanitizedDocs.egressBytes;

    const remainingMs = overallDeadlineMs - (Date.now() - startedAt);
    if (remainingMs <= 0) {
      releaseUnusedRerank();
      return fallbackToMode0('overall_deadline_exceeded_fallback_to_mode0', { egressBytes });
    }

    const rerankCallRes = await callCloudProviderGateway({
      operatorDb,
      cloudApprovalId: rerankApprovalId,
      runPlanId,
      preReserved: rerankReservation,
      provider,
      modelId: rerankModel,
      purpose: 'rerank',
      baseUrl,
      endpointUrl: resolvedRerankEndpoint,
      requiresQueryEgress: true,
      apiKeyProvider,
      vaultId,
      dataId,
      payloadInput: {
        query: safeQueryText,
        documents: sanitizedDocs.sanitizedItems.map((d) => d.text),
        topN: Math.min(topK, sanitizedDocs.sanitizedItems.length)
      },
      reservedInputTokens: rerankReservation.reservedInputTokens,
      maxOutputTokens: 0,
      overallDeadlineMs: remainingMs,
      testContext,
      sentinelReport,
      fetchFn
    });

    const orderedIndices = rerankCallRes.parsed.orderedIndices;
    const rerankedPrefix = orderedIndices.map((idx) => submittedChannel1[idx]);
    const reordered = [...rerankedPrefix, ...unsubmittedChannel1, ...channel2Candidates];
    const sliced = reordered.slice(0, topK);
    return {
      mode: resultMode,
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      noAnswer: sliced.length === 0,
      fallbackUsed: false,
      fallbackReason: null,
      cloudUsed: true,
      spaceId,
      invalidatedDocs,
      egressBytes,
      items: sliced
    };
  } catch (err) {
    releaseUnusedRerank();
    return fallbackToMode0(`cloud_rerank_failed:${err.code || err.message}`, { egressBytes });
  }
}

export async function searchKnowledgeAsync({
  db = null,
  approvalDb = null,
  vaultDir,
  query,
  project = null,
  sourceTool = null,
  env = null,
  todayStr = getBeijingTodayStr(),
  mode = DEFAULT_SEARCH_MODE,
  topK = 10,
  indexDir = null,
  cloudConfig = null
} = {}) {
  const effectiveTodayStr = todayStr || getBeijingTodayStr();
  const effectiveMode = mode || DEFAULT_SEARCH_MODE;
  if (effectiveMode === 'literal' || !cloudConfig) {
    return searchKnowledge({
      db,
      approvalDb,
      vaultDir,
      query,
      project,
      sourceTool,
      env,
      todayStr: effectiveTodayStr,
      mode: effectiveMode === 'semantic' ? 'literal' : effectiveMode,
      topK,
      indexDir
    });
  }

  const startedAt = Date.now();
  const parsedDeadline = Number(cloudConfig.overallDeadlineMs);
  const overallDeadlineMs = Number.isFinite(parsedDeadline) ? Math.max(1, parsedDeadline) : 4000;
  const runPlanId = `run-${crypto.randomUUID()}`;
  const {
    operatorDb,
    embedApprovalId = null,
    rerankApprovalId = null,
    provider = 'siliconflow',
    embedModel = 'BAAI/bge-m3',
    rerankModel = 'BAAI/bge-reranker-v2-m3',
    baseUrl = null,
    embedEndpointUrl = null,
    rerankEndpointUrl = null,
    apiKeyProvider,
    vaultId,
    dataId,
    vectorsDbPath,
    testContext = false,
    sentinelReport = null,
    fetchFn = globalThis.fetch
  } = cloudConfig;

  const cleanBaseUrl = typeof baseUrl === 'string' ? baseUrl.trim().replace(/\/+$/, '') : null;
  const resolvedEmbedEndpoint = embedEndpointUrl || (cleanBaseUrl ? `${cleanBaseUrl}/v1/embeddings` : null);
  const resolvedRerankEndpoint = rerankEndpointUrl || (cleanBaseUrl ? `${cleanBaseUrl}/v1/rerank` : null);

  const fallbackToMode0 = createMode0FallbackRunner({
    db,
    approvalDb,
    vaultDir,
    query,
    project,
    sourceTool,
    env,
    effectiveTodayStr,
    topK
  });

  if (!operatorDb || !embedApprovalId || !vectorsDbPath) {
    return fallbackToMode0('missing_cloud_config_fallback_to_mode0');
  }

  let sanitizedQueryRes;
  try {
    sanitizedQueryRes = sanitizePayloadForExitA({
      db,
      requireRegisteredSanitized: false,
      items: [{ kind: 'query', text: String(query || '') }],
      allowedFields: ['text']
    });
  } catch (err) {
    return fallbackToMode0(`exit_a_query_blocked:${err.code || err.message}`);
  }
  const safeQueryText = sanitizedQueryRes.sanitizedItems[0]?.text || '';
  if (!safeQueryText.trim()) {
    return fallbackToMode0('empty_sanitized_query_fallback_to_mode0');
  }

  const embedStageReqId = `req-${crypto.randomUUID()}`;
  const rerankStageReqId = rerankApprovalId ? `req-${crypto.randomUUID()}` : null;

  const stages = [
    {
      cloudApprovalId: embedApprovalId,
      requestId: embedStageReqId,
      provider,
      modelId: embedModel,
      purpose: 'embed_query',
      endpointUrl: resolvedEmbedEndpoint,
      requiresQueryEgress: true,
      reservedInputTokens: estimateTokenBudget(safeQueryText),
      maxOutputTokens: 0
    }
  ];

  // Literal candidates fetched locally first so rerank token budget can be cleanly bounded
  const maxRerankPoolSize = Math.max(topK * 3, 20);
  const literalPool = searchKnowledge({
    db,
    approvalDb,
    vaultDir,
    query,
    project,
    sourceTool,
    env,
    todayStr: effectiveTodayStr,
    mode: 'literal',
    topK: maxRerankPoolSize,
    indexDir: null
  });

  if (rerankApprovalId) {
    let registeredSanitizedCount = 0;
    if (db) {
      try {
        registeredSanitizedCount = Number(
          db.prepare("SELECT COUNT(*) AS c FROM notes WHERE status = 'active' AND privacy = 'sanitized'").get()?.c || 0
        );
      } catch {
        registeredSanitizedCount = 0;
      }
    }
    const literalChannel1 = literalPool.items.filter((it) => it.actionable === true);
    const literalDocTokens = literalChannel1.reduce(
      (sum, it) => sum + estimateTokenBudget(`${it.title}\n${it.snippet}`),
      0
    );
    const extraSemanticSlots = Math.max(0, Math.min(maxRerankPoolSize, registeredSanitizedCount) - literalChannel1.length);
    const estDocTokens = cloudConfig.rerankReservedInputTokens != null
      ? Number(cloudConfig.rerankReservedInputTokens)
      : Math.max(120, literalDocTokens + extraSemanticSlots * 260 + 64);
    stages.push({
      cloudApprovalId: rerankApprovalId,
      requestId: rerankStageReqId,
      provider,
      modelId: rerankModel,
      purpose: 'rerank',
      endpointUrl: resolvedRerankEndpoint,
      requiresQueryEgress: true,
      reservedInputTokens: estimateTokenBudget(safeQueryText) + estDocTokens,
      maxOutputTokens: 0
    });
  }

  let runPlan;
  try {
    runPlan = reserveRunPlanBudgets(operatorDb, {
      runPlanId,
      stages,
      vaultId,
      dataId
    });
  } catch (err) {
    return fallbackToMode0(`run_plan_reservation_failed:${err.code || err.message}`);
  }

  const embedReservation = runPlan.reservations[0];
  const rerankReservation = runPlan.reservations[1] || null;
  let egressBytes = sanitizedQueryRes.egressBytes;

  const releaseUnusedRerank = buildSafeReleaseReservationFn(operatorDb, rerankReservation);
  const releaseUnusedEmbed = buildSafeReleaseReservationFn(operatorDb, embedReservation);

  let embedCallRes;
  try {
    const remainingMs = overallDeadlineMs - (Date.now() - startedAt);
    if (remainingMs <= 0) {
      releaseUnusedEmbed();
      releaseUnusedRerank();
      return fallbackToMode0('overall_deadline_exceeded_fallback_to_mode0', { egressBytes: 0 });
    }
    embedCallRes = await callCloudProviderGateway({
      operatorDb,
      cloudApprovalId: embedApprovalId,
      runPlanId,
      preReserved: embedReservation,
      provider,
      modelId: embedModel,
      purpose: 'embed_query',
      baseUrl,
      endpointUrl: resolvedEmbedEndpoint,
      requiresQueryEgress: true,
      apiKeyProvider,
      vaultId,
      dataId,
      payloadInput: { inputs: [safeQueryText] },
      reservedInputTokens: embedReservation.reservedInputTokens,
      maxOutputTokens: 0,
      overallDeadlineMs: remainingMs,
      testContext,
      sentinelReport,
      fetchFn
    });
  } catch (err) {
    releaseUnusedRerank();
    return fallbackToMode0(`cloud_embed_failed:${err.code || err.message}`, {
      egressBytes: err?.precheckFailed ? 0 : egressBytes
    });
  }

  const queryVector = embedCallRes.parsed.vectors[0];
  let vectorHitsRes;
  try {
    vectorHitsRes = queryVectorIndex({
      stateDb: db,
      vectorsDbPath,
      vaultDir,
      queryVector,
      provider,
      model: embedModel,
      topK: maxRerankPoolSize
    });
  } catch (err) {
    releaseUnusedRerank();
    return fallbackToMode0(`vector_index_error_fallback_to_mode0:${err.code || err.message}`, { egressBytes });
  }

  // Merge literal pool (Channel 1 + Channel 2) with verified semantic hits
  const mergedById = new Map();
  for (const lit of literalPool.items) {
    const key = lit.id || lit.path;
    mergedById.set(key, {
      ...lit,
      literalScore: lit.score || 0,
      vectorScore: 0,
      score: lit.score || 0
    });
  }

  const {
    proposalsByTargetId,
    managedIdCounts,
    deriveSourceToolsForNote
  } = collectVaultSearchContext(vaultDir, db);
  const queryTerms = String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
  for (const hit of vectorHitsRes.items) {
    const existing = mergedById.get(hit.docId);
    if (existing) {
      existing.vectorScore = hit.score;
      existing.score = existing.literalScore + hit.score * 10;
      continue;
    }
    const candidateItem = buildActionableStatusForFile({
      db,
      vaultDir,
      deriveSourceToolsForNote,
      filePath: hit.resolvedPath,
      parsed: hit.parsed,
      project,
      sourceTool,
      env,
      todayStr: effectiveTodayStr,
      managedIdCounts,
      proposalsByTargetId,
      queryTerms
    });
    if (candidateItem) {
      mergedById.set(hit.docId, {
        ...candidateItem,
        literalScore: 0,
        vectorScore: hit.score,
        score: hit.score * 10
      });
    }
  }

  const mergedList = [...mergedById.values()].sort((a, b) => {
    if (a.actionable !== b.actionable) return a.actionable ? -1 : 1;
    return b.score - a.score;
  });

  if (rerankReservation) {
    const channel1Candidates = mergedList.filter((it) => it.actionable === true);
    const channel2Candidates = mergedList.filter((it) => it.actionable !== true);
    return executeCloudRerankOnCandidates({
      db,
      operatorDb,
      rerankApprovalId,
      rerankReservation,
      runPlanId,
      provider,
      rerankModel,
      baseUrl,
      resolvedRerankEndpoint,
      apiKeyProvider,
      vaultId,
      dataId,
      safeQueryText,
      channel1Candidates,
      channel2Candidates,
      overallDeadlineMs,
      startedAt,
      initialEgressBytes: egressBytes,
      topK,
      resultMode: effectiveMode,
      spaceId: vectorHitsRes.spaceId,
      invalidatedDocs: vectorHitsRes.invalidatedDocs,
      testContext,
      sentinelReport,
      fetchFn,
      releaseUnusedRerank,
      fallbackToMode0
    });
  }

  const sliced = mergedList.slice(0, topK);
  return {
    mode: effectiveMode,
    dailyDefaultMode: DEFAULT_SEARCH_MODE,
    noAnswer: sliced.length === 0,
    fallbackUsed: false,
    fallbackReason: null,
    cloudUsed: true,
    spaceId: vectorHitsRes.spaceId,
    invalidatedDocs: vectorHitsRes.invalidatedDocs,
    egressBytes,
    items: sliced
  };
}

/**
 * 冻结 Channel 1 候选池独立外部 /rerank 执行器（无需 embedApprovalId 或向量检索）。
 * 严格忽略调用方传入的 actionable/privacy/title/snippet，现场从 db + Vault Markdown 重验，
 * 确保 0 条 Channel 2、0 条未登记/local_only/过期/待审提案、0 个 UUID 进入 /rerank 报文；
 * 任一校验/额度/时限/返回值异常均安全回退真实 Mode 0 (literal)。
 */
export async function rerankFrozenCandidatesAsync({
  db = null,
  approvalDb = null,
  vaultDir,
  query,
  frozenCandidates = [],
  project = null,
  sourceTool = null,
  env = null,
  todayStr = getBeijingTodayStr(),
  topK = 10,
  cloudConfig = null
} = {}) {
  const effectiveTodayStr = todayStr || getBeijingTodayStr();
  const fallbackToMode0 = createMode0FallbackRunner({
    db,
    approvalDb,
    vaultDir,
    query,
    project,
    sourceTool,
    env,
    effectiveTodayStr,
    topK
  });

  if (!cloudConfig || !cloudConfig.operatorDb || !cloudConfig.rerankApprovalId) {
    return fallbackToMode0('missing_rerank_config_fallback_to_mode0');
  }

  const startedAt = Date.now();
  const parsedDeadline = Number(cloudConfig.overallDeadlineMs);
  const overallDeadlineMs = Number.isFinite(parsedDeadline) ? Math.max(1, parsedDeadline) : 4000;
  const runPlanId = `run-${crypto.randomUUID()}`;
  const {
    operatorDb,
    rerankApprovalId,
    provider = 'siliconflow',
    rerankModel = 'BAAI/bge-reranker-v2-m3',
    baseUrl = null,
    rerankEndpointUrl = null,
    apiKeyProvider,
    vaultId,
    dataId,
    testContext = false,
    sentinelReport = null,
    fetchFn = globalThis.fetch
  } = cloudConfig;

  const cleanBaseUrl = typeof baseUrl === 'string' ? baseUrl.trim().replace(/\/+$/, '') : null;
  const resolvedRerankEndpoint = rerankEndpointUrl || (cleanBaseUrl ? `${cleanBaseUrl}/v1/rerank` : null);

  let sanitizedQueryRes;
  try {
    sanitizedQueryRes = sanitizePayloadForExitA({
      db,
      requireRegisteredSanitized: false,
      items: [{ kind: 'query', text: String(query || '') }],
      allowedFields: ['text']
    });
  } catch (err) {
    return fallbackToMode0(`exit_a_query_blocked:${err.code || err.message}`);
  }
  const safeQueryText = sanitizedQueryRes.sanitizedItems[0]?.text || '';
  if (!safeQueryText.trim()) {
    return fallbackToMode0('empty_sanitized_query_fallback_to_mode0');
  }

  if (!Array.isArray(frozenCandidates) || frozenCandidates.length === 0) {
    return {
      mode: 'rerank',
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      noAnswer: true,
      fallbackUsed: false,
      fallbackReason: null,
      cloudUsed: false,
      spaceId: null,
      invalidatedDocs: [],
      egressBytes: 0,
      items: []
    };
  }

  // Scan Vault fresh once and re-evaluate every frozen candidate from live DB + Markdown
  const {
    notesDir,
    proposalsByTargetId,
    managedIdCounts,
    fileRawCache,
    deriveSourceToolsForNote
  } = collectVaultSearchContext(vaultDir, db);
  const queryTerms = String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
  const noteFilesById = new Map();
  const noteFilesByRelPath = new Map();

  for (const fp of findMarkdownFiles(notesDir, { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir })) {
    try {
      const content = fileRawCache.get(path.resolve(fp)) ?? fs.readFileSync(fp, 'utf8');
      const parsed = parseMarkdownFrontmatter(content);
      const fm = parsed?.frontmatter || {};
      const entry = { filePath: fp, parsed };
      const rel = path.relative(vaultDir, fp).replace(/\\/g, '/');
      noteFilesByRelPath.set(rel, entry);
      if (fm.id) {
        if (!noteFilesById.has(fm.id)) noteFilesById.set(fm.id, []);
        noteFilesById.get(fm.id).push(entry);
      }
    } catch {
      // Ignore unreadable notes
    }
  }

  const channel1Candidates = [];
  const channel2Candidates = [];
  const seenKeys = new Set();

  for (const rawCand of frozenCandidates) {
    const candObj = typeof rawCand === 'string' ? { id: rawCand } : (rawCand || {});
    const candId = candObj.id || candObj.noteId || null;
    const candRel = candObj.path
      ? path.relative(vaultDir, path.resolve(vaultDir, candObj.path)).replace(/\\/g, '/')
      : null;
    const dedupKey = candId || candRel;
    if (!dedupKey || seenKeys.has(dedupKey)) continue;
    seenKeys.add(dedupKey);

    let entry = null;
    if (candId && noteFilesById.has(candId)) {
      const matches = noteFilesById.get(candId);
      entry = matches[0];
    } else if (candRel && noteFilesByRelPath.has(candRel)) {
      entry = noteFilesByRelPath.get(candRel);
    }
    if (!entry) continue;

    const evaluatedItem = buildActionableStatusForFile({
      db,
      vaultDir,
      deriveSourceToolsForNote,
      filePath: entry.filePath,
      parsed: entry.parsed,
      project,
      sourceTool,
      env,
      todayStr: effectiveTodayStr,
      managedIdCounts,
      proposalsByTargetId,
      queryTerms
    });
    if (!evaluatedItem) continue;

    const hydrated = {
      ...evaluatedItem,
      literalScore: Number(candObj.literalScore || 0),
      vectorScore: Number(candObj.vectorScore || 0),
      score: Number.isFinite(Number(candObj.score)) ? Number(candObj.score) : 0
    };
    if (hydrated.actionable === true) {
      channel1Candidates.push(hydrated);
    } else {
      channel2Candidates.push(hydrated);
    }
  }

  if (channel1Candidates.length === 0) {
    const sliced = channel2Candidates.slice(0, topK);
    return {
      mode: 'rerank',
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      noAnswer: sliced.length === 0,
      fallbackUsed: false,
      fallbackReason: null,
      cloudUsed: false,
      spaceId: null,
      invalidatedDocs: [],
      egressBytes: 0,
      items: sliced
    };
  }

  const docsTokens = channel1Candidates.reduce(
    (sum, it) => sum + estimateTokenBudget(`${it.title}\n${it.snippet}`),
    0
  );
  const estInputTokens = cloudConfig.rerankReservedInputTokens != null
    ? Number(cloudConfig.rerankReservedInputTokens)
    : estimateTokenBudget(safeQueryText) + docsTokens + 32;

  let rerankReservation;
  try {
    rerankReservation = reserveCloudEgressBudget(operatorDb, {
      cloudApprovalId: rerankApprovalId,
      runPlanId,
      requestId: `req-${crypto.randomUUID()}`,
      provider,
      modelId: rerankModel,
      purpose: 'rerank',
      endpointUrl: resolvedRerankEndpoint,
      requiresQueryEgress: true,
      reservedInputTokens: estInputTokens,
      maxOutputTokens: 0,
      vaultId,
      dataId
    });
  } catch (err) {
    return fallbackToMode0(`rerank_reservation_failed:${err.code || err.message}`);
  }

  const releaseUnusedRerank = buildSafeReleaseReservationFn(operatorDb, rerankReservation);
  const remainingBeforeSend = overallDeadlineMs - (Date.now() - startedAt);
  if (remainingBeforeSend <= 0) {
    releaseUnusedRerank();
    return fallbackToMode0('overall_deadline_exceeded_fallback_to_mode0', { egressBytes: 0 });
  }

  return executeCloudRerankOnCandidates({
    db,
    operatorDb,
    rerankApprovalId,
    rerankReservation,
    runPlanId,
    provider,
    rerankModel,
    baseUrl,
    resolvedRerankEndpoint,
    apiKeyProvider,
    vaultId,
    dataId,
    safeQueryText,
    channel1Candidates,
    channel2Candidates,
    overallDeadlineMs,
    startedAt,
    initialEgressBytes: sanitizedQueryRes.egressBytes,
    topK,
    resultMode: 'rerank',
    spaceId: null,
    invalidatedDocs: [],
    testContext,
    sentinelReport,
    fetchFn,
    releaseUnusedRerank,
    fallbackToMode0
  });
}
