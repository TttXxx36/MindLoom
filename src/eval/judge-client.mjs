import fs from 'node:fs';
import path from 'node:path';
import { parseEventAnchor, parseRenderedSessionEvents } from '../distill/llm-distiller.mjs';
import { sanitizePayloadForExitA } from '../egress/egress-controller.mjs';
import { callCloudProviderGateway } from '../providers/api-gateway.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { sanitizeOutputText } from '../security/sanitizer.mjs';
import { assertPathWithinBoundary, findMarkdownFiles } from '../storage/path-sanitizer.mjs';

export const ALLOWED_JUDGE_VERDICTS = Object.freeze(
  new Set(['relevant', 'partial', 'irrelevant', 'insufficient_evidence'])
);

export const ALLOWED_JUDGE_ADVISORIES = Object.freeze(
  new Set(['evidence_insufficient', 'suspected_conflict', 'stale_risk'])
);

export const FORBIDDEN_JUDGE_DIRECTIVE_KEYS = Object.freeze(
  new Set([
    'actionable',
    'review_state',
    'lifecycle',
    'reconcile_state',
    'proposal_status',
    'write_file',
    'write_files',
    'mutations',
    'sql',
    'execute',
    'db_ops',
    'tombstone',
    'delete_note',
    'approve_egress',
    'promote_channel2',
    'file_edits',
    'commands'
  ])
);

function parseWikiCitationRef(rawRef) {
  if (typeof rawRef !== 'string') return null;
  let inner = rawRef.trim();
  if (!inner) return null;

  if (inner.startsWith('[[') && inner.endsWith(']]')) {
    inner = inner.slice(2, -2);
  }
  inner = inner.split('|')[0].trim();
  if (!inner) return null;

  const hashIdx = inner.indexOf('#');
  const noteRef = (hashIdx === -1 ? inner : inner.slice(0, hashIdx)).trim();
  const fragment = (hashIdx === -1 ? '' : inner.slice(hashIdx + 1)).trim();
  return { rawRef, noteRef, fragment };
}

function buildSafeVaultIndex(vaultDir) {
  const mdFiles = findMarkdownFiles(vaultDir, {
    excludeTemplates: true,
    followSymlinks: false,
    boundaryDir: vaultDir
  });
  const byRelNoExt = new Map();
  const byBaseNoExt = new Map();

  for (const absPath of mdFiles) {
    const relNoExt = path
      .relative(vaultDir, absPath)
      .replace(/\\/g, '/')
      .replace(/\.md$/i, '');
    byRelNoExt.set(relNoExt.toLowerCase(), absPath);
    const baseNoExt = path.basename(relNoExt).toLowerCase();
    const list = byBaseNoExt.get(baseNoExt) || [];
    list.push(absPath);
    byBaseNoExt.set(baseNoExt, list);
  }

  return { byRelNoExt, byBaseNoExt };
}

function verifySingleCitation({ db, vaultDir, vaultIndex, rawRef }) {
  const parsedRef = parseWikiCitationRef(rawRef);
  if (!parsedRef || !parsedRef.noteRef) {
    return { valid: false, rawRef, reason: 'invalid_citation_syntax' };
  }

  const normalizedNoteRef = parsedRef.noteRef.replace(/\\/g, '/').replace(/\.md$/i, '');
  if (
    path.isAbsolute(normalizedNoteRef) ||
    normalizedNoteRef.split('/').some((seg) => seg === '..')
  ) {
    return { valid: false, rawRef, reason: 'citation_path_outside_boundary' };
  }

  let absPath = vaultIndex.byRelNoExt.get(normalizedNoteRef.toLowerCase()) || null;
  if (!absPath && !normalizedNoteRef.includes('/')) {
    const matches = vaultIndex.byBaseNoExt.get(normalizedNoteRef.toLowerCase()) || [];
    if (matches.length === 1) {
      absPath = matches[0];
    } else if (matches.length > 1) {
      return { valid: false, rawRef, reason: 'ambiguous_citation_target' };
    }
  }

  if (!absPath) {
    return { valid: false, rawRef, reason: 'citation_target_not_found' };
  }

  try {
    assertPathWithinBoundary(absPath, vaultDir, { followSymlinks: false });
  } catch {
    return { valid: false, rawRef, reason: 'citation_boundary_or_symlink_blocked' };
  }

  const content = fs.readFileSync(absPath, 'utf8');
  const { frontmatter } = parseMarkdownFrontmatter(content);
  if (!frontmatter || frontmatter.privacy !== 'sanitized') {
    return { valid: false, rawRef, reason: 'citation_target_not_sanitized' };
  }

  if (db && frontmatter.id) {
    const noteRow = db
      .prepare('SELECT privacy, status FROM notes WHERE id = ?')
      .get(String(frontmatter.id));
    if (noteRow && (noteRow.privacy !== 'sanitized' || noteRow.status !== 'active')) {
      return { valid: false, rawRef, reason: 'citation_target_db_privacy_or_status_blocked' };
    }
  }

  if (parsedRef.fragment) {
    const parsedAnchor = parseEventAnchor(parsedRef.fragment);
    if (!parsedAnchor) {
      return { valid: false, rawRef, reason: 'invalid_citation_anchor' };
    }
    const sessionParsed = parseRenderedSessionEvents(content);
    const ev = sessionParsed.eventsById.get(parsedAnchor.eventId);
    if (!ev || ev.isPlaceholder) {
      return { valid: false, rawRef, reason: 'citation_anchor_not_found_in_rendered_events' };
    }
    return {
      valid: true,
      rawRef,
      resolvedRelPath: path.relative(vaultDir, absPath).replace(/\\/g, '/'),
      noteId: frontmatter.id ? String(frontmatter.id) : null,
      anchor: parsedAnchor.anchor
    };
  }

  return {
    valid: true,
    rawRef,
    resolvedRelPath: path.relative(vaultDir, absPath).replace(/\\/g, '/'),
    noteId: frontmatter.id ? String(frontmatter.id) : null,
    anchor: null
  };
}

/**
 * 本地确定性代码先行核验引文路径、隐私级别与 `#^event-NNNNNN` 锚点是否存在
 * @param {{ db?: any, vaultDir: string, citations?: string[] }} params
 */
export function verifyLocalCitations({ db = null, vaultDir, citations = [] }) {
  const vaultIndex = buildSafeVaultIndex(vaultDir);
  const verifiedCitations = [];
  const invalidCitations = [];

  for (const rawRef of Array.isArray(citations) ? citations : []) {
    const res = verifySingleCitation({ db, vaultDir, vaultIndex, rawRef });
    if (res.valid) {
      verifiedCitations.push(res);
    } else {
      invalidCitations.push(res);
    }
  }

  return {
    validCount: verifiedCitations.length,
    invalidCount: invalidCitations.length,
    verifiedCitations,
    invalidCitations
  };
}

function collectForbiddenDirectives(obj, prefix = '', hits = []) {
  if (!obj || typeof obj !== 'object') return hits;
  if (Array.isArray(obj)) {
    obj.forEach((item, idx) => collectForbiddenDirectives(item, `${prefix}[${idx}]`, hits));
    return hits;
  }
  for (const [key, val] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    const fieldPath = prefix ? `${prefix}.${key}` : key;
    if (FORBIDDEN_JUDGE_DIRECTIVE_KEYS.has(lowerKey)) {
      hits.push(fieldPath);
    }
    if (val && typeof val === 'object') {
      collectForbiddenDirectives(val, fieldPath, hits);
    }
  }
  return hits;
}

/**
 * 对 Judge 模型返回做严格输出消毒与零写越权剥离（§5.3 绝对禁区）
 */
export function sanitizeJudgeResponseOutput({
  rawParsedJson,
  vaultDir,
  db = null,
  localCitationCheck
}) {
  if (!rawParsedJson || typeof rawParsedJson !== 'object' || Array.isArray(rawParsedJson)) {
    return {
      status: 'unavailable_skipped',
      modelUnavailable: true,
      verdict: 'insufficient_evidence',
      advisories: ['evidence_insufficient'],
      modelReasoningNotes: '',
      blockedDirectives: [],
      rejectedModelCitations: [],
      verifiedModelCitations: [],
      reason: 'empty_or_non_object_judge_response'
    };
  }

  const blockedDirectives = collectForbiddenDirectives(rawParsedJson);
  const rawVerdict = typeof rawParsedJson.verdict === 'string' ? rawParsedJson.verdict.trim() : '';
  if (!ALLOWED_JUDGE_VERDICTS.has(rawVerdict)) {
    return {
      status: 'unavailable_skipped',
      modelUnavailable: true,
      verdict: 'insufficient_evidence',
      advisories: ['evidence_insufficient'],
      modelReasoningNotes: sanitizeOutputText(
        String(rawParsedJson.model_reasoning_notes || rawParsedJson.reason || ''),
        { scrubRawPaths: true }
      ),
      blockedDirectives,
      rejectedModelCitations: [],
      verifiedModelCitations: [],
      reason: rawVerdict ? `invalid_judge_verdict:${rawVerdict}` : 'missing_judge_verdict'
    };
  }

  const rawModelCitations = Array.isArray(rawParsedJson.citations)
    ? rawParsedJson.citations
    : Array.isArray(rawParsedJson.cited_refs)
      ? rawParsedJson.cited_refs
      : [];
  const modelCitationCheck = verifyLocalCitations({
    db,
    vaultDir,
    citations: rawModelCitations
  });

  const advisorySet = new Set();
  for (const adv of Array.isArray(rawParsedJson.advisories) ? rawParsedJson.advisories : []) {
    if (ALLOWED_JUDGE_ADVISORIES.has(String(adv))) {
      advisorySet.add(String(adv));
    }
  }

  let effectiveVerdict = rawVerdict;
  if (localCitationCheck.validCount === 0 || modelCitationCheck.invalidCount > 0) {
    if (effectiveVerdict === 'relevant' || effectiveVerdict === 'partial') {
      effectiveVerdict = 'insufficient_evidence';
    }
    advisorySet.add('evidence_insufficient');
  }

  return {
    status: 'completed',
    modelUnavailable: false,
    verdict: effectiveVerdict,
    advisories: Array.from(advisorySet),
    modelReasoningNotes: sanitizeOutputText(
      String(rawParsedJson.model_reasoning_notes || rawParsedJson.reason || ''),
      { scrubRawPaths: true }
    ),
    blockedDirectives,
    rejectedModelCitations: modelCitationCheck.invalidCitations,
    verifiedModelCitations: modelCitationCheck.verifiedCitations,
    reason: null
  };
}

function buildJudgeMessages({ item, localCitationCheck }) {
  return [
    {
      role: 'system',
      content:
        '你是只读评估顾问（Judge）。严禁输出文件修改、数据库写操作、SQL 或审核状态变更指令。' +
        '仅输出严格 JSON: {"verdict": "relevant|partial|irrelevant|insufficient_evidence", "advisories": ["evidence_insufficient"|"suspected_conflict"|"stale_risk"], "citations": ["[[...]]"], "model_reasoning_notes": "..."}。'
    },
    {
      role: 'user',
      content: JSON.stringify({
        query: item.query,
        claim_or_snippet: item.claim_or_snippet,
        locally_verified_citations: localCitationCheck.verifiedCitations.map((c) => ({
          ref: c.rawRef,
          resolved: c.resolvedRelPath,
          anchor: c.anchor
        })),
        locally_invalid_citations_count: localCitationCheck.invalidCount
      })
    }
  ];
}

function estimateJudgeTokens(messages) {
  return Math.max(16, Math.ceil(Buffer.byteLength(JSON.stringify(messages), 'utf8') / 3));
}

/**
 * V3.3-4 离线批次 Judge 评审（§5.3 业务表与 Vault Markdown 绝对零写入）
 */
export async function evaluateJudgeBatch({
  db = null,
  operatorDb,
  vaultDir,
  cloudApprovalId,
  provider = 'deepseek',
  modelId = 'deepseek-chat',
  baseUrl = null,
  endpointUrl = null,
  pricingVersion = null,
  vaultId = null,
  dataId = null,
  apiKeyProvider = undefined,
  items = [],
  maxOutputTokens = 1024,
  temperature = 0,
  thinkingMode = false,
  overallDeadlineMs = 15000,
  testContext = false,
  sentinelReport = null,
  fetchFn = globalThis.fetch,
  reservedInputTokens = null
}) {
  if (!operatorDb) {
    throw new Error('[ERR_JUDGE_OPERATOR_DB_REQUIRED] operatorDb is required');
  }

  const evaluations = [];
  for (let i = 0; i < (Array.isArray(items) ? items.length : 0); i++) {
    const rawItem = items[i];
    const itemId = String(rawItem?.id || rawItem?.candidateId || `judge-item-${i + 1}`);
    const localCitationCheck = verifyLocalCitations({
      db,
      vaultDir,
      citations: rawItem?.citations || []
    });

    const sanitizedPayload = sanitizePayloadForExitA({
      db,
      items: [
        {
          id: rawItem?.candidateId || itemId,
          privacy: rawItem?.privacy || 'sanitized',
          query: String(rawItem?.query || ''),
          title: String(rawItem?.title || itemId),
          text: String(rawItem?.claim || rawItem?.snippet || '')
        }
      ],
      allowedFields: ['id', 'privacy', 'query', 'title', 'text'],
      requireRegisteredSanitized: Boolean(db && rawItem?.candidateId)
    });

    const safeEntry = sanitizedPayload.sanitizedItems[0];
    const messages = buildJudgeMessages({
      item: {
        query: safeEntry.query || '',
        claim_or_snippet: safeEntry.text || ''
      },
      localCitationCheck
    });
    const reqTokens = reservedInputTokens ?? estimateJudgeTokens(messages);

    try {
      const gatewayRes = await callCloudProviderGateway({
        operatorDb,
        cloudApprovalId,
        provider,
        modelId,
        purpose: 'judge',
        baseUrl,
        endpointUrl,
        pricingVersion,
        vaultId,
        dataId,
        apiKeyProvider,
        payloadInput: {
          messages,
          maxTokens: maxOutputTokens,
          temperature,
          thinkingMode,
          responseFormat: { type: 'json_object' }
        },
        reservedInputTokens: reqTokens,
        maxOutputTokens,
        expectJson: true,
        overallDeadlineMs,
        testContext,
        sentinelReport,
        fetchFn
      });

      const normalized = sanitizeJudgeResponseOutput({
        rawParsedJson: gatewayRes.parsed?.parsedJson,
        vaultDir,
        db,
        localCitationCheck
      });
      evaluations.push({
        itemId,
        localCitationCheck,
        ...normalized,
        gatewayRequestId: gatewayRes.requestId,
        egressBytes: gatewayRes.egressBytes
      });
    } catch (err) {
      evaluations.push({
        itemId,
        localCitationCheck,
        status: 'unavailable_skipped',
        modelUnavailable: true,
        verdict: 'insufficient_evidence',
        advisories: ['evidence_insufficient'],
        modelReasoningNotes: '',
        blockedDirectives: [],
        rejectedModelCitations: [],
        verifiedModelCitations: [],
        reason: err.code || err.message || 'judge_gateway_unavailable',
        gatewayRequestId: err.attemptIds?.[0] || err.retainedRequestId || null
      });
    }
  }

  return {
    readOnlyAdvisory: true,
    vaultWritesCount: 0,
    businessDbWritesCount: 0,
    evaluations
  };
}

/**
 * 检索旁路只读质量观察（仅审查 Channel 1 条目，绝不改序、绝不提权 Channel 2、业务零写入）
 */
export async function observeSearchResultsWithJudge({
  db,
  operatorDb,
  vaultDir,
  cloudApprovalId,
  query,
  searchResult,
  ...restOptions
}) {
  const allItems = Array.isArray(searchResult?.items) ? searchResult.items : [];
  const rawChannel1Items = allItems.filter((item) => item?.actionable === true);
  const channel1Items = [];
  for (const item of rawChannel1Items) {
    if (!item?.id || !db) continue;
    const row = db
      .prepare('SELECT privacy, status FROM notes WHERE id = ?')
      .get(String(item.id));
    if (row && row.privacy === 'sanitized' && row.status === 'active') {
      channel1Items.push({ ...item, privacy: row.privacy });
    }
  }
  const channel2Items = Array.isArray(searchResult?.channel2Items)
    ? searchResult.channel2Items
    : allItems.filter((item) => item?.actionable !== true);

  const batchItems = channel1Items.map((item) => ({
    id: item.id,
    candidateId: item.id,
    privacy: item.privacy,
    query,
    title: item.title || item.id,
    snippet: item.snippet || '',
    citations: Array.isArray(item.sources) ? item.sources : []
  }));

  const batchReport = await evaluateJudgeBatch({
    db,
    operatorDb,
    vaultDir,
    cloudApprovalId,
    items: batchItems,
    ...restOptions
  });

  const advisoriesByItemId = {};
  for (const ev of batchReport.evaluations) {
    advisoriesByItemId[ev.itemId] = {
      verdict: ev.verdict,
      advisories: ev.advisories,
      blockedDirectives: ev.blockedDirectives,
      rejectedModelCitations: ev.rejectedModelCitations
    };
  }

  return {
    readOnlyAdvisory: true,
    itemsOrderPreserved: true,
    channel1EvaluatedCount: channel1Items.length,
    channel2UntouchedCount: channel2Items.length,
    channel2PromotedCount: 0,
    vaultWritesCount: 0,
    businessDbWritesCount: 0,
    advisoriesByItemId,
    evaluations: batchReport.evaluations
  };
}
