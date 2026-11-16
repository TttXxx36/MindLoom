import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { openDatabase, openExistingDatabase } from '../db/sqlite.mjs';
import {
  DEFAULT_SEARCH_MODE,
  searchKnowledge,
  buildLocalSearchIndex,
  getBeijingTodayStr
} from '../search/query-engine.mjs';
import { issueTrustedEgressApproval } from '../security/trusted-approvals.mjs';
import { findMarkdownFiles } from '../storage/path-sanitizer.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { buildSyntheticPilotCorpus, PILOT_QUESTIONS } from './pilot-suite.synthetic.mjs';

function computePercentile(sortedValues, p) {
  if (!sortedValues || sortedValues.length === 0) return null;
  const idx = Math.min(
    sortedValues.length - 1,
    Math.max(0, Math.ceil((p / 100) * sortedValues.length) - 1)
  );
  return Number(sortedValues[idx].toFixed(3));
}

function computeSplitMetrics(resultsSubset, questionsSubset) {
  const answerable = resultsSubset.filter(r => !r.question.isNoAnswer && !r.question.expectNonActionableOnly);
  const noAnswerCases = resultsSubset.filter(r => r.question.isNoAnswer);
  const trapCases = resultsSubset.filter(r => r.question.expectNonActionableOnly);

  let rawHitAt1Count = 0;
  let rawHitAt5Count = 0;
  let rawMrrSum = 0;
  let actionableHitAt1Count = 0;
  let actionableHitAt5Count = 0;
  let actionableMrrSum = 0;

  for (const { question, res } of answerable) {
    const expectedIds = Array.isArray(question.expectedIds) ? question.expectedIds : [];
    const seenIds = new Set();
    const uniqueItems = [];
    for (const item of res.items || []) {
      if (!seenIds.has(item.id)) {
        seenIds.add(item.id);
        uniqueItems.push(item);
      }
    }
    const top5 = uniqueItems.slice(0, 5);

    if (top5.length > 0 && expectedIds.includes(top5[0].id)) {
      rawHitAt1Count++;
    }
    const rawFirstRank = top5.findIndex(item => expectedIds.includes(item.id));
    if (rawFirstRank !== -1) {
      rawHitAt5Count++;
      rawMrrSum += 1 / (rawFirstRank + 1);
    }

    if (top5.length > 0 && top5[0].actionable === true && expectedIds.includes(top5[0].id)) {
      actionableHitAt1Count++;
    }
    const actFirstRank = top5.findIndex(item => item.actionable === true && expectedIds.includes(item.id));
    if (actFirstRank !== -1) {
      actionableHitAt5Count++;
      actionableMrrSum += 1 / (actFirstRank + 1);
    }
  }

  let noAnswerCorrect = 0;
  for (const { res } of noAnswerCases) {
    if (res.items.length === 0 && res.noAnswer === true) {
      noAnswerCorrect++;
    }
  }

  let staleOrConflictMisuseCount = 0;
  for (const { res } of trapCases) {
    if (res.items.some(item => item.actionable === true)) {
      staleOrConflictMisuseCount++;
    }
  }

  const denominators = {
    total: questionsSubset.length,
    answerable: answerable.length,
    noAnswer: noAnswerCases.length,
    conflictOrStaleTrap: trapCases.length
  };

  const unassessedReasons = [];
  if (answerable.length === 0) unassessedReasons.push('empty_answerable');
  if (noAnswerCases.length === 0) unassessedReasons.push('empty_no_answer');
  if (trapCases.length === 0) unassessedReasons.push('empty_conflict_or_stale_trap');

  const actionableEvaluable = answerable.length > 0;
  const noAnswerEvaluable = noAnswerCases.length > 0;
  const trapEvaluable = trapCases.length > 0;
  const evaluable = unassessedReasons.length === 0;

  return {
    questionCounts: { ...denominators },
    denominators,
    // 旧字段保持向后兼容原义
    hitAt1: answerable.length ? Number((rawHitAt1Count / answerable.length).toFixed(4)) : 0,
    hitAt5: answerable.length ? Number((rawHitAt5Count / answerable.length).toFixed(4)) : 0,
    mrrAt5: answerable.length ? Number((rawMrrSum / answerable.length).toFixed(4)) : 0,
    // V3.3 新增前 5 唯一双口径：actionable vs raw
    actionableHitAt1: answerable.length ? Number((actionableHitAt1Count / answerable.length).toFixed(4)) : null,
    actionableHitAt5: answerable.length ? Number((actionableHitAt5Count / answerable.length).toFixed(4)) : null,
    actionableMrrAt5: answerable.length ? Number((actionableMrrSum / answerable.length).toFixed(4)) : null,
    rawHitAt1: answerable.length ? Number((rawHitAt1Count / answerable.length).toFixed(4)) : null,
    rawHitAt5: answerable.length ? Number((rawHitAt5Count / answerable.length).toFixed(4)) : null,
    rawMrrAt5: answerable.length ? Number((rawMrrSum / answerable.length).toFixed(4)) : null,
    noAnswerAccuracy: noAnswerCases.length ? Number((noAnswerCorrect / noAnswerCases.length).toFixed(4)) : null,
    staleOrConflictMisuseCount,
    actionableEvaluable,
    noAnswerEvaluable,
    trapEvaluable,
    evaluable,
    evaluationStatus: evaluable ? 'evaluable' : '不可评估',
    actionableEvaluationStatus: actionableEvaluable ? 'evaluable' : '不可评估',
    noAnswerEvaluationStatus: noAnswerEvaluable ? 'evaluable' : '不可评估',
    trapEvaluationStatus: trapEvaluable ? 'evaluable' : '不可评估',
    unassessedReasons
  };
}

const AMBIGUOUS_LINK_KEY = Symbol('AMBIGUOUS_LINK_KEY');

function registerLinkKey(map, key, rec, { allowAmbiguousOverwrite = false } = {}) {
  if (!key) return;
  if (!allowAmbiguousOverwrite && map.has(key)) {
    const existing = map.get(key);
    if (existing !== rec) {
      map.set(key, AMBIGUOUS_LINK_KEY);
    }
    return;
  }
  map.set(key, rec);
}

function extractWikiLinkTokens(linkStr) {
  const clean = String(linkStr || '').replace(/^\[\[/, '').replace(/\]\]$/, '').split('|')[0].split('#')[0].trim();
  if (!clean) return [];
  const norm = clean.replace(/\\/g, '/').replace(/^\.\//, '');
  if (norm.includes('/')) {
    const noExt = norm.replace(/\.md$/i, '');
    const withExt = norm.toLowerCase().endsWith('.md') ? norm : `${norm}.md`;
    return [...new Set([norm, withExt, noExt])];
  }
  const base = path.basename(norm);
  const noExt = base.endsWith('.md') ? base.slice(0, -3) : base;
  const withExt = base.toLowerCase().endsWith('.md') ? base : `${base}.md`;
  const prefixMatch = noExt.match(/^((?:SES|EV|KN)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/);
  return [...new Set([norm, withExt, noExt, ...(prefixMatch ? [prefixMatch[1]] : [])])];
}

function resolveLinkRecord(map, linkStr) {
  for (const tok of extractWikiLinkTokens(linkStr)) {
    if (!map.has(tok)) continue;
    const val = map.get(tok);
    if (val === AMBIGUOUS_LINK_KEY) return null;
    return val;
  }
  return null;
}

function verifyParticipatingSourceChains({ db, vaultDir, questions }) {
  const scoredNoteIds = new Set();
  for (const q of questions || []) {
    if (!q || q.isNoAnswer) continue;
    for (const id of q.expectedIds || []) {
      if (id) scoredNoteIds.add(String(id));
    }
  }

  const dbNoteStatusById = new Map();
  if (db) {
    try {
      for (const r of db.prepare('SELECT id, status, privacy FROM notes').all()) {
        dbNoteStatusById.set(r.id, r);
      }
    } catch {
      // ignore
    }
  }

  const sessionsByKey = new Map();
  const sessionsDir = path.join(vaultDir, '10_Readable_Sessions');
  for (const fp of findMarkdownFiles(sessionsDir, { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir })) {
    try {
      const { frontmatter } = parseMarkdownFrontmatter(fs.readFileSync(fp, 'utf8'));
      if (!frontmatter || frontmatter.privacy !== 'sanitized' || !frontmatter.source_tool) continue;
      const dbRow = frontmatter.id ? dbNoteStatusById.get(frontmatter.id) : null;
      if (dbRow && (dbRow.status === 'missing' || dbRow.status === 'deleted' || dbRow.privacy !== 'sanitized')) continue;
      const rec = {
        id: frontmatter.id || path.basename(fp, '.md'),
        sourceTool: String(frontmatter.source_tool).toLowerCase(),
        path: fp
      };
      const rel = path.relative(vaultDir, fp).replace(/\\/g, '/');
      const subRel = path.relative(sessionsDir, fp).replace(/\\/g, '/');
      for (const k of [frontmatter.id, rel, rel.replace(/\.md$/i, ''), subRel, subRel.replace(/\.md$/i, ''), path.basename(fp), path.basename(fp, '.md')]) {
        registerLinkKey(sessionsByKey, k, rec);
      }
    } catch {
      // ignore
    }
  }

  const evidenceByKey = new Map();
  const evidenceDir = path.join(vaultDir, '20_Evidence_Cards');
  for (const fp of findMarkdownFiles(evidenceDir, { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir })) {
    try {
      const { frontmatter } = parseMarkdownFrontmatter(fs.readFileSync(fp, 'utf8'));
      if (!frontmatter || frontmatter.privacy !== 'sanitized') continue;
      const dbRow = frontmatter.id ? dbNoteStatusById.get(frontmatter.id) : null;
      if (dbRow && (dbRow.status === 'missing' || dbRow.status === 'deleted' || dbRow.privacy !== 'sanitized')) continue;
      const rec = {
        id: frontmatter.id || path.basename(fp, '.md'),
        sourceTool: frontmatter.source_tool ? String(frontmatter.source_tool).toLowerCase() : null,
        sources: Array.isArray(frontmatter.sources) ? frontmatter.sources.map(s => String(s)) : [],
        path: fp
      };
      const rel = path.relative(vaultDir, fp).replace(/\\/g, '/');
      const subRel = path.relative(evidenceDir, fp).replace(/\\/g, '/');
      for (const k of [frontmatter.id, rel, rel.replace(/\.md$/i, ''), subRel, subRel.replace(/\.md$/i, ''), path.basename(fp), path.basename(fp, '.md')]) {
        registerLinkKey(evidenceByKey, k, rec);
      }
    } catch {
      // ignore
    }
  }

  const knowledgeById = new Map();
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes');
  for (const fp of findMarkdownFiles(notesDir, { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir })) {
    try {
      const { frontmatter } = parseMarkdownFrontmatter(fs.readFileSync(fp, 'utf8'));
      if (!frontmatter || !frontmatter.id || frontmatter.privacy !== 'sanitized') continue;
      const dbRow = dbNoteStatusById.get(frontmatter.id);
      if (dbRow && (dbRow.status === 'missing' || dbRow.status === 'deleted' || dbRow.privacy !== 'sanitized')) continue;
      knowledgeById.set(frontmatter.id, {
        id: frontmatter.id,
        sources: Array.isArray(frontmatter.sources) ? frontmatter.sources.map(s => String(s)) : []
      });
    } catch {
      // ignore
    }
  }

  const verifiedTools = new Set();
  const chainsByTool = {};

  for (const knId of scoredNoteIds) {
    const kn = knowledgeById.get(knId);
    if (!kn) continue;
    for (const srcLink of kn.sources) {
      const matchedEvidence = resolveLinkRecord(evidenceByKey, srcLink);
      const matchedSession = matchedEvidence ? null : resolveLinkRecord(sessionsByKey, srcLink);
      if (matchedEvidence) {
        for (const evLink of matchedEvidence.sources) {
          const ses = resolveLinkRecord(sessionsByKey, evLink);
          if (ses) {
            if (!matchedEvidence.sourceTool || matchedEvidence.sourceTool === ses.sourceTool) {
              verifiedTools.add(ses.sourceTool);
              if (!chainsByTool[ses.sourceTool]) chainsByTool[ses.sourceTool] = [];
              chainsByTool[ses.sourceTool].push({
                knowledgeId: kn.id,
                evidenceId: matchedEvidence.id,
                sessionId: ses.id
              });
            }
          }
        }
      } else if (matchedSession) {
        verifiedTools.add(matchedSession.sourceTool);
        if (!chainsByTool[matchedSession.sourceTool]) chainsByTool[matchedSession.sourceTool] = [];
        chainsByTool[matchedSession.sourceTool].push({
          knowledgeId: kn.id,
          evidenceId: null,
          sessionId: matchedSession.id
        });
      }
    }
  }

  return {
    corpusSourceCoverage: [...verifiedTools].sort(),
    participatingEvidenceChains: chainsByTool
  };
}

function evaluateMode({
  db,
  approvalDb = null,
  vaultDir,
  indexDir,
  questions,
  mode,
  topK = 5,
  todayStr = '2026-11-10',
  externalRerankFn = null,
  egressApprovalId = null,
  provider = 'local'
}) {
  // 1. 预热轮次 (1 warmup pass)
  const warmupStart = performance.now();
  for (const q of questions) {
    searchKnowledge({
      db,
      approvalDb,
      vaultDir,
      query: q.query,
      project: q.project,
      todayStr,
      mode,
      topK,
      indexDir,
      egressApprovalId,
      provider,
      externalRerankFn
    });
  }
  const warmupMs = Number((performance.now() - warmupStart).toFixed(3));

  // 2. 预热后 3 轮重复计时（同时采集逐请求耗时）
  const runTimingsMs = [];
  const perRequestLatenciesMs = [];
  let lastPassResults = [];

  for (let round = 0; round < 3; round++) {
    const t0 = performance.now();
    const passResults = [];
    for (const q of questions) {
      const reqStart = performance.now();
      const res = searchKnowledge({
        db,
        approvalDb,
        vaultDir,
        query: q.query,
        project: q.project,
        todayStr,
        mode,
        topK,
        indexDir,
        egressApprovalId,
        provider,
        externalRerankFn
      });
      perRequestLatenciesMs.push(performance.now() - reqStart);
      passResults.push({ question: q, res });
    }
    runTimingsMs.push(Number((performance.now() - t0).toFixed(3)));
    lastPassResults = passResults;
  }

  // 3. 统计核心指标 (overall + splits.main / splits.holdout 同一口径)
  const overall = computeSplitMetrics(lastPassResults, questions);
  const isHoldout = q => q?.holdout === true || String(q?.split || '').toLowerCase() === 'holdout';
  const mainQuestions = questions.filter(q => !isHoldout(q));
  const holdoutQuestions = questions.filter(q => isHoldout(q));
  const mainResults = lastPassResults.filter(r => !isHoldout(r.question));
  const holdoutResults = lastPassResults.filter(r => isHoldout(r.question));

  const splits = {
    main: computeSplitMetrics(mainResults, mainQuestions),
    holdout: computeSplitMetrics(holdoutResults, holdoutQuestions)
  };

  let totalEgressBytes = 0;
  let fallbackCount = 0;
  const fallbackReasons = [];

  for (const { res } of lastPassResults) {
    totalEgressBytes += res.egressBytes || 0;
    if (res.fallbackUsed) {
      fallbackCount++;
      if (res.fallbackReason) fallbackReasons.push(res.fallbackReason);
    }
  }

  const sortedTimings = [...runTimingsMs].sort((a, b) => a - b);
  const avgLatencyMs = Number((runTimingsMs.reduce((a, b) => a + b, 0) / runTimingsMs.length).toFixed(3));
  const p50LatencyMs = sortedTimings[1];
  const sortedReqLatencies = [...perRequestLatenciesMs].sort((a, b) => a - b);
  const p50RequestLatencyMs = computePercentile(sortedReqLatencies, 50);
  const p95RequestLatencyMs = computePercentile(sortedReqLatencies, 95);
  const legacyByteEstimateCostCny = Number(((totalEgressBytes / 1024) * 0.0001).toFixed(6));

  return {
    mode,
    topK,
    ...overall,
    splits,
    warmupMs,
    runTimingsMs,
    avgLatencyMs,
    p50LatencyMs,
    requestCount: perRequestLatenciesMs.length,
    p50RequestLatencyMs,
    p95RequestLatencyMs,
    egressBytes: totalEgressBytes,
    estimatedCostCny: legacyByteEstimateCostCny,
    legacyByteEstimateCostCny,
    costBasisVersion: 'legacy_byte_estimate_v1',
    fallbackCount,
    fallbackReasons: [...new Set(fallbackReasons)]
  };
}

/**
 * 运行阶段 D 探索对比评测 (mem benchmark --suite pilot|growth)
 * @param {{
 *   suite?: 'pilot' | 'growth',
 *   vaultDir?: string,
 *   dataDir?: string,
 *   corpusDir?: string,
 *   questionsPath?: string,
 *   questions?: Array<object>,
 *   outputPath?: string,
 *   reportDir?: string,
 *   todayStr?: string
 * }} options
 */
export function runBenchmarkSuite({
  suite = 'pilot',
  vaultDir,
  dataDir,
  corpusDir,
  questionsPath = null,
  questions: customQuestions = null,
  outputPath = null,
  reportDir = null,
  allowIndexWrite = true,
  todayStr = null
} = {}) {
  let effectiveVault = vaultDir;
  let effectiveData = dataDir;
  let questions = Array.isArray(customQuestions) ? customQuestions : PILOT_QUESTIONS;
  let suiteOrigin = Array.isArray(customQuestions) ? 'custom_questions_array' : 'synthetic_pilot_v1';
  if (questionsPath) {
    if (!fs.existsSync(questionsPath)) {
      throw new Error(`评测题集文件不存在: ${questionsPath}`);
    }
    const loaded = JSON.parse(fs.readFileSync(questionsPath, 'utf8'));
    questions = Array.isArray(loaded) ? loaded : (loaded.questions || []);
    suiteOrigin = `file:${path.basename(questionsPath)}`;
  }
  let autoSandboxDir = null;
  let tempDrillDir = null;

  // 若使用独立临时语料目录（确保可复现且不污染日常生产库）
  const usingSyntheticCorpus = Boolean(corpusDir || (!effectiveVault && !effectiveData));
  if (usingSyntheticCorpus) {
    if (!corpusDir) {
      autoSandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-pilot-bench-'));
    }
    const base = corpusDir || autoSandboxDir;
    effectiveVault = path.join(base, 'AgentMemory');
    effectiveData = path.join(base, 'AgentMemory-Data');
    buildSyntheticPilotCorpus({ vaultDir: effectiveVault, dataDir: effectiveData });
  }

  const effectiveTodayStr = todayStr || (usingSyntheticCorpus ? '2026-11-10' : getBeijingTodayStr());
  const dbPath = path.join(effectiveData, 'runtime', 'state.sqlite');
  let indexDir = null;
  if (allowIndexWrite) {
    indexDir = path.join(effectiveData, 'runtime', 'index');
    if (!fs.existsSync(path.join(indexDir, 'lexical-index.json'))) {
      try {
        buildLocalSearchIndex({ vaultDir: effectiveVault, indexDir });
      } catch (err) {
        if (!/EACCES|EPERM|EROFS|Access.*denied/i.test(String(err?.code || err?.message || ''))) {
          throw err;
        }
      }
    }
  }

  const db = openExistingDatabase(dbPath, { readOnly: true });
  let drillDb = null;
  try {
    const mode0 = evaluateMode({
      db,
      vaultDir: effectiveVault,
      indexDir,
      questions,
      mode: 'literal',
      todayStr: effectiveTodayStr
    });

    const mode1 = evaluateMode({
      db,
      vaultDir: effectiveVault,
      indexDir,
      questions,
      mode: 'hybrid',
      todayStr: effectiveTodayStr
    });

    const mode2Local = evaluateMode({
      db,
      vaultDir: effectiveVault,
      indexDir,
      questions,
      mode: 'rerank',
      todayStr: effectiveTodayStr
    });

    // 回退演练 A：未授权外发时必须在调用外部函数前阻断并安全回退至 Mode 0
    let unapprovedExternalCalls = 0;
    const mode2FallbackDrill = evaluateMode({
      db,
      vaultDir: effectiveVault,
      indexDir,
      questions,
      mode: 'rerank',
      todayStr: effectiveTodayStr,
      provider: 'siliconflow',
      egressApprovalId: null,
      externalRerankFn: () => {
        unapprovedExternalCalls++;
        throw new Error('simulated_api_timeout');
      }
    });
    mode2FallbackDrill.externalInvokeCount = unapprovedExternalCalls;

    // 回退演练 B：在独立空白合成审批库 (approvalDb) 中签发可信批准，绝不复制 state.sqlite；原只读 db 仍负责 notes 与核对状态
    tempDrillDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-bench-drill-'));
    const drillDbPath = path.join(tempDrillDir, 'drill-approvals.sqlite');
    drillDb = openDatabase(drillDbPath);
    const drillApproval = issueTrustedEgressApproval({
      db: drillDb,
      snapshotId: 'benchmark-or-search',
      provider: 'siliconflow',
      purpose: 'rerank',
      trustedHumanContext: true
    });
    let timeoutDrillInvokeCount = 0;
    const mode2TimeoutFallbackDrill = evaluateMode({
      db,
      approvalDb: drillDb,
      vaultDir: effectiveVault,
      indexDir,
      questions,
      mode: 'rerank',
      todayStr: effectiveTodayStr,
      provider: 'siliconflow',
      egressApprovalId: drillApproval.egressApprovalId,
      externalRerankFn: () => {
        timeoutDrillInvokeCount++;
        throw new Error('simulated_api_timeout');
      }
    });
    mode2TimeoutFallbackDrill.externalInvokeCount = timeoutDrillInvokeCount;

    // 统计参与评分的知识/证据链三端来源覆盖 (直接核验 Vault KN -> EV -> SES 链，不靠搜索探针或只数目录标签)
    const { corpusSourceCoverage, participatingEvidenceChains } = verifyParticipatingSourceChains({
      db,
      vaultDir: effectiveVault,
      questions
    });

    // 40 题成长集默认切换门禁评估 (ADR-005 / PLAN.md §7.2：须验证去重题量、留出题 >=10 与真实三端来源覆盖)
    const normalizedQueries = questions.map(q => String(q?.query || '').trim().toLowerCase()).filter(Boolean);
    const uniqueQuestionCount = new Set(normalizedQueries).size;
    const holdoutCount = questions.filter(q => q?.holdout === true || String(q?.split || '').toLowerCase() === 'holdout').length;
    const hit5Gain =
      mode2Local.actionableHitAt5 !== null && mode0.actionableHitAt5 !== null
        ? Number((mode2Local.actionableHitAt5 - mode0.actionableHitAt5).toFixed(4))
        : 0;
    const growthSuiteReady =
      !usingSyntheticCorpus &&
      questions.length >= 40 &&
      uniqueQuestionCount >= 40 &&
      holdoutCount >= 10 &&
      corpusSourceCoverage.length === 3 &&
      mode0.evaluable &&
      mode2Local.evaluable &&
      mode2Local.splits.holdout.evaluable;
    const growthSwitchGatePassed =
      suite === 'growth' &&
      growthSuiteReady &&
      hit5Gain >= 0.1 &&
      (mode2Local.noAnswerAccuracy ?? 0) >= (mode0.noAnswerAccuracy ?? 0) &&
      mode2Local.staleOrConflictMisuseCount === 0;

    const report = {
      suite,
      suiteOrigin,
      isolatedCorpus: usingSyntheticCorpus,
      evalTodayStr: effectiveTodayStr,
      allowIndexWrite: Boolean(allowIndexWrite),
      corpusSourceCoverage,
      participatingEvidenceChains,
      uniqueQuestionCount,
      holdoutCount,
      growthSuiteReady,
      executedAt: new Date().toISOString(),
      dailyDefaultMode: DEFAULT_SEARCH_MODE,
      dailyDefaultPolicy: 'Mode 0 (literal) remains daily default per ADR-005 until 40-question growth suite with >=10pp Hit@5 gain passes',
      growthSwitchGatePassed,
      modelConfig: {
        mode0: 'local-literal-substring-no-network',
        mode1: 'local-hybrid-char-bigram-index',
        mode2: 'local-structural-rerank-plus-exit-a-fallback-drill',
        topK: 5
      },
      modes: {
        'Mode 0 (literal)': mode0,
        'Mode 1 (hybrid)': mode1,
        'Mode 2 (rerank)': mode2Local,
        'Mode 2 (fallback_drill)': mode2FallbackDrill,
        'Mode 2 (fallback_drill_timeout)': mode2TimeoutFallbackDrill
      }
    };

    const defaultDir = reportDir || (autoSandboxDir
      ? path.join(os.tmpdir(), 'mindloom-benchmarks')
      : path.join(effectiveData, 'runtime', 'benchmarks'));
    let targetOut =
      outputPath || path.join(defaultDir, `${suite}-report-${Date.now()}.json`);
    try {
      const outParent = path.dirname(targetOut);
      if (!fs.existsSync(outParent)) fs.mkdirSync(outParent, { recursive: true });
      fs.writeFileSync(targetOut, JSON.stringify(report, null, 2), 'utf8');
    } catch (writeErr) {
      if (!outputPath && /EACCES|EPERM|EROFS|Access.*denied/i.test(String(writeErr?.code || writeErr?.message || ''))) {
        targetOut = null;
      } else {
        throw writeErr;
      }
    }

    return {
      ...report,
      reportPath: targetOut
    };
  } finally {
    if (drillDb) {
      try { drillDb.close(); } catch {}
    }
    db.close();
    if (tempDrillDir && fs.existsSync(tempDrillDir)) {
      try {
        fs.rmSync(tempDrillDir, { recursive: true, force: true });
      } catch {}
    }
    if (autoSandboxDir && fs.existsSync(autoSandboxDir)) {
      try {
        fs.rmSync(autoSandboxDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup error
      }
    }
  }
}
