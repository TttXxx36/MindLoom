import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import { initRepository } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { ensureInstanceIdentity } from '../src/storage/instance-identity.mjs';
import {
  openOperatorDatabase,
  issueCloudEgressApproval,
  revokeCloudEgressApproval
} from '../src/security/cloud-approvals.mjs';
import { indexSanitizedVaultVectors } from '../src/search/vector-index.mjs';
import {
  searchKnowledge,
  searchKnowledgeAsync,
  rerankFrozenCandidatesAsync
} from '../src/search/query-engine.mjs';
import {
  RERANK_TRIAL_LOCAL_CANARY,
  RERANK_TRIAL_UNREG_CANARY,
  RERANK_TRIAL_EXPIRED_CANARY,
  RERANK_TRIAL_PENDING_CANARY,
  runFrozenRerankTrial
} from '../src/benchmark/rerank-frozen-trial.mjs';

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function futureIso(hours = 2) {
  return new Date(Date.now() + hours * 3600_000).toISOString();
}

function syntheticApiKey() {
  return ['sk', 'mock', 'v333RerankFrozenUnitKey'].join('-');
}

async function startMockServer(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      let json = null;
      try {
        json = rawBody ? JSON.parse(rawBody) : null;
      } catch {
        json = null;
      }
      const record = { method: req.method, url: req.url, headers: req.headers, json, rawBody };
      requests.push(record);
      await handler(record, res, requests.length);
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    requests,
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

function setupRerankFixtureVault(rootDir) {
  const vaultPath = path.join(rootDir, 'vault');
  const dataPath = path.join(rootDir, 'data');
  const initRes = initRepository({ vaultPath, dataPath });
  const identity = ensureInstanceIdentity({ vaultPath, dataPath });
  const stateDb = openExistingDatabase(initRes.dbPath);
  const operatorDb = openOperatorDatabase(path.join(rootDir, 'operator', 'operator-state.sqlite'), {
    autoMigrate: true
  });
  const vectorsDbPath = path.join(dataPath, 'runtime', 'vectors.sqlite');
  const noteDir = path.join(vaultPath, '30_Knowledge_Notes');
  const queueDir = path.join(vaultPath, '40_Review_Queue');
  fs.mkdirSync(noteDir, { recursive: true });
  fs.mkdirSync(queueDir, { recursive: true });

  const nowIso = new Date().toISOString();
  const addSanitizedActive = (id, title, body, filename) => {
    const p = path.join(noteDir, filename);
    const md = [
      '---',
      `id: ${id}`,
      'note_type: decision',
      `title: ${title}`,
      'project: oam',
      'privacy: sanitized',
      'lifecycle: active',
      'review_state: accepted',
      '---',
      '',
      body
    ].join('\n');
    fs.writeFileSync(p, md, 'utf8');
    stateDb
      .prepare(
        `INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, review_state, status, created_at, updated_at)
         VALUES (?, 'decision', ?, 'oam', 'sanitized', ?, ?, 'active', 'accepted', 'active', ?, ?)`
      )
      .run(id, title, p, `sha-${id}`, nowIso, nowIso);
    return p;
  };

  addSanitizedActive(
    'kn-ch1-a',
    'Candidate Alpha Fallback Signal',
    'fallback signal alpha baseline guidance.',
    'DEC-20261114-000001_Alpha.md'
  );
  addSanitizedActive(
    'kn-ch1-b',
    'Candidate Beta Fallback Signal',
    'fallback signal beta distractor.',
    'DEC-20261114-000002_Beta.md'
  );
  addSanitizedActive(
    'kn-ch1-c',
    'Candidate Gamma Fallback Signal',
    'fallback signal gamma exact best answer.',
    'DEC-20261114-000003_Gamma.md'
  );
  addSanitizedActive(
    'kn-ch1-d',
    'Candidate Delta Fallback Signal',
    'fallback signal delta fourth note.',
    'DEC-20261114-000004_Delta.md'
  );

  // Local-only trap registered in DB
  const localPath = path.join(noteDir, 'DEC-20261114-000091_Local.md');
  fs.writeFileSync(
    localPath,
    [
      '---',
      'id: kn-trap-local',
      'note_type: decision',
      'title: Local Fallback Signal',
      'project: oam',
      'privacy: local_only',
      'lifecycle: active',
      'review_state: accepted',
      '---',
      '',
      `fallback signal ${RERANK_TRIAL_LOCAL_CANARY}`
    ].join('\n'),
    'utf8'
  );
  stateDb
    .prepare(
      `INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, review_state, status, created_at, updated_at)
       VALUES ('kn-trap-local', 'decision', 'Local Fallback Signal', 'oam', 'local_only', ?, 'sha-loc', 'active', 'accepted', 'active', ?, ?)`
    )
    .run(localPath, nowIso, nowIso);

  // Unregistered sanitized manual note (Channel 2)
  fs.writeFileSync(
    path.join(noteDir, 'DEC-20261114-000092_Unreg.md'),
    [
      '---',
      'id: kn-trap-unreg',
      'note_type: decision',
      'title: Unregistered Fallback Signal',
      'project: oam',
      'privacy: sanitized',
      'lifecycle: active',
      'review_state: accepted',
      '---',
      '',
      `fallback signal ${RERANK_TRIAL_UNREG_CANARY}`
    ].join('\n'),
    'utf8'
  );

  // Expired sanitized note (Channel 2)
  const expPath = path.join(noteDir, 'DEC-20261114-000093_Expired.md');
  fs.writeFileSync(
    expPath,
    [
      '---',
      'id: kn-trap-exp',
      'note_type: decision',
      'title: Expired Fallback Signal',
      'project: oam',
      'privacy: sanitized',
      'lifecycle: active',
      'review_state: accepted',
      'review_after: 2020-01-01',
      '---',
      '',
      `fallback signal ${RERANK_TRIAL_EXPIRED_CANARY}`
    ].join('\n'),
    'utf8'
  );
  stateDb
    .prepare(
      `INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, review_state, status, created_at, updated_at)
       VALUES ('kn-trap-exp', 'decision', 'Expired Fallback Signal', 'oam', 'sanitized', ?, 'sha-exp', 'active', 'accepted', 'active', ?, ?)`
    )
    .run(expPath, nowIso, nowIso);

  // Pending conflict proposal note (Channel 2)
  addSanitizedActive(
    'kn-trap-pending',
    'Pending Proposal Fallback Signal',
    `fallback signal ${RERANK_TRIAL_PENDING_CANARY}`,
    'DEC-20261114-000094_Pending.md'
  );
  fs.writeFileSync(
    path.join(queueDir, 'PROP-20261114-000094.md'),
    [
      '---',
      'id: prop-trap-94',
      'proposal_kind: conflict',
      'proposal_status: pending',
      'target_id: kn-trap-pending',
      '---',
      '',
      'Pending conflict proposal'
    ].join('\n'),
    'utf8'
  );

  return {
    vaultPath,
    dataPath,
    stateDb,
    operatorDb,
    vectorsDbPath,
    identity
  };
}

function issueStandardMockApprovals(operatorDb, { baseUrl, identity, embedCalls = 10, rerankCalls = 10, rerankMaxInput = 50_000 } = {}) {
  const common = {
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    expiresAt: futureIso(),
    trustedHumanContext: true
  };
  const embedDoc = issueCloudEgressApproval(operatorDb, {
    ...common,
    provider: 'siliconflow',
    endpointUrl: `${baseUrl}/v1/embeddings`,
    modelId: 'BAAI/bge-m3',
    purpose: 'embed_doc',
    scopeRef: 'corpus:v33-3-mock',
    corpusDigest: 'a'.repeat(64),
    queryEgressAllowed: 0,
    maxCalls: embedCalls,
    maxInputTokens: 50_000,
    maxOutputTokens: 0,
    maxCostMicroCny: 500_000
  });
  const embedQuery = issueCloudEgressApproval(operatorDb, {
    ...common,
    provider: 'siliconflow',
    endpointUrl: `${baseUrl}/v1/embeddings`,
    modelId: 'BAAI/bge-m3',
    purpose: 'embed_query',
    scopeRef: 'query:v33-3-mock',
    corpusDigest: 'b'.repeat(64),
    queryEgressAllowed: 1,
    maxCalls: embedCalls,
    maxInputTokens: 50_000,
    maxOutputTokens: 0,
    maxCostMicroCny: 500_000
  });
  const rerank = issueCloudEgressApproval(operatorDb, {
    ...common,
    provider: 'siliconflow',
    endpointUrl: `${baseUrl}/v1/rerank`,
    modelId: 'BAAI/bge-reranker-v2-m3',
    purpose: 'rerank',
    scopeRef: 'rerank:v33-3-mock',
    corpusDigest: 'c'.repeat(64),
    queryEgressAllowed: 1,
    maxCalls: rerankCalls,
    maxInputTokens: rerankMaxInput,
    maxOutputTokens: 0,
    maxCostMicroCny: 500_000
  });
  return { embedDoc, embedQuery, rerank };
}

function assertExactMode0Parity(actualFallback, expectedMode0) {
  assert.equal(actualFallback.fallbackUsed, true);
  assert.equal(actualFallback.mode, 'literal');
  assert.equal(actualFallback.cloudUsed, false);
  assert.equal(actualFallback.noAnswer, expectedMode0.noAnswer);
  assert.deepEqual(
    actualFallback.items.map((it) => ({ id: it.id, score: it.score, actionable: it.actionable })),
    expectedMode0.items.map((it) => ({ id: it.id, score: it.score, actionable: it.actionable }))
  );
}

test('V3.3-T10a: Frozen Channel 1 pool standalone /rerank benchmark (0 embed_query calls, hit@1 lift, 0 Channel 2 & 0 UUID leak)', async (t) => {
  const root = makeTempDir('oam-v33-t10a-');
  const wsDir = path.join(root, 'workspace');
  let operatorDb = null;
  let mock = null;
  t.after(async () => {
    if (mock) await mock.close();
    try { operatorDb?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  mock = await startMockServer(async (req, res) => {
    if (req.url === '/v1/embeddings') {
      const inputs = req.json?.input || [];
      const data = inputs.map((text, idx) => {
        let vec = [0.2, 0.2, 0.96];
        if (text.includes('RERANK_MARKER_TARGET_PG_STORM') || text.includes('客户数打满')) vec = [0.99, 0.05, 0.05];
        else if (text.includes('RERANK_MARKER_TARGET_WAL_ACL') || text.includes('伴生共享页')) vec = [0.05, 0.99, 0.05];
        else if (text.includes('RERANK_MARKER_TARGET_3XX') || text.includes('重定向')) vec = [0.6, 0.6, 0.5];
        else if (text.includes('RERANK_MARKER_TARGET_NTFS') || text.includes('微软盘符')) vec = [0.5, 0.1, 0.85];
        return { index: idx, embedding: vec };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data, usage: { prompt_tokens: 18 } }));
      return;
    }

    if (req.url === '/v1/rerank') {
      const q = req.json?.query || '';
      const docs = req.json?.documents || [];
      const scored = docs.map((doc, idx) => {
        let rel = 0.1 - idx * 0.01;
        if (q.includes('客户数打满') && doc.includes('RERANK_MARKER_TARGET_PG_STORM')) rel = 0.99;
        if (q.includes('伴生共享页') && doc.includes('RERANK_MARKER_TARGET_WAL_ACL')) rel = 0.99;
        if (q.includes('重定向') && doc.includes('RERANK_MARKER_TARGET_3XX')) rel = 0.99;
        if (q.includes('微软盘符') && doc.includes('RERANK_MARKER_TARGET_NTFS')) rel = 0.99;
        return { index: idx, relevance_score: rel };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ results: scored, usage: { prompt_tokens: 45 } }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  // First initialize workspace so vault_id/data_id exist, then issue scoped approvals
  const { initFrozenRerankWorkspace } = await import('../src/benchmark/rerank-frozen-trial.mjs');
  const meta = initFrozenRerankWorkspace({ workspaceDir: wsDir });
  operatorDb = openOperatorDatabase(path.join(root, 'operator-state.sqlite'), { autoMigrate: true });
  const apps = issueStandardMockApprovals(operatorDb, {
    baseUrl: mock.baseUrl,
    identity: { vaultId: meta.vault_id, dataId: meta.data_id },
    embedCalls: 20,
    rerankCalls: 20
  });

  const report = await runFrozenRerankTrial({
    workspaceDir: wsDir,
    operatorDb,
    embedDocApprovalId: apps.embedDoc.cloud_approval_id,
    embedQueryApprovalId: apps.embedQuery.cloud_approval_id,
    rerankApprovalId: apps.rerank.cloud_approval_id,
    provider: 'siliconflow',
    baseUrl: mock.baseUrl,
    apiKeyProvider: syntheticApiKey(),
    testContext: true,
    overallDeadlineMs: 5000,
    runTwoStageMode2: true
  });

  assert.equal(report.dailyDefaultModeMaintained, 'literal');
  assert.equal(report.liveVaultMutated, false);
  assert.ok(fs.existsSync(report.reportPath));

  // Standalone frozen pool /rerank lifts poor baseline ranking (hitAt1=0 -> 1.0, hitAt5=1.0, mrrAt5=1.0)
  assert.equal(report.comparison.frozenBaselinePool.hitAt5, 1);
  assert.equal(report.comparison.frozenBaselinePool.hitAt1, 0);
  assert.ok(report.comparison.mode0Literal.hitAt1 < 1);
  assert.equal(report.comparison.standaloneFrozenRerank.hitAt1, 1);
  assert.equal(report.comparison.standaloneFrozenRerank.hitAt5, 1);
  assert.equal(report.comparison.standaloneFrozenRerank.mrrAt5, 1);

  // Every standalone frozen question made ZERO /v1/embeddings calls and strictly 1 /v1/rerank call
  for (const pq of report.comparison.perQuestion) {
    assert.equal(pq.liftedToRank1, true);
    assert.equal(pq.outboundRequestsForQuestion.length, 1);
    assert.ok(pq.outboundRequestsForQuestion[0].endsWith('/v1/rerank'));
  }

  // Two-stage Mode 2 RunPlan end-to-end also hits 1.0
  assert.equal(report.comparison.twoStageMode2RunPlan.hitAt1, 1);
  assert.equal(report.comparison.twoStageMode2RunPlan.mrrAt5, 1);

  // Zero privacy / Channel 2 / UUID / Vault path leakage in captured HTTP payloads
  assert.equal(report.privacyAudit.localOnlyCanaryLeaked, false);
  assert.equal(report.privacyAudit.unregisteredCanaryLeaked, false);
  assert.equal(report.privacyAudit.expiredCanaryLeaked, false);
  assert.equal(report.privacyAudit.pendingProposalCanaryLeaked, false);
  assert.equal(report.privacyAudit.noteUuidLeaked, false);
  assert.equal(report.privacyAudit.vaultPathLeaked, false);

  const rerankReqs = mock.requests.filter((r) => r.url === '/v1/rerank');
  assert.equal(rerankReqs.length, 8); // 4 standalone + 4 two-stage
  for (const req of rerankReqs) {
    const joinedDocs = (req.json?.documents || []).join('\n');
    assert.ok(!joinedDocs.includes('KN-019316a8-'));
    assert.ok(!joinedDocs.includes(RERANK_TRIAL_LOCAL_CANARY));
    assert.ok(!joinedDocs.includes(RERANK_TRIAL_UNREG_CANARY));
    assert.ok(!joinedDocs.includes(RERANK_TRIAL_EXPIRED_CANARY));
    assert.ok(!joinedDocs.includes(RERANK_TRIAL_PENDING_CANARY));
  }
});

test('V3.3-T10b: Two-stage RunPlan lacking rerank quota/status dispatches ZERO embed_query HTTP requests and falls back to exact Mode 0', async (t) => {
  const root = makeTempDir('oam-v33-t10b-');
  let env = null;
  let mock = null;
  t.after(async () => {
    if (mock) await mock.close();
    try { env?.stateDb?.close(); } catch {}
    try { env?.operatorDb?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  env = setupRerankFixtureVault(root);
  mock = await startMockServer(async (req, res) => {
    res.writeHead(500);
    res.end('should never receive outbound traffic when RunPlan reservation fails');
  });

  await indexSanitizedVaultVectors({
    stateDb: env.stateDb,
    vectorsDbPath: env.vectorsDbPath,
    vaultDir: env.vaultPath,
    provider: 'siliconflow',
    model: 'BAAI/bge-m3',
    embedTextsFn: async (texts) => ({
      dimension: 3,
      vectors: texts.map(() => [1, 0, 0])
    })
  });

  const apps = issueStandardMockApprovals(env.operatorDb, {
    baseUrl: mock.baseUrl,
    identity: env.identity,
    embedCalls: 10,
    rerankCalls: 10,
    rerankMaxInput: 80 // Too small for two-stage rerank reservation
  });
  const exhaustedRerank = issueCloudEgressApproval(env.operatorDb, {
    provider: 'siliconflow',
    endpointUrl: `${mock.baseUrl}/v1/rerank`,
    modelId: 'BAAI/bge-reranker-v2-m3',
    purpose: 'rerank',
    scopeRef: 'rerank:exhausted',
    corpusDigest: 'd'.repeat(64),
    queryEgressAllowed: 1,
    maxCalls: 1,
    maxInputTokens: 50_000,
    maxOutputTokens: 0,
    maxCostMicroCny: 500_000,
    boundVaultId: env.identity.vaultId,
    boundDataId: env.identity.dataId,
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  // Consume the single call via revoke after issuing another active one, or revoke directly
  revokeCloudEgressApproval(env.operatorDb, { cloudApprovalId: exhaustedRerank.cloud_approval_id });

  const mode0Expected = searchKnowledge({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'literal',
    topK: 5
  });

  // 1. Rerank maxInputTokens insufficient for RunPlan -> 0 embed_query calls
  const lowTokensRes = await searchKnowledgeAsync({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'rerank',
    topK: 5,
    cloudConfig: {
      operatorDb: env.operatorDb,
      embedApprovalId: apps.embedQuery.cloud_approval_id,
      rerankApprovalId: apps.rerank.cloud_approval_id,
      provider: 'siliconflow',
      baseUrl: mock.baseUrl,
      apiKeyProvider: syntheticApiKey(),
      vaultId: env.identity.vaultId,
      dataId: env.identity.dataId,
      vectorsDbPath: env.vectorsDbPath,
      testContext: true
    }
  });
  assertExactMode0Parity(lowTokensRes, mode0Expected);
  assert.match(lowTokensRes.fallbackReason, /run_plan_reservation_failed:ERR_CLOUD_BUDGET_EXCEEDED/);
  assert.equal(mock.requests.length, 0);

  // 2. Rerank approval revoked before RunPlan -> 0 embed_query calls
  const revokedRes = await searchKnowledgeAsync({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'rerank',
    topK: 5,
    cloudConfig: {
      operatorDb: env.operatorDb,
      embedApprovalId: apps.embedQuery.cloud_approval_id,
      rerankApprovalId: exhaustedRerank.cloud_approval_id,
      provider: 'siliconflow',
      baseUrl: mock.baseUrl,
      apiKeyProvider: syntheticApiKey(),
      vaultId: env.identity.vaultId,
      dataId: env.identity.dataId,
      vectorsDbPath: env.vectorsDbPath,
      testContext: true
    }
  });
  assertExactMode0Parity(revokedRes, mode0Expected);
  assert.match(revokedRes.fallbackReason, /run_plan_reservation_failed:ERR_APPROVAL_REVOKED/);
  assert.equal(mock.requests.length, 0);

  // Confirm embed_query approval had ZERO reservations leaked and ZERO calls used
  const embedRow = env.operatorDb
    .prepare('SELECT reserved_calls, used_calls, used_input_tokens FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(apps.embedQuery.cloud_approval_id);
  assert.equal(embedRow.reserved_calls, 0);
  assert.equal(embedRow.used_calls, 0);
  assert.equal(embedRow.used_input_tokens, 0);
});

test('V3.3-T10c: Mid-flight rerank revoke after embed_query settles cancels unsent /rerank immediately and releases reservation', async (t) => {
  const root = makeTempDir('oam-v33-t10c-');
  let env = null;
  let mock = null;
  t.after(async () => {
    if (mock) await mock.close();
    try { env?.stateDb?.close(); } catch {}
    try { env?.operatorDb?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  env = setupRerankFixtureVault(root);
  let apps = null;
  mock = await startMockServer(async (req, res) => {
    if (req.url === '/v1/embeddings') {
      // Simulate operator revoking rerank approval immediately after embed_query finishes!
      revokeCloudEgressApproval(env.operatorDb, { cloudApprovalId: apps.rerank.cloud_approval_id });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: [{ index: 0, embedding: [1, 0, 0] }], usage: { prompt_tokens: 9 } }));
      return;
    }
    if (req.url === '/v1/rerank') {
      res.writeHead(500);
      res.end('revoked rerank MUST NEVER be sent over network');
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await indexSanitizedVaultVectors({
    stateDb: env.stateDb,
    vectorsDbPath: env.vectorsDbPath,
    vaultDir: env.vaultPath,
    provider: 'siliconflow',
    model: 'BAAI/bge-m3',
    embedTextsFn: async (texts) => ({
      dimension: 3,
      vectors: texts.map(() => [1, 0, 0])
    })
  });

  apps = issueStandardMockApprovals(env.operatorDb, { baseUrl: mock.baseUrl, identity: env.identity });

  const mode0Expected = searchKnowledge({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'literal',
    topK: 5
  });

  const res = await searchKnowledgeAsync({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'rerank',
    topK: 5,
    cloudConfig: {
      operatorDb: env.operatorDb,
      embedApprovalId: apps.embedQuery.cloud_approval_id,
      rerankApprovalId: apps.rerank.cloud_approval_id,
      provider: 'siliconflow',
      baseUrl: mock.baseUrl,
      apiKeyProvider: syntheticApiKey(),
      vaultId: env.identity.vaultId,
      dataId: env.identity.dataId,
      vectorsDbPath: env.vectorsDbPath,
      testContext: true
    }
  });

  assertExactMode0Parity(res, mode0Expected);
  assert.match(res.fallbackReason, /cloud_rerank_failed:ERR_APPROVAL_REVOKED/);

  // Only 1 outbound HTTP call (/v1/embeddings); ZERO /v1/rerank calls
  assert.equal(mock.requests.length, 1);
  assert.equal(mock.requests[0].url, '/v1/embeddings');

  // Ledger state: embed_query settled/ok; rerank released_precheck_failed/denied with 0 egress_bytes
  const embedLedger = env.operatorDb
    .prepare("SELECT reservation_state, outcome, prompt_tokens FROM cloud_egress_usage_ledger WHERE purpose = 'embed_query'")
    .get();
  assert.equal(embedLedger.reservation_state, 'settled');
  assert.equal(embedLedger.outcome, 'ok');
  assert.equal(embedLedger.prompt_tokens, 9);

  const rerankLedger = env.operatorDb
    .prepare("SELECT reservation_state, outcome, egress_bytes FROM cloud_egress_usage_ledger WHERE purpose = 'rerank'")
    .get();
  assert.equal(rerankLedger.reservation_state, 'released_precheck_failed');
  assert.equal(rerankLedger.outcome, 'denied');
  assert.equal(rerankLedger.egress_bytes, 0);

  const rerankAppRow = env.operatorDb
    .prepare('SELECT reserved_calls, used_calls FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(apps.rerank.cloud_approval_id);
  assert.equal(rerankAppRow.reserved_calls, 0);
  assert.equal(rerankAppRow.used_calls, 0);
});

test('V3.3-T10d: Partial subset tail order preservation, unsubmitted tail preservation, and [] / out-of-range / duplicate / non-finite / 502 fallback to exact Mode 0', async (t) => {
  const root = makeTempDir('oam-v33-t10d-');
  let env = null;
  let mock = null;
  t.after(async () => {
    if (mock) await mock.close();
    try { env?.stateDb?.close(); } catch {}
    try { env?.operatorDb?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  env = setupRerankFixtureVault(root);
  let rerankBehavior = 'partial';
  mock = await startMockServer(async (req, res) => {
    if (req.url === '/v1/rerank') {
      if (rerankBehavior === 'partial') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            results: [
              { index: 2, relevance_score: 0.96 },
              { index: 0, relevance_score: 0.72 }
            ],
            usage: { prompt_tokens: 33 }
          })
        );
        return;
      }
      if (rerankBehavior === 'empty') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ results: [], usage: { prompt_tokens: 15 } }));
        return;
      }
      if (rerankBehavior === 'out_of_range') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ results: [{ index: 99, relevance_score: 0.9 }], usage: { prompt_tokens: 15 } }));
        return;
      }
      if (rerankBehavior === 'duplicate') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            results: [
              { index: 0, relevance_score: 0.9 },
              { index: 0, relevance_score: 0.8 }
            ],
            usage: { prompt_tokens: 15 }
          })
        );
        return;
      }
      if (rerankBehavior === 'non_finite') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ results: [{ index: 0, relevance_score: null }], usage: { prompt_tokens: 15 } }));
        return;
      }
      if (rerankBehavior === 'upstream_502') {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad gateway' }));
        return;
      }
    }
    res.writeHead(404);
    res.end();
  });

  const apps = issueStandardMockApprovals(env.operatorDb, { baseUrl: mock.baseUrl, identity: env.identity, rerankCalls: 20 });

  // 1. Partial subset: submit 4 Channel 1 + Channel 2 trap; mock returns [2, 0] -> expects [c, a, b, d, ...channel2]
  const frozenMixed = ['kn-ch1-a', 'kn-ch1-b', 'kn-ch1-c', 'kn-ch1-d', 'kn-trap-exp', 'kn-trap-pending', 'kn-trap-unreg', 'kn-trap-local'];
  const partialRes = await rerankFrozenCandidatesAsync({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    frozenCandidates: frozenMixed,
    todayStr: '2026-11-14',
    topK: 10,
    cloudConfig: {
      operatorDb: env.operatorDb,
      rerankApprovalId: apps.rerank.cloud_approval_id,
      provider: 'siliconflow',
      baseUrl: mock.baseUrl,
      apiKeyProvider: syntheticApiKey(),
      vaultId: env.identity.vaultId,
      dataId: env.identity.dataId,
      testContext: true
    }
  });
  assert.equal(partialRes.cloudUsed, true);
  assert.equal(partialRes.fallbackUsed, false);
  const partialCh1Ids = partialRes.items.filter((i) => i.actionable).map((i) => i.id);
  assert.deepEqual(partialCh1Ids, ['kn-ch1-c', 'kn-ch1-a', 'kn-ch1-b', 'kn-ch1-d']);
  const partialCh2Ids = partialRes.items.filter((i) => !i.actionable).map((i) => i.id);
  assert.deepEqual(partialCh2Ids, ['kn-trap-exp', 'kn-trap-pending', 'kn-trap-unreg']); // local_only never included

  const sentDocs = mock.requests[0].json.documents;
  assert.equal(sentDocs.length, 4);
  const rawJoined = mock.requests[0].rawBody;
  assert.ok(!rawJoined.includes(RERANK_TRIAL_LOCAL_CANARY));
  assert.ok(!rawJoined.includes(RERANK_TRIAL_UNREG_CANARY));
  assert.ok(!rawJoined.includes(RERANK_TRIAL_EXPIRED_CANARY));
  assert.ok(!rawJoined.includes(RERANK_TRIAL_PENDING_CANARY));
  assert.ok(!rawJoined.includes('kn-ch1-'));

  // 2. Malformed responses & HTTP 502 fall back identically to Mode 0
  const mode0Expected = searchKnowledge({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'literal',
    topK: 5
  });

  for (const modeName of ['empty', 'out_of_range', 'duplicate', 'non_finite', 'upstream_502']) {
    rerankBehavior = modeName;
    const fb = await rerankFrozenCandidatesAsync({
      db: env.stateDb,
      vaultDir: env.vaultPath,
      query: 'fallback signal',
      frozenCandidates: ['kn-ch1-a', 'kn-ch1-b', 'kn-ch1-c', 'kn-ch1-d'],
      todayStr: '2026-11-14',
      topK: 5,
      cloudConfig: {
        operatorDb: env.operatorDb,
        rerankApprovalId: apps.rerank.cloud_approval_id,
        provider: 'siliconflow',
        baseUrl: mock.baseUrl,
        apiKeyProvider: syntheticApiKey(),
        vaultId: env.identity.vaultId,
        dataId: env.identity.dataId,
        testContext: true
      }
    });
    assertExactMode0Parity(fb, mode0Expected);
  }
});

test('V3.3-T10e: Forged frozenCandidates fields cannot bypass DB/Markdown gate, and overallDeadlineMs expiry cancels /rerank pre-send', async (t) => {
  const root = makeTempDir('oam-v33-t10e-');
  let env = null;
  let mock = null;
  t.after(async () => {
    if (mock) await mock.close();
    try { env?.stateDb?.close(); } catch {}
    try { env?.operatorDb?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  env = setupRerankFixtureVault(root);
  mock = await startMockServer(async (req, res) => {
    if (req.url === '/v1/embeddings') {
      // Sleep longer than overallDeadlineMs so inter-stage deadline check aborts /rerank
      setTimeout(() => {
        if (!res.destroyed) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ data: [{ index: 0, embedding: [1, 0, 0] }], usage: { prompt_tokens: 8 } }));
        }
      }, 120);
      return;
    }
    if (req.url === '/v1/rerank') {
      const docs = req.json?.documents || [];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          results: docs.map((_, idx) => ({ index: idx, relevance_score: 0.9 - idx * 0.1 })),
          usage: { prompt_tokens: 18 }
        })
      );
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await indexSanitizedVaultVectors({
    stateDb: env.stateDb,
    vectorsDbPath: env.vectorsDbPath,
    vaultDir: env.vaultPath,
    provider: 'siliconflow',
    model: 'BAAI/bge-m3',
    embedTextsFn: async (texts) => ({
      dimension: 3,
      vectors: texts.map(() => [1, 0, 0])
    })
  });

  const apps = issueStandardMockApprovals(env.operatorDb, { baseUrl: mock.baseUrl, identity: env.identity });

  // 1. Caller passes forged actionable:true + privacy:'sanitized' for trap IDs -> MUST be ignored/re-verified
  const forgedInput = [
    { id: 'kn-trap-local', actionable: true, privacy: 'sanitized', title: 'Forged Local', snippet: 'Forged' },
    { id: 'kn-trap-unreg', actionable: true, privacy: 'sanitized', title: 'Forged Unreg', snippet: 'Forged' },
    { id: 'kn-trap-exp', actionable: true, privacy: 'sanitized', title: 'Forged Exp', snippet: 'Forged' },
    { id: 'kn-trap-pending', actionable: true, privacy: 'sanitized', title: 'Forged Pend', snippet: 'Forged' },
    { id: 'kn-ch1-a', actionable: true, title: 'Forged Title', snippet: 'Forged Body' }
  ];
  const forgeRes = await rerankFrozenCandidatesAsync({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    frozenCandidates: forgedInput,
    todayStr: '2026-11-14',
    topK: 10,
    cloudConfig: {
      operatorDb: env.operatorDb,
      rerankApprovalId: apps.rerank.cloud_approval_id,
      provider: 'siliconflow',
      baseUrl: mock.baseUrl,
      apiKeyProvider: syntheticApiKey(),
      vaultId: env.identity.vaultId,
      dataId: env.identity.dataId,
      testContext: true
    }
  });
  assert.equal(forgeRes.cloudUsed, true);
  assert.equal(mock.requests.length, 1);
  assert.equal(mock.requests[0].json.documents.length, 1);
  assert.ok(mock.requests[0].json.documents[0].includes('Candidate Alpha Fallback Signal'));
  assert.ok(!mock.requests[0].rawBody.includes('Forged'));
  assert.ok(!mock.requests[0].rawBody.includes(RERANK_TRIAL_LOCAL_CANARY));

  // 2. Inter-stage overallDeadlineMs exhausted after slow /v1/embeddings -> /v1/rerank cancelled with 0 HTTP calls
  mock.requests.length = 0;
  const mode0Expected = searchKnowledge({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'literal',
    topK: 5
  });
  const deadlineRes = await searchKnowledgeAsync({
    db: env.stateDb,
    vaultDir: env.vaultPath,
    query: 'fallback signal',
    todayStr: '2026-11-14',
    mode: 'rerank',
    topK: 5,
    cloudConfig: {
      operatorDb: env.operatorDb,
      embedApprovalId: apps.embedQuery.cloud_approval_id,
      rerankApprovalId: apps.rerank.cloud_approval_id,
      provider: 'siliconflow',
      baseUrl: mock.baseUrl,
      apiKeyProvider: syntheticApiKey(),
      vaultId: env.identity.vaultId,
      dataId: env.identity.dataId,
      vectorsDbPath: env.vectorsDbPath,
      overallDeadlineMs: 110,
      testContext: true
    }
  });
  assertExactMode0Parity(deadlineRes, mode0Expected);
  assert.equal(mock.requests.filter((r) => r.url === '/v1/rerank').length, 0);
});
