import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import { createConsistentBackup, restoreFromBackup } from '../src/backup/backup-manager.mjs';
import { restoreNote } from '../src/storage/restore-manager.mjs';
import {
  issueTrustedEgressApproval,
  issueTrustedLowSensitivityApproval,
  verifyEgressApproval,
  verifyLowSensitivityIngestApproval
} from '../src/security/trusted-approvals.mjs';
import { readInstanceIdentity } from '../src/storage/instance-identity.mjs';
import {
  CLOUD_EGRESS_PURPOSES,
  CLOUD_ISSUER_CHANNELS,
  CLOUD_RESERVATION_STATES,
  CLOUD_LEDGER_OUTCOMES,
  openOperatorDatabase,
  migrateCloudEgressSchema,
  issueCloudEgressApproval,
  verifyCloudEgressApproval,
  revokeCloudEgressApproval,
  reserveCloudEgressBudget,
  reserveRunPlanBudgets,
  recheckApprovalBeforeSend,
  releasePrecheckFailedReservation,
  settleCloudEgressUsage,
  retainCloudEgressReservation,
  recoverCrashRetainedReservations,
  reconcileRetainedLedgerEntry,
  restoreOperatorDatabase,
  estimateWorstCaseCostMicroCny,
  computeBillableOutputTokens,
  DEFAULT_PRICING_CATALOG
} from '../src/security/cloud-approvals.mjs';
import { sanitizePayloadForExitA } from '../src/egress/egress-controller.mjs';
import {
  runFourPointCloudIsolationSentinel,
  assertRealCloudApiGate
} from '../src/security/isolation-sentinel.mjs';

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function futureIso(hours = 2) {
  return new Date(Date.now() + hours * 3600_000).toISOString();
}

function buildSyntheticSecret() {
  return ['sk', 'proj', 'syntheticTestToken1234567890'].join('-');
}

function setupSampleRepo(rootDir) {
  const vaultPath = path.join(rootDir, 'vault');
  const dataPath = path.join(rootDir, 'data');
  const initRes = initRepository({ vaultPath, dataPath });
  const operatorDbPath = path.join(dataPath, 'runtime', 'operator-state.sqlite');
  return { vaultPath, dataPath, stateDbPath: initRes.dbPath, operatorDbPath, identity: initRes.instanceIdentity };
}

test('V3.3-T05: PLAN.md §4.2 verbatim STRICT schema, enums, safe-int guards, V2.5 bidirectional isolation, and explicit migration', (t) => {
  const root = makeTempDir('oam-v33-t05-');
  let stateDb = null;
  let opDb = null;
  let roOpDb = null;
  const prevProd = process.env.OAM_PRODUCTION_CLI;
  t.after(() => {
    if (prevProd === undefined) delete process.env.OAM_PRODUCTION_CLI;
    else process.env.OAM_PRODUCTION_CLI = prevProd;
    for (const d of [roOpDb, opDb, stateDb]) {
      try { d?.close(); } catch {}
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  const { stateDbPath, operatorDbPath, identity } = setupSampleRepo(root);

  // 1. openDatabase() on state.sqlite keeps V2.5 tables intact and does NOT auto-create cloud tables
  stateDb = openExistingDatabase(stateDbPath);
  const stateTables = stateDb
    .prepare("SELECT name FROM sqlite_master WHERE type='table'")
    .all()
    .map((r) => r.name);
  assert.ok(stateTables.includes('egress_approvals'));
  assert.ok(!stateTables.includes('cloud_egress_approvals'));
  assert.ok(!stateTables.includes('cloud_egress_usage_ledger'));

  // 2. openOperatorDatabase readOnly=false without autoMigrate does not write DDL, explicit migrate creates STRICT tables
  opDb = openOperatorDatabase(operatorDbPath, { autoMigrate: false });
  const beforeMigrateTables = opDb
    .prepare("SELECT name FROM sqlite_master WHERE type='table'")
    .all()
    .map((r) => r.name);
  assert.equal(beforeMigrateTables.length, 0);

  migrateCloudEgressSchema(opDb);

  // Verify verbatim PLAN.md §4.2 columns for cloud_egress_approvals & cloud_egress_usage_ledger
  const approvalCols = opDb.prepare('PRAGMA table_info(cloud_egress_approvals)').all().map((c) => c.name);
  assert.deepEqual(approvalCols, [
    'cloud_approval_id',
    'purpose',
    'scope_ref',
    'corpus_digest',
    'bound_vault_id',
    'bound_data_id',
    'query_egress_allowed',
    'provider',
    'endpoint_url',
    'model_id',
    'pricing_version',
    'allowed_fields_json',
    'approved_by',
    'issuer_channel',
    'approval_token_sha256',
    'max_calls',
    'reserved_calls',
    'used_calls',
    'max_input_tokens',
    'reserved_input_tokens',
    'used_input_tokens',
    'max_output_tokens',
    'reserved_output_tokens',
    'used_output_tokens',
    'max_output_tokens_per_call',
    'max_cost_micro_cny',
    'reserved_cost_micro_cny',
    'used_cost_micro_cny',
    'status',
    'created_at',
    'expires_at'
  ]);

  const ledgerCols = opDb.prepare('PRAGMA table_info(cloud_egress_usage_ledger)').all().map((c) => c.name);
  assert.deepEqual(ledgerCols, [
    'request_id',
    'parent_request_id',
    'attempt_no',
    'run_plan_id',
    'cloud_approval_id',
    'purpose',
    'query_egress_allowed',
    'provider',
    'endpoint_url',
    'model_id',
    'pricing_version',
    'reservation_state',
    'http_status',
    'reserved_input_tokens',
    'reserved_output_tokens',
    'prompt_tokens',
    'completion_tokens',
    'reasoning_tokens',
    'billable_output_tokens',
    'total_tokens',
    'reserved_cost_micro_cny',
    'billed_cost_micro_cny',
    'egress_bytes',
    'latency_ms',
    'outcome',
    'created_at',
    'settled_at'
  ]);

  assert.deepEqual(CLOUD_EGRESS_PURPOSES, ['distill', 'embed_doc', 'embed_query', 'rerank', 'judge']);
  assert.deepEqual(CLOUD_ISSUER_CHANNELS, ['operator_cli', 'operator_tty_ps1', 'test_harness']);
  assert.deepEqual(CLOUD_RESERVATION_STATES, [
    'reserved',
    'settled',
    'retained_on_timeout',
    'retained_on_unknown_bill',
    'released_precheck_failed'
  ]);
  assert.deepEqual(CLOUD_LEDGER_OUTCOMES, [
    'pending',
    'ok',
    'denied',
    'timeout',
    'http_error',
    'invalid_response',
    'crash_retained'
  ]);

  // Read-only open works without attempting DDL writes
  roOpDb = openOperatorDatabase(operatorDbPath, { readOnly: true });
  assert.equal(
    roOpDb.prepare('SELECT COUNT(*) AS cnt FROM cloud_egress_approvals').get().cnt,
    0
  );

  // 3. Reject legacy/invalid purpose & issuer_channel at both application layer and SQLite CHECK
  assert.throws(
    () =>
      issueCloudEgressApproval(opDb, {
        purpose: 'embed_index',
        scopeRef: 'corpus:abc',
        corpusDigest: 'a'.repeat(64),
        boundVaultId: identity.vaultId,
        boundDataId: identity.dataId,
        provider: 'siliconflow',
        endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
        modelId: 'BAAI/bge-m3',
        issuerChannel: 'operator_cli',
        approvedBy: 'tester',
        maxCalls: 1,
        maxInputTokens: 1000,
        maxOutputTokens: 0,
        maxCostMicroCny: 1000,
        expiresAt: futureIso(),
        trustedHumanContext: true
      }),
    /ERR_INVALID_PURPOSE/
  );

  for (const badChannel of ['cli_interactive', 'local_operator_ui']) {
    assert.throws(
      () =>
        issueCloudEgressApproval(opDb, {
          purpose: 'embed_doc',
          scopeRef: 'corpus:abc',
          corpusDigest: 'a'.repeat(64),
          boundVaultId: identity.vaultId,
          boundDataId: identity.dataId,
          provider: 'siliconflow',
          endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
          modelId: 'BAAI/bge-m3',
          issuerChannel: badChannel,
          approvedBy: 'tester',
          maxCalls: 1,
          maxInputTokens: 1000,
          maxOutputTokens: 0,
          maxCostMicroCny: 1000,
          expiresAt: futureIso(),
          trustedHumanContext: true
        }),
      /ERR_INVALID_ISSUER_CHANNEL/
    );
  }

  // 4. Reject float (1.5), negative (-1), 0, and unsafe (> MAX_SAFE_INTEGER) at application layer AND SQLite STRICT/CHECK
  for (const badInt of [1.5, -1, 0, Number.MAX_SAFE_INTEGER + 1, Number.NaN]) {
    assert.throws(
      () =>
        issueCloudEgressApproval(opDb, {
          purpose: 'embed_query',
          scopeRef: 'query-session:s1',
          corpusDigest: 'a'.repeat(64),
          boundVaultId: identity.vaultId,
          boundDataId: identity.dataId,
          queryEgressAllowed: 1,
          provider: 'siliconflow',
          endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
          modelId: 'BAAI/bge-m3',
          issuerChannel: 'operator_cli',
          approvedBy: 'tester',
          maxCalls: badInt,
          maxInputTokens: 1000,
          maxOutputTokens: 0,
          maxCostMicroCny: 1000,
          expiresAt: futureIso(),
          trustedHumanContext: true
        }),
      /ERR_INVALID_POSITIVE_INTEGER/
    );
  }

  // Raw SQLite STRICT table rejects float 1.5 and invalid CHECK values directly
  assert.throws(() => {
    opDb
      .prepare(
        `INSERT INTO cloud_egress_approvals (
          cloud_approval_id, purpose, scope_ref, corpus_digest,
          bound_vault_id, bound_data_id, query_egress_allowed,
          provider, endpoint_url, model_id, pricing_version,
          allowed_fields_json, approved_by, issuer_channel, approval_token_sha256,
          max_calls, max_input_tokens, max_output_tokens, max_output_tokens_per_call,
          max_cost_micro_cny, created_at, expires_at
        ) VALUES (
          'CEGR-bad-strict', 'embed_query', 's', 'd', 'v', 'd', 1,
          'siliconflow', 'https://api.siliconflow.cn/v1/embeddings', 'BAAI/bge-m3', '2026-11-13-v1',
          '["query"]', 'op', 'operator_cli', 'tok',
          1.5, 100, 0, 0, 100, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'
        )`
      )
      .run();
  });

  // 5. Issue valid approvals via operator_cli and operator_tty_ps1 -> verify bidirectional isolation with V2.5
  const cegr = issueCloudEgressApproval(opDb, {
    purpose: 'embed_query',
    scopeRef: 'query-session:s1',
    corpusDigest: 'b'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 1,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    modelId: 'BAAI/bge-m3',
    allowedFields: ['title', 'sanitized_snippet'],
    approvedBy: 'human-alice',
    issuerChannel: 'operator_cli',
    maxCalls: 5,
    maxInputTokens: 10_000,
    maxOutputTokens: 0,
    maxCostMicroCny: 50_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  assert.ok(cegr.cloud_approval_id.startsWith('CEGR-'));

  const ttyJudgeApproval = issueCloudEgressApproval(opDb, {
    purpose: 'judge',
    scopeRef: 'frozen-pool:p1',
    corpusDigest: 'c'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 0,
    provider: 'deepseek',
    endpointUrl: 'https://api.deepseek.com/v1/chat/completions',
    modelId: 'deepseek-chat',
    approvedBy: 'human-alice',
    issuerChannel: 'operator_tty_ps1',
    maxCalls: 3,
    maxInputTokens: 20_000,
    maxOutputTokens: 3000,
    maxOutputTokensPerCall: 1024,
    maxCostMicroCny: 100_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  assert.equal(ttyJudgeApproval.purpose, 'judge');
  assert.equal(ttyJudgeApproval.issuer_channel, 'operator_tty_ps1');

  const v3Check = verifyCloudEgressApproval(opDb, {
    cloudApprovalId: cegr.cloud_approval_id,
    provider: 'siliconflow',
    modelId: 'BAAI/bge-m3',
    purpose: 'embed_query',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    vaultId: identity.vaultId,
    dataId: identity.dataId
  });
  assert.equal(v3Check.valid, true);

  const v25Egr = issueTrustedEgressApproval({
    db: stateDb,
    snapshotId: 'snap-1',
    provider: 'manual-export',
    purpose: 'review',
    approvedBy: 'human-alice',
    ttlHours: 24,
    trustedHumanContext: true
  });
  const v25Lsi = issueTrustedLowSensitivityApproval({
    db: stateDb,
    sourceTool: 'codex',
    sessionId: 'sess-1',
    approvedBy: 'human-alice',
    ttlHours: 24,
    trustedHumanContext: true
  });

  // V2.5 EGR-* rejected by V3.3 cloud verifier; V3.3 CEGR-* rejected by V2.5 verifiers
  const crossV3 = verifyCloudEgressApproval(opDb, { cloudApprovalId: v25Egr.egressApprovalId });
  assert.equal(crossV3.valid, false);
  assert.equal(crossV3.code, 'ERR_INVALID_CLOUD_APPROVAL_PREFIX');

  assert.equal(
    verifyEgressApproval({
      db: stateDb,
      egressApprovalId: cegr.cloud_approval_id,
      snapshotId: 'snap-1',
      provider: 'manual-export',
      purpose: 'review'
    }).valid,
    false
  );
  assert.equal(
    verifyLowSensitivityIngestApproval({
      db: stateDb,
      approvalId: cegr.cloud_approval_id,
      sourceTool: 'codex',
      sessionId: 'sess-1'
    }).valid,
    false
  );
  // V2.5 approvals remain valid
  assert.equal(
    verifyEgressApproval({
      db: stateDb,
      egressApprovalId: v25Egr.egressApprovalId,
      snapshotId: 'snap-1',
      provider: 'manual-export',
      purpose: 'review'
    }).valid,
    true
  );
  assert.equal(
    verifyLowSensitivityIngestApproval({
      db: stateDb,
      approvalId: v25Lsi.ingestApprovalId,
      sourceTool: 'codex',
      sessionId: 'sess-1'
    }).valid,
    true
  );

  // 6. Production CLI rejects test_harness channel; operator_cli rejects http:// loopback
  assert.throws(
    () =>
      issueCloudEgressApproval(opDb, {
        purpose: 'embed_doc',
        scopeRef: 'corpus:x',
        corpusDigest: 'd'.repeat(64),
        boundVaultId: identity.vaultId,
        boundDataId: identity.dataId,
        provider: 'siliconflow',
        endpointUrl: 'http://127.0.0.1:8080/v1/embeddings',
        modelId: 'BAAI/bge-m3',
        issuerChannel: 'operator_cli',
        approvedBy: 'op',
        maxCalls: 1,
        maxInputTokens: 100,
        maxOutputTokens: 0,
        maxCostMicroCny: 100,
        expiresAt: futureIso(),
        trustedHumanContext: true
      }),
    /ERR_LOOPBACK_FORBIDDEN_FOR_CHANNEL/
  );

  process.env.OAM_PRODUCTION_CLI = '1';
  try {
    assert.throws(
      () =>
        issueCloudEgressApproval(opDb, {
          purpose: 'embed_query',
          scopeRef: 'query-session:s1',
          corpusDigest: 'e'.repeat(64),
          boundVaultId: identity.vaultId,
          boundDataId: identity.dataId,
          queryEgressAllowed: 1,
          provider: 'siliconflow',
          endpointUrl: 'http://127.0.0.1:8080/v1/embeddings',
          modelId: 'BAAI/bge-m3',
          issuerChannel: 'test_harness',
          approvedBy: 'harness',
          maxCalls: 1,
          maxInputTokens: 100,
          maxOutputTokens: 0,
          maxCostMicroCny: 100,
          expiresAt: futureIso(),
          trustedHumanContext: true
        }),
      /ERR_TEST_HARNESS_FORBIDDEN_IN_PROD/
    );
  } finally {
    if (prevProd === undefined) delete process.env.OAM_PRODUCTION_CLI;
    else process.env.OAM_PRODUCTION_CLI = prevProd;
  }
});

test('V3.3-T05: mem restore does NOT trigger restore_locked; restoreFromBackup & operator DB rollback DO trigger restore_locked without affecting original instance', (t) => {
  const root = makeTempDir('oam-v33-t05-restore-');
  const openHandles = [];
  t.after(() => {
    for (const h of openHandles) {
      try { h?.close(); } catch {}
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  const { vaultPath, dataPath, stateDbPath, operatorDbPath, identity } = setupSampleRepo(root);

  const noteRelPath = 'notes/sample.md';
  const noteAbsPath = path.join(vaultPath, noteRelPath);
  const revDir = path.join(dataPath, 'revisions', 'note-1');
  fs.mkdirSync(revDir, { recursive: true });
  const revContent = '---\nid: note-1\ntitle: Sample\nprivacy: sanitized\n---\n\nRestored revision content\n';
  fs.writeFileSync(path.join(revDir, 'rev-1.md'), revContent, 'utf8');

  const stateDb = openExistingDatabase(stateDbPath);
  openHandles.push(stateDb);
  stateDb
    .prepare(
      `INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at, updated_at)
       VALUES ('note-1', 'decision', 'Sample', 'oam', 'sanitized', 'notes/sample.md', 'sha-1', 'active', ?, ?)`
    )
    .run(new Date().toISOString(), new Date().toISOString());

  const opDb = openOperatorDatabase(operatorDbPath, { autoMigrate: true });
  openHandles.push(opDb);
  const activeCegr = issueCloudEgressApproval(opDb, {
    purpose: 'embed_query',
    scopeRef: 'query-session:s1',
    corpusDigest: 'a'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 1,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    modelId: 'BAAI/bge-m3',
    issuerChannel: 'operator_cli',
    approvedBy: 'human-alice',
    maxCalls: 3,
    maxInputTokens: 5000,
    maxOutputTokens: 0,
    maxCostMicroCny: 20_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  const revokedCegr = issueCloudEgressApproval(opDb, {
    purpose: 'embed_doc',
    scopeRef: 'corpus:c1',
    corpusDigest: 'b'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 0,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    modelId: 'BAAI/bge-m3',
    issuerChannel: 'operator_tty_ps1',
    approvedBy: 'human-alice',
    maxCalls: 2,
    maxInputTokens: 5000,
    maxOutputTokens: 0,
    maxCostMicroCny: 20_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  revokeCloudEgressApproval(opDb, { cloudApprovalId: revokedCegr.cloud_approval_id, reason: 'spent_then_revoked' });

  // Single-note restore (mem restore equivalent) MUST NOT alter instance identity or cloud_egress_approvals
  const singleRestore = restoreNote({
    db: stateDb,
    noteId: 'note-1',
    revision: 'rev-1',
    content: revContent,
    targetVaultPath: noteAbsPath,
    stagingDir: path.join(dataPath, 'staging'),
    revisionsDir: path.join(dataPath, 'revisions'),
    confirm: true
  });
  assert.equal(singleRestore.restored, true);
  assert.equal(
    opDb.prepare('SELECT status FROM cloud_egress_approvals WHERE cloud_approval_id = ?').get(activeCegr.cloud_approval_id).status,
    'active'
  );
  const idAfterSingle = readInstanceIdentity({ vaultPath, dataPath });
  assert.equal(idAfterSingle.vaultId, identity.vaultId);
  assert.equal(idAfterSingle.dataId, identity.dataId);

  const opSnapshotBackup = path.join(root, 'operator-backup.sqlite');
  opDb.close();
  stateDb.close();
  fs.copyFileSync(operatorDbPath, opSnapshotBackup);

  const backupRoot = path.join(root, 'backups');
  const backupRes = createConsistentBackup({ vaultPath, dataPath, targetDir: backupRoot });

  const restoredVault = path.join(root, 'restored-vault');
  const restoredData = path.join(root, 'restored-data');
  const restoredOpDbPath = path.join(root, 'restored-operator-state.sqlite');
  fs.copyFileSync(opSnapshotBackup, restoredOpDbPath);

  const restoreRes = restoreFromBackup({
    backupDir: backupRes.backupDir,
    newVaultPath: restoredVault,
    newDataPath: restoredData,
    operatorDbPath: restoredOpDbPath
  });
  assert.equal(restoreRes.restored, true);
  assert.equal(restoreRes.instanceIdentity.restoredFromBackup, backupRes.backupId);
  assert.notEqual(restoreRes.instanceIdentity.vaultId, identity.vaultId);
  assert.notEqual(restoreRes.instanceIdentity.dataId, identity.dataId);
  assert.equal(restoreRes.cloudRestoreLock.operatorDbLock.lockedCount, 1);

  const restoredOpDb = openOperatorDatabase(restoredOpDbPath, { readOnly: true });
  openHandles.push(restoredOpDb);
  const lockedRow = restoredOpDb
    .prepare('SELECT status FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(activeCegr.cloud_approval_id);
  assert.equal(lockedRow.status, 'restore_locked');

  // Revoked approval stays revoked and cannot be resurrected via verify
  const revokedAfter = restoredOpDb
    .prepare('SELECT status FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(revokedCegr.cloud_approval_id);
  assert.equal(revokedAfter.status, 'revoked');

  const verifyLocked = verifyCloudEgressApproval(restoredOpDb, {
    cloudApprovalId: activeCegr.cloud_approval_id,
    vaultId: restoreRes.instanceIdentity.vaultId,
    dataId: restoreRes.instanceIdentity.dataId
  });
  assert.equal(verifyLocked.valid, false);
  assert.equal(verifyLocked.code, 'ERR_APPROVAL_RESTORE_LOCKED');

  // Original instance's operator DB remains completely active & untouched
  const origOpDb = openOperatorDatabase(operatorDbPath, { readOnly: true });
  openHandles.push(origOpDb);
  const origVerify = verifyCloudEgressApproval(origOpDb, {
    cloudApprovalId: activeCegr.cloud_approval_id,
    vaultId: identity.vaultId,
    dataId: identity.dataId
  });
  assert.equal(origVerify.valid, true);

  // Operator DB rollback onto same vault/data also triggers restore_locked
  const rollbackTarget = path.join(root, 'rollback-op.sqlite');
  const rollbackRes = restoreOperatorDatabase({
    sourceDbPath: opSnapshotBackup,
    targetDbPath: rollbackTarget,
    newVaultId: identity.vaultId,
    newDataId: identity.dataId
  });
  assert.equal(rollbackRes.lockedCount, 1);
  const rbDb = openOperatorDatabase(rollbackTarget, { readOnly: true });
  openHandles.push(rbDb);
  assert.equal(
    rbDb.prepare('SELECT status FROM cloud_egress_approvals WHERE cloud_approval_id = ?').get(activeCegr.cloud_approval_id).status,
    'restore_locked'
  );
});

test('V3.3-T06: reserved vs used split, output token & per-call caps, concurrency race, overrun_paused, RunPlan, crash_retained recovery & reconcile', async (t) => {
  const root = makeTempDir('oam-v33-t06-budget-');
  let db1 = null;
  let db2 = null;
  t.after(() => {
    try { db1?.close(); } catch {}
    try { db2?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  });

  const { operatorDbPath, identity } = setupSampleRepo(root);
  db1 = openOperatorDatabase(operatorDbPath, { autoMigrate: true });
  db2 = openOperatorDatabase(operatorDbPath, { autoMigrate: false });

  // A. Math.ceil worst-case estimation & reasoning token anti-double-count
  const chatPricing = DEFAULT_PRICING_CATALOG.deepseek['deepseek-reasoner'];
  assert.equal(
    estimateWorstCaseCostMicroCny({ inputTokens: 1, maxOutputTokens: 1, pricing: chatPricing }),
    5
  );
  assert.equal(
    estimateWorstCaseCostMicroCny({
      inputTokens: 1,
      maxOutputTokens: 0,
      pricing: DEFAULT_PRICING_CATALOG.siliconflow['BAAI/bge-m3']
    }),
    1
  );
  assert.equal(
    computeBillableOutputTokens({
      completionTokens: 120,
      reasoningTokens: 80,
      completionIncludesReasoning: true
    }),
    120
  );
  assert.equal(
    computeBillableOutputTokens({
      completionTokens: 40,
      reasoningTokens: 80,
      completionIncludesReasoning: false
    }),
    120
  );

  // B. Reserved vs Used split + output token caps + per-call output cap
  const judgeApproval = issueCloudEgressApproval(db1, {
    purpose: 'judge',
    scopeRef: 'frozen-pool:j1',
    corpusDigest: 'f'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 0,
    provider: 'deepseek',
    endpointUrl: 'https://api.deepseek.com/v1/chat/completions',
    modelId: 'deepseek-chat',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 4,
    maxInputTokens: 2000,
    maxOutputTokens: 300,
    maxOutputTokensPerCall: 200,
    maxCostMicroCny: 50_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });

  // Exceeding per-call output cap rejected before mutating reserved_*
  assert.throws(
    () =>
      reserveCloudEgressBudget(db1, {
        cloudApprovalId: judgeApproval.cloud_approval_id,
        requestId: 'judge-too-big-per-call',
        provider: 'deepseek',
        modelId: 'deepseek-chat',
        purpose: 'judge',
        reservedInputTokens: 100,
        maxOutputTokens: 250,
        vaultId: identity.vaultId,
        dataId: identity.dataId
      }),
    /ERR_OUTPUT_TOKENS_PER_CALL_EXCEEDED/
  );

  // Reserve call 1 with 200 output tokens -> ONLY reserved_* increases, used_* stays 0!
  const jRes1 = reserveCloudEgressBudget(db1, {
    cloudApprovalId: judgeApproval.cloud_approval_id,
    requestId: 'judge-res-1',
    provider: 'deepseek',
    modelId: 'deepseek-chat',
    purpose: 'judge',
    reservedInputTokens: 100,
    maxOutputTokens: 200,
    vaultId: identity.vaultId,
    dataId: identity.dataId
  });
  assert.equal(jRes1.reservedOutputTokens, 200);
  const rowAfterRes1 = db1
    .prepare('SELECT reserved_calls, used_calls, reserved_input_tokens, used_input_tokens, reserved_output_tokens, used_output_tokens, reserved_cost_micro_cny, used_cost_micro_cny FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(judgeApproval.cloud_approval_id);
  assert.equal(rowAfterRes1.reserved_calls, 1);
  assert.equal(rowAfterRes1.used_calls, 0);
  assert.equal(rowAfterRes1.reserved_input_tokens, 100);
  assert.equal(rowAfterRes1.used_input_tokens, 0);
  assert.equal(rowAfterRes1.reserved_output_tokens, 200);
  assert.equal(rowAfterRes1.used_output_tokens, 0);
  assert.equal(rowAfterRes1.reserved_cost_micro_cny, 800); // 100*2 + 200*3
  assert.equal(rowAfterRes1.used_cost_micro_cny, 0);

  // Call 2 asking for 150 output tokens fits per-call (<=200), but 200+150=350 > max_output_tokens (300) -> rejected!
  assert.throws(
    () =>
      reserveCloudEgressBudget(db1, {
        cloudApprovalId: judgeApproval.cloud_approval_id,
        requestId: 'judge-res-2-over-total-out',
        provider: 'deepseek',
        modelId: 'deepseek-chat',
        purpose: 'judge',
        reservedInputTokens: 100,
        maxOutputTokens: 150,
        vaultId: identity.vaultId,
        dataId: identity.dataId
      }),
    /ERR_CLOUD_BUDGET_EXCEEDED/
  );

  // Settle call 1 with 80 input, 120 output -> reserved_* returns to 0, used_* accurately updated!
  const jSettle1 = settleCloudEgressUsage(db1, {
    requestId: 'judge-res-1',
    actualInputTokens: 80,
    actualOutputTokens: 120,
    httpStatus: 200,
    egressBytes: 512,
    latencyMs: 42.5,
    outcome: 'ok'
  });
  assert.equal(jSettle1.settled, true);
  assert.equal(jSettle1.reservedCalls, 0);
  assert.equal(jSettle1.usedCalls, 1);
  assert.equal(jSettle1.reservedInputTokens, 0);
  assert.equal(jSettle1.usedInputTokens, 80);
  assert.equal(jSettle1.reservedOutputTokens, 0);
  assert.equal(jSettle1.usedOutputTokens, 120);
  assert.equal(jSettle1.usedCostMicroCny, 520); // 80*2 + 120*3

  // C. Concurrency race for last 1 call slot across separate workers (0 outbound calls for loser)
  const raceApproval = issueCloudEgressApproval(db1, {
    purpose: 'embed_query',
    scopeRef: 'query-session:race',
    corpusDigest: '1'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 1,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    modelId: 'BAAI/bge-m3',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 1,
    maxInputTokens: 10_000,
    maxOutputTokens: 0,
    maxCostMicroCny: 100_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });

  let outboundCount = 0;
  const workerScript = `
    import { openOperatorDatabase, reserveCloudEgressBudget } from ${JSON.stringify(
      new URL('../src/security/cloud-approvals.mjs', import.meta.url).href
    )};
    const [dbPath, cloudApprovalId, reqId, vaultId, dataId] = process.argv.slice(2);
    const db = openOperatorDatabase(dbPath, { autoMigrate: false });
    try {
      const r = reserveCloudEgressBudget(db, {
        cloudApprovalId,
        requestId: reqId,
        provider: 'siliconflow',
        modelId: 'BAAI/bge-m3',
        purpose: 'embed_query',
        reservedInputTokens: 100,
        vaultId,
        dataId
      });
      console.log(JSON.stringify({ ok: true, requestId: r.requestId }));
    } catch (err) {
      console.log(JSON.stringify({ ok: false, code: err.code }));
    } finally {
      db.close();
    }
  `;
  const workerPath = path.join(root, 'race-worker.mjs');
  fs.writeFileSync(workerPath, workerScript, 'utf8');

  const [r1, r2] = await Promise.all([
    execFileAsync(process.execPath, [
      workerPath,
      operatorDbPath,
      raceApproval.cloud_approval_id,
      'race-req-1',
      identity.vaultId,
      identity.dataId
    ]).then(({ stdout }) => JSON.parse(stdout.trim())),
    execFileAsync(process.execPath, [
      workerPath,
      operatorDbPath,
      raceApproval.cloud_approval_id,
      'race-req-2',
      identity.vaultId,
      identity.dataId
    ]).then(({ stdout }) => JSON.parse(stdout.trim()))
  ]);
  for (const r of [r1, r2]) {
    if (r.ok) outboundCount += 1;
  }
  assert.equal([r1, r2].filter((r) => r.ok).length, 1);
  assert.equal([r1, r2].filter((r) => !r.ok && r.code === 'ERR_CLOUD_BUDGET_EXCEEDED').length, 1);
  assert.equal(outboundCount, 1);

  // D. Overrun billing -> overrun_paused + true un-truncated bill + idempotent double-settle
  const chatApproval = issueCloudEgressApproval(db1, {
    purpose: 'distill',
    scopeRef: 'snapshot:s1',
    corpusDigest: '2'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 0,
    provider: 'deepseek',
    endpointUrl: 'https://api.deepseek.com/v1/chat/completions',
    modelId: 'deepseek-chat',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 5,
    maxInputTokens: 1000,
    maxOutputTokens: 10_000,
    maxOutputTokensPerCall: 2000,
    maxCostMicroCny: 20_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  const resChat = reserveCloudEgressBudget(db1, {
    cloudApprovalId: chatApproval.cloud_approval_id,
    requestId: 'chat-overrun-1',
    provider: 'deepseek',
    modelId: 'deepseek-chat',
    purpose: 'distill',
    reservedInputTokens: 500,
    maxOutputTokens: 1000,
    vaultId: identity.vaultId,
    dataId: identity.dataId
  });
  assert.equal(resChat.reservedCostMicroCny, 4000);

  // Provider reports huge output tokens (8000) -> 500*2 + 8000*3 = 25000 > maxCostMicroCny (20000)
  const settled1 = settleCloudEgressUsage(db1, {
    requestId: 'chat-overrun-1',
    actualInputTokens: 500,
    actualOutputTokens: 8000,
    actualReasoningTokens: 2000,
    completionIncludesReasoning: true,
    httpStatus: 200
  });
  assert.equal(settled1.settled, true);
  assert.equal(settled1.overrunPaused, true);
  assert.equal(settled1.billedCostMicroCny, 25_000);
  assert.equal(settled1.usedCostMicroCny, 25_000); // NOT truncated to 20_000!

  const settled2 = settleCloudEgressUsage(db2, {
    requestId: 'chat-overrun-1',
    actualInputTokens: 500,
    actualOutputTokens: 8000,
    httpStatus: 200
  });
  assert.equal(settled2.settled, false);
  assert.equal(settled2.idempotent, true);
  assert.equal(
    db1.prepare('SELECT used_cost_micro_cny, status FROM cloud_egress_approvals WHERE cloud_approval_id = ?').get(chatApproval.cloud_approval_id).used_cost_micro_cny,
    25_000
  );
  assert.throws(
    () =>
      reserveCloudEgressBudget(db1, {
        cloudApprovalId: chatApproval.cloud_approval_id,
        requestId: 'chat-after-overrun',
        provider: 'deepseek',
        modelId: 'deepseek-chat',
        purpose: 'distill',
        reservedInputTokens: 10,
        maxOutputTokens: 10,
        vaultId: identity.vaultId,
        dataId: identity.dataId
      }),
    /ERR_APPROVAL_OVERRUN_PAUSED/
  );

  // E. query_egress_allowed = 0 blocks embed_query
  const blockedQueryApp = issueCloudEgressApproval(db1, {
    purpose: 'embed_query',
    scopeRef: 'query-session:no-egress',
    corpusDigest: '3'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 0,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    modelId: 'BAAI/bge-m3',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 2,
    maxInputTokens: 1000,
    maxOutputTokens: 0,
    maxCostMicroCny: 10_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  assert.throws(
    () =>
      reserveCloudEgressBudget(db1, {
        cloudApprovalId: blockedQueryApp.cloud_approval_id,
        requestId: 'blocked-q-1',
        provider: 'siliconflow',
        modelId: 'BAAI/bge-m3',
        purpose: 'embed_query',
        reservedInputTokens: 20,
        vaultId: identity.vaultId,
        dataId: identity.dataId
      }),
    /ERR_QUERY_EGRESS_FORBIDDEN/
  );
  // Passing requiresQueryEgress: false MUST NOT bypass query_egress_allowed = 0 on embed_query
  assert.throws(
    () =>
      reserveCloudEgressBudget(db1, {
        cloudApprovalId: blockedQueryApp.cloud_approval_id,
        requestId: 'blocked-q-bypass-attempt',
        provider: 'siliconflow',
        modelId: 'BAAI/bge-m3',
        purpose: 'embed_query',
        requiresQueryEgress: false,
        reservedInputTokens: 20,
        vaultId: identity.vaultId,
        dataId: identity.dataId
      }),
    /ERR_QUERY_EGRESS_FORBIDDEN/
  );
  // distill / judge require positive maxOutputTokens & maxOutputTokensPerCall
  assert.throws(
    () =>
      issueCloudEgressApproval(db1, {
        purpose: 'judge',
        scopeRef: 'frozen-pool:zero-out',
        corpusDigest: '3'.repeat(64),
        boundVaultId: identity.vaultId,
        boundDataId: identity.dataId,
        provider: 'deepseek',
        endpointUrl: 'https://api.deepseek.com/chat/completions',
        modelId: 'deepseek-chat',
        issuerChannel: 'test_harness',
        approvedBy: 'harness',
        maxCalls: 1,
        maxInputTokens: 1000,
        maxOutputTokens: 0,
        maxCostMicroCny: 1000,
        expiresAt: futureIso(),
        trustedHumanContext: true
      }),
    /ERR_INVALID_OUTPUT_TOKEN_CAP/
  );

  // F. RunPlan single-transaction atomic dual-stage reservation (stage 2 failure leaves 0 reservations)
  const embedApp = issueCloudEgressApproval(db1, {
    purpose: 'embed_query',
    scopeRef: 'query-session:rp',
    corpusDigest: '4'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 1,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
    modelId: 'BAAI/bge-m3',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 5,
    maxInputTokens: 5000,
    maxOutputTokens: 0,
    maxCostMicroCny: 50_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  const rerankApp = issueCloudEgressApproval(db1, {
    purpose: 'rerank',
    scopeRef: 'frozen-pool:rp',
    corpusDigest: '5'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 1,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/rerank',
    modelId: 'BAAI/bge-reranker-v2-m3',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 1,
    maxInputTokens: 50,
    maxOutputTokens: 0,
    maxCostMicroCny: 50_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  assert.throws(
    () =>
      reserveRunPlanBudgets(db1, {
        runPlanId: 'runplan-fail',
        vaultId: identity.vaultId,
        dataId: identity.dataId,
        stages: [
          {
            cloudApprovalId: embedApp.cloud_approval_id,
            requestId: 'rp-fail-1',
            provider: 'siliconflow',
            modelId: 'BAAI/bge-m3',
            purpose: 'embed_query',
            reservedInputTokens: 100
          },
          {
            cloudApprovalId: rerankApp.cloud_approval_id,
            requestId: 'rp-fail-2',
            provider: 'siliconflow',
            modelId: 'BAAI/bge-reranker-v2-m3',
            purpose: 'rerank',
            reservedInputTokens: 200
          }
        ]
      }),
    /ERR_CLOUD_BUDGET_EXCEEDED/
  );
  assert.equal(
    db1.prepare('SELECT reserved_calls FROM cloud_egress_approvals WHERE cloud_approval_id = ?').get(embedApp.cloud_approval_id).reserved_calls,
    0
  );

  // G. RunPlan succeeds, stage 2 revoked mid-flight -> pre-send recheck releases stage 2 as released_precheck_failed (outcome='denied')
  const rerankOkApp = issueCloudEgressApproval(db1, {
    purpose: 'rerank',
    scopeRef: 'frozen-pool:rp2',
    corpusDigest: '6'.repeat(64),
    boundVaultId: identity.vaultId,
    boundDataId: identity.dataId,
    queryEgressAllowed: 1,
    provider: 'siliconflow',
    endpointUrl: 'https://api.siliconflow.cn/v1/rerank',
    modelId: 'BAAI/bge-reranker-v2-m3',
    issuerChannel: 'test_harness',
    approvedBy: 'harness',
    maxCalls: 2,
    maxInputTokens: 5000,
    maxOutputTokens: 0,
    maxCostMicroCny: 50_000,
    expiresAt: futureIso(),
    trustedHumanContext: true
  });
  reserveRunPlanBudgets(db1, {
    runPlanId: 'runplan-revoke-mid',
    vaultId: identity.vaultId,
    dataId: identity.dataId,
    stages: [
      {
        cloudApprovalId: embedApp.cloud_approval_id,
        requestId: 'rp-ok-1',
        provider: 'siliconflow',
        modelId: 'BAAI/bge-m3',
        purpose: 'embed_query',
        reservedInputTokens: 100
      },
      {
        cloudApprovalId: rerankOkApp.cloud_approval_id,
        requestId: 'rp-ok-2',
        provider: 'siliconflow',
        modelId: 'BAAI/bge-reranker-v2-m3',
        purpose: 'rerank',
        reservedInputTokens: 200
      }
    ]
  });
  revokeCloudEgressApproval(db1, { cloudApprovalId: rerankOkApp.cloud_approval_id });
  const precheckStage2 = recheckApprovalBeforeSend(db1, {
    cloudApprovalId: rerankOkApp.cloud_approval_id,
    requestId: 'rp-ok-2',
    vaultId: identity.vaultId,
    dataId: identity.dataId
  });
  assert.equal(precheckStage2.allowed, false);
  assert.equal(precheckStage2.code, 'ERR_APPROVAL_REVOKED');
  assert.equal(precheckStage2.released, true);
  const stage2Ledger = db1
    .prepare('SELECT reservation_state, outcome, egress_bytes FROM cloud_egress_usage_ledger WHERE request_id = ?')
    .get('rp-ok-2');
  assert.equal(stage2Ledger.reservation_state, 'released_precheck_failed');
  assert.equal(stage2Ledger.outcome, 'denied');
  assert.equal(stage2Ledger.egress_bytes, 0);
  assert.equal(
    db1.prepare('SELECT reserved_calls, used_calls FROM cloud_egress_approvals WHERE cloud_approval_id = ?').get(rerankOkApp.cloud_approval_id).reserved_calls,
    0
  );

  // H. Timeout retention & crash_retained recovery + idempotent reconciliation
  retainCloudEgressReservation(db1, {
    requestId: 'rp-ok-1',
    state: 'retained_on_timeout',
    outcome: 'timeout',
    egressBytes: 64,
    latencyMs: 500
  });
  const timeoutLedger = db1
    .prepare('SELECT reservation_state, outcome FROM cloud_egress_usage_ledger WHERE request_id = ?')
    .get('rp-ok-1');
  assert.equal(timeoutLedger.reservation_state, 'retained_on_timeout');
  assert.equal(timeoutLedger.outcome, 'timeout');
  assert.equal(
    db1.prepare('SELECT reserved_calls, used_calls FROM cloud_egress_approvals WHERE cloud_approval_id = ?').get(embedApp.cloud_approval_id).reserved_calls,
    1
  );

  // Dangling reservation recovered on crash startup -> retained_on_unknown_bill + outcome = 'crash_retained'
  reserveCloudEgressBudget(db1, {
    cloudApprovalId: embedApp.cloud_approval_id,
    requestId: 'crash-dangling-1',
    provider: 'siliconflow',
    modelId: 'BAAI/bge-m3',
    purpose: 'embed_query',
    reservedInputTokens: 50,
    vaultId: identity.vaultId,
    dataId: identity.dataId
  });
  const crashRec = recoverCrashRetainedReservations(db1);
  assert.equal(crashRec.recoveredCount, 2); // winning race-req-* + crash-dangling-1
  const crashRow = db1
    .prepare('SELECT reservation_state, outcome FROM cloud_egress_usage_ledger WHERE request_id = ?')
    .get('crash-dangling-1');
  assert.equal(crashRow.reservation_state, 'retained_on_unknown_bill');
  assert.equal(crashRow.outcome, 'crash_retained');

  // Reconcile unbilled timeout -> settles with 0 cost & 0 callsUsed (does NOT use released_precheck_failed)
  const recUnbilled1 = reconcileRetainedLedgerEntry(db1, {
    requestId: 'rp-ok-1',
    outcome: 'confirmed_unbilled'
  });
  assert.equal(recUnbilled1.reconciled, true);
  assert.equal(recUnbilled1.reservationState, 'settled');
  assert.equal(recUnbilled1.outcome, 'timeout');
  assert.equal(recUnbilled1.billedCostMicroCny, 0);
  const recUnbilled2 = reconcileRetainedLedgerEntry(db1, {
    requestId: 'rp-ok-1',
    outcome: 'confirmed_unbilled'
  });
  assert.equal(recUnbilled2.reconciled, false);
  assert.equal(recUnbilled2.idempotent, true);

  // Reconcile crash_retained billed -> settles and moves from reserved_* to used_*
  const recBilled = reconcileRetainedLedgerEntry(db1, {
    requestId: 'crash-dangling-1',
    outcome: 'confirmed_billed',
    actualInputTokens: 40
  });
  assert.equal(recBilled.reconciled, true);
  assert.equal(recBilled.reservationState, 'settled');
  assert.equal(recBilled.outcome, 'crash_retained');
  const finalEmbedApp = db1
    .prepare('SELECT reserved_calls, used_calls, used_input_tokens FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(embedApp.cloud_approval_id);
  assert.equal(finalEmbedApp.reserved_calls, 0);
  assert.equal(finalEmbedApp.used_calls, 1);
  assert.equal(finalEmbedApp.used_input_tokens, 40);
});

test('V3.3-T06: pure in-memory sanitizePayloadForExitA + 4-point OS isolation sentinel including operator code/module/config unwritable', (t) => {
  const root = makeTempDir('oam-v33-t06-sentinel-');
  let stateDb = null;
  t.after(() => {
    try { stateDb?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  });

  const { dataPath, stateDbPath } = setupSampleRepo(root);
  stateDb = openExistingDatabase(stateDbPath);

  stateDb
    .prepare(
      `INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at, updated_at)
       VALUES
       ('note-san', 'decision', 'Sanitized Note', 'oam', 'sanitized', 'notes/san.md', 's1', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
       ('note-loc', 'decision', 'Local Note', 'oam', 'local_only', 'notes/loc.md', 's2', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`
    )
    .run();

  const egressDir = path.join(dataPath, 'egress');
  const beforeFiles = fs.existsSync(egressDir) ? fs.readdirSync(egressDir) : [];

  const syntheticKey = buildSyntheticSecret();
  const exitARes = sanitizePayloadForExitA({
    db: stateDb,
    items: [
      {
        noteId: 'note-san',
        ephemeralId: 0,
        privacy: 'sanitized',
        title: 'Clean Summary',
        content: `User path C:\\Obsidian\\AgentMemory-Data\\raw\\secret.jsonl and Bearer ${syntheticKey}`,
        rawPath: 'D:\\Secret\\raw\\file.json'
      }
    ],
    allowedFields: ['ephemeralId', 'title', 'content']
  });
  assert.equal(exitARes.clean, true);
  assert.equal(exitARes.inMemoryOnly, true);
  assert.equal(exitARes.sanitizedItems.length, 1);
  assert.equal(Object.hasOwn(exitARes.sanitizedItems[0], 'rawPath'), false);
  assert.equal(Object.hasOwn(exitARes.sanitizedItems[0], 'noteId'), false);
  assert.ok(!exitARes.sanitizedItems[0].content.includes(syntheticKey));
  assert.ok(!exitARes.sanitizedItems[0].content.includes('secret.jsonl'));
  const afterFiles = fs.existsSync(egressDir) ? fs.readdirSync(egressDir) : [];
  assert.deepEqual(afterFiles, beforeFiles);

  assert.throws(
    () =>
      sanitizePayloadForExitA({
        db: stateDb,
        items: [{ noteId: 'note-loc', privacy: 'local_only', content: 'secret' }]
      }),
    { code: 'ERR_EXIT_A_PRIVACY_BLOCKED' }
  );
  assert.throws(
    () =>
      sanitizePayloadForExitA({
        db: stateDb,
        items: [{ noteId: 'manual-unregistered', privacy: 'sanitized', content: 'unregistered' }]
      }),
    { code: 'ERR_EXIT_A_UNREGISTERED_ITEM' }
  );
  assert.throws(
    () =>
      sanitizePayloadForExitA({
        db: stateDb,
        items: [{ noteId: 'note-san', privacy: 'sanitized', content: 'ok' }],
        allowedFields: ['content', 'rawPath']
      }),
    { code: 'ERR_EXIT_A_FORBIDDEN_FIELD' }
  );
  const querySanRes = sanitizePayloadForExitA({
    db: stateDb,
    requireRegisteredSanitized: false,
    items: [{ kind: 'query', text: `Authorization: Bearer ${syntheticKey}` }],
    allowedFields: ['text']
  });
  assert.equal(querySanRes.clean, true);
  assert.ok(!querySanRes.sanitizedItems[0].text.includes(syntheticKey));
});

test('V3.3-T06: 4-point OS isolation sentinel enforces real file/module/config non-writability', (t) => {
  const root = makeTempDir('oam-v33-t06-os4-');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const keyFile = path.join(root, 'cloud.key');
  const opDbFile = path.join(root, 'operator-state.sqlite');
  const entryFile = path.join(root, 'operator-entry.mjs');
  const modFile = path.join(root, 'operator-mod.mjs');
  const cfgFile = path.join(root, 'operator-config.json');
  for (const f of [keyFile, opDbFile, entryFile, modFile, cfgFile]) {
    fs.writeFileSync(f, 'placeholder\n', 'utf8');
  }

  const realFailReport = runFourPointCloudIsolationSentinel({
    keyFilePath: keyFile,
    operatorDbPath: opDbFile,
    operatorPackage: {
      entrypointPath: entryFile,
      modulePaths: [modFile],
      configPaths: [cfgFile]
    }
  });
  assert.equal(realFailReport.allFourPassed, false);
  assert.throws(() => assertRealCloudApiGate(realFailReport), /ERR_CLOUD_OS_ISOLATION_FAILED/);
  assert.ok(realFailReport.failedSentinels.includes('key_file_unreadable'));
  assert.ok(realFailReport.failedSentinels.includes('operator_db_unwritable'));
  assert.ok(realFailReport.failedSentinels.includes('operator_package_unwritable'));

  const writableConfigReport = runFourPointCloudIsolationSentinel({
    keyFilePath: keyFile,
    operatorDbPath: opDbFile,
    operatorPackage: {
      entrypointPath: entryFile,
      modulePaths: [modFile],
      configPaths: [cfgFile]
    },
    probeReadFn: () => ({ blocked: true, reason: 'os_denied_EACCES', code: 'EACCES' }),
    probeWriteFn: (target) =>
      path.resolve(target) === path.resolve(cfgFile)
        ? { blocked: false, reason: 'write_open_succeeded', code: null }
        : { blocked: true, reason: 'os_denied_EACCES', code: 'EACCES' }
  });
  assert.equal(writableConfigReport.allFourPassed, false);
  assert.deepEqual(writableConfigReport.failedSentinels, ['operator_package_unwritable']);
  assert.equal(writableConfigReport.sentinels.operator_package_unwritable.writableTargets[0].category, 'config');

  const writableModuleReport = runFourPointCloudIsolationSentinel({
    keyFilePath: keyFile,
    operatorDbPath: opDbFile,
    operatorPackage: {
      entrypointPath: entryFile,
      modulePaths: [modFile],
      configPaths: [cfgFile]
    },
    probeReadFn: () => ({ blocked: true, reason: 'os_denied_EACCES', code: 'EACCES' }),
    probeWriteFn: (target) =>
      path.resolve(target) === path.resolve(modFile)
        ? { blocked: false, reason: 'write_open_succeeded', code: null }
        : { blocked: true, reason: 'os_denied_EACCES', code: 'EACCES' }
  });
  assert.equal(writableModuleReport.allFourPassed, false);
  assert.equal(writableModuleReport.sentinels.operator_package_unwritable.writableTargets[0].category, 'module');

  const allPassReport = runFourPointCloudIsolationSentinel({
    keyFilePath: keyFile,
    operatorDbPath: opDbFile,
    operatorPackage: {
      entrypointPath: entryFile,
      modulePaths: [modFile],
      configPaths: [cfgFile]
    },
    probeReadFn: () => ({ blocked: true, reason: 'os_denied_EACCES', code: 'EACCES' }),
    probeWriteFn: () => ({ blocked: true, reason: 'os_denied_EACCES', code: 'EACCES' })
  });
  assert.equal(allPassReport.allFourPassed, true);
  assert.equal(assertRealCloudApiGate(allPassReport), true);
});
