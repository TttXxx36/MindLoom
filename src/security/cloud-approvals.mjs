import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { assertNoForbiddenCliFlags } from './trusted-approvals.mjs';

export const CLOUD_EGRESS_MIGRATION_VERSION = 1;
export const DEFAULT_PRICING_VERSION = '2026-11-13-v1';

export const CLOUD_APPROVAL_STATUSES = Object.freeze([
  'active',
  'revoked',
  'exhausted',
  'overrun_paused',
  'expired',
  'restore_locked'
]);

export const CLOUD_EGRESS_PURPOSES = Object.freeze([
  'distill',
  'embed_doc',
  'embed_query',
  'rerank',
  'judge'
]);

export const CLOUD_ISSUER_CHANNELS = Object.freeze([
  'operator_cli',
  'operator_tty_ps1',
  'test_harness'
]);

export const CLOUD_RESERVATION_STATES = Object.freeze([
  'reserved',
  'settled',
  'retained_on_timeout',
  'retained_on_unknown_bill',
  'released_precheck_failed'
]);

export const CLOUD_LEDGER_OUTCOMES = Object.freeze([
  'pending',
  'ok',
  'denied',
  'timeout',
  'http_error',
  'invalid_response',
  'crash_retained'
]);

const FORBIDDEN_ALLOWED_FIELDS = new Set([
  'raw_path',
  'rawpath',
  'note_id',
  'noteid',
  'uuid',
  'file_path',
  'filepath',
  'api_key',
  'apikey',
  'secret',
  'token',
  'password',
  'raw_snapshot'
]);

const DEFAULT_ALLOWED_FIELDS_BY_PURPOSE = Object.freeze({
  embed_doc: Object.freeze(['content']),
  embed_query: Object.freeze(['query']),
  rerank: Object.freeze(['query', 'title', 'sanitized_snippet']),
  distill: Object.freeze(['sanitized_events']),
  judge: Object.freeze(['query', 'title', 'sanitized_snippet', 'citations'])
});

const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);

export const DEFAULT_PRICING_CATALOG = Object.freeze({
  siliconflow: Object.freeze({
    'BAAI/bge-m3': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 70_000,
      outputMicroCnyPerMillionTokens: 0,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 0
    }),
    'BAAI/bge-reranker-v2-m3': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 140_000,
      outputMicroCnyPerMillionTokens: 0,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 0
    }),
    'Qwen/Qwen3-Embedding-8B': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 140_000,
      outputMicroCnyPerMillionTokens: 0,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 0
    }),
    'Qwen/Qwen3-Reranker-8B': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 210_000,
      outputMicroCnyPerMillionTokens: 0,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 0
    })
  }),
  emrank: Object.freeze({
    'Qwen/Qwen3-Embedding-0.6B': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 140_000,
      outputMicroCnyPerMillionTokens: 0,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 0
    }),
    'Qwen/Qwen3-Embedding-8B': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 140_000,
      outputMicroCnyPerMillionTokens: 0,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 0
    })
  }),
  deepseek: Object.freeze({
    'deepseek-chat': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 2_000_000,
      outputMicroCnyPerMillionTokens: 3_000_000,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 2048
    }),
    'deepseek-reasoner': Object.freeze({
      pricingVersion: DEFAULT_PRICING_VERSION,
      inputMicroCnyPerMillionTokens: 2_000_000,
      outputMicroCnyPerMillionTokens: 3_000_000,
      completionIncludesReasoning: true,
      defaultMaxOutputTokens: 4096
    })
  })
});

function createCloudError(code, message, extra = {}) {
  const err = new Error(`[${code}] ${message}`);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

export function assertSafeNonNegativeInt(value, fieldName) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw createCloudError(
      'ERR_INVALID_SAFE_INTEGER',
      `${fieldName} must be a non-negative safe integer, got ${String(value)}`
    );
  }
  return value;
}

export function assertSafePositiveInt(value, fieldName) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw createCloudError(
      'ERR_INVALID_POSITIVE_INTEGER',
      `${fieldName} must be a positive safe integer, got ${String(value)}`
    );
  }
  return value;
}

function assertSafeNonNegativeReal(value, fieldName) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw createCloudError(
      'ERR_INVALID_NON_NEGATIVE_REAL',
      `${fieldName} must be a non-negative finite number, got ${String(value)}`
    );
  }
  return value;
}

function assertSafeAddition(a, b, fieldName) {
  assertSafeNonNegativeInt(a, `${fieldName}.base`);
  assertSafeNonNegativeInt(b, `${fieldName}.delta`);
  if (a > Number.MAX_SAFE_INTEGER - b) {
    throw createCloudError(
      'ERR_SAFE_INTEGER_OVERFLOW',
      `${fieldName} exceeds Number.MAX_SAFE_INTEGER`
    );
  }
  return a + b;
}

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw createCloudError('ERR_INVALID_ARGUMENT', `${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function assertZeroOrOne(value, fieldName) {
  if (value === true || value === 1) return 1;
  if (value === false || value === 0) return 0;
  throw createCloudError('ERR_INVALID_ARGUMENT', `${fieldName} must be 0, 1, or boolean`);
}

function isLoopbackHost(hostname) {
  return LOOPBACK_HOSTNAMES.has(String(hostname || '').trim().toLowerCase());
}

function validateApprovedEndpointUrl(endpointUrl, { issuerChannel }) {
  const clean = assertNonEmptyString(endpointUrl, 'endpointUrl');
  let parsed;
  try {
    parsed = new URL(clean);
  } catch {
    throw createCloudError('ERR_INVALID_ENDPOINT', `Malformed endpointUrl: ${clean}`);
  }
  if (parsed.username || parsed.password) {
    throw createCloudError(
      'ERR_ENDPOINT_CREDENTIALS_FORBIDDEN',
      'endpointUrl must not contain embedded credentials'
    );
  }
  const loopback = isLoopbackHost(parsed.hostname);
  if (loopback) {
    if (issuerChannel !== 'test_harness') {
      throw createCloudError(
        'ERR_LOOPBACK_FORBIDDEN_FOR_CHANNEL',
        `Loopback endpointUrl is only permitted for test_harness issuerChannel (got ${issuerChannel})`
      );
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw createCloudError('ERR_INVALID_PROTOCOL', `Unsupported protocol: ${parsed.protocol}`);
    }
  } else if (parsed.protocol !== 'https:') {
    throw createCloudError(
      'ERR_HTTPS_REQUIRED',
      `External endpointUrl must use https:// (got ${parsed.protocol})`
    );
  }
  return parsed.toString().replace(/\/+$/, '');
}

function validateAllowedFields(allowedFields, purpose) {
  const fields = allowedFields ?? DEFAULT_ALLOWED_FIELDS_BY_PURPOSE[purpose];
  if (!Array.isArray(fields) || fields.length === 0) {
    throw createCloudError('ERR_INVALID_ALLOWED_FIELDS', 'allowedFields must be a non-empty array');
  }
  const normalized = [];
  for (const f of fields) {
    const clean = assertNonEmptyString(f, 'allowedFields[]');
    if (FORBIDDEN_ALLOWED_FIELDS.has(clean.toLowerCase())) {
      throw createCloudError(
        'ERR_FORBIDDEN_ALLOWED_FIELD',
        `Forbidden field in allowedFields: ${clean}`
      );
    }
    if (!normalized.includes(clean)) {
      normalized.push(clean);
    }
  }
  return normalized;
}

export function isProductionCliRuntime() {
  return process.env.OAM_PRODUCTION_CLI === '1';
}

export function resolvePricingSpec({
  provider,
  modelId,
  pricingVersion = DEFAULT_PRICING_VERSION,
  pricingCatalog = DEFAULT_PRICING_CATALOG,
  pricingOverride = null
}) {
  const cleanVersion = assertNonEmptyString(pricingVersion, 'pricingVersion');
  if (pricingOverride && typeof pricingOverride === 'object') {
    const inputRate = assertSafeNonNegativeInt(
      pricingOverride.inputMicroCnyPerMillionTokens,
      'pricingOverride.inputMicroCnyPerMillionTokens'
    );
    const outputRate = assertSafeNonNegativeInt(
      pricingOverride.outputMicroCnyPerMillionTokens ?? 0,
      'pricingOverride.outputMicroCnyPerMillionTokens'
    );
    const defaultMaxOutputTokens = assertSafeNonNegativeInt(
      pricingOverride.defaultMaxOutputTokens ?? 0,
      'pricingOverride.defaultMaxOutputTokens'
    );
    return {
      provider,
      modelId,
      pricingVersion: pricingOverride.pricingVersion || cleanVersion,
      inputMicroCnyPerMillionTokens: inputRate,
      outputMicroCnyPerMillionTokens: outputRate,
      completionIncludesReasoning: pricingOverride.completionIncludesReasoning !== false,
      defaultMaxOutputTokens
    };
  }

  const providerPricing = pricingCatalog?.[provider];
  const spec = providerPricing?.[modelId];
  if (!spec) {
    throw createCloudError(
      'ERR_PRICING_UNAVAILABLE',
      `No pricing snapshot entry for provider=${provider}, model_id=${modelId}`
    );
  }
  const specVersion = spec.pricingVersion || DEFAULT_PRICING_VERSION;
  if (specVersion !== cleanVersion) {
    throw createCloudError(
      'ERR_PRICING_VERSION_MISMATCH',
      `Pricing version mismatch for ${provider}/${modelId}: expected ${specVersion}, got ${cleanVersion}`
    );
  }
  return {
    provider,
    modelId,
    pricingVersion: specVersion,
    inputMicroCnyPerMillionTokens: assertSafeNonNegativeInt(
      spec.inputMicroCnyPerMillionTokens,
      'pricing.inputMicroCnyPerMillionTokens'
    ),
    outputMicroCnyPerMillionTokens: assertSafeNonNegativeInt(
      spec.outputMicroCnyPerMillionTokens ?? 0,
      'pricing.outputMicroCnyPerMillionTokens'
    ),
    completionIncludesReasoning: spec.completionIncludesReasoning !== false,
    defaultMaxOutputTokens: assertSafeNonNegativeInt(
      spec.defaultMaxOutputTokens ?? 0,
      'pricing.defaultMaxOutputTokens'
    )
  };
}

function ceilPerMillionMicroCny(tokens, microCnyPerMillion) {
  assertSafeNonNegativeInt(tokens, 'tokens');
  assertSafeNonNegativeInt(microCnyPerMillion, 'microCnyPerMillion');
  if (tokens === 0 || microCnyPerMillion === 0) {
    return 0;
  }
  const product = BigInt(tokens) * BigInt(microCnyPerMillion);
  const ceilVal = (product + 999_999n) / 1_000_000n;
  if (ceilVal > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw createCloudError(
      'ERR_COST_OVERFLOW',
      `Computed micro-CNY cost ${ceilVal.toString()} exceeds MAX_SAFE_INTEGER`
    );
  }
  return Number(ceilVal);
}

export function estimateWorstCaseCostMicroCny({
  inputTokens,
  maxOutputTokens = 0,
  pricing
}) {
  assertSafeNonNegativeInt(inputTokens, 'inputTokens');
  assertSafeNonNegativeInt(maxOutputTokens, 'maxOutputTokens');
  if (!pricing || typeof pricing !== 'object') {
    throw createCloudError('ERR_PRICING_UNAVAILABLE', 'pricing specification is required');
  }
  const inputCost = ceilPerMillionMicroCny(inputTokens, pricing.inputMicroCnyPerMillionTokens);
  const outputCost = ceilPerMillionMicroCny(
    maxOutputTokens,
    pricing.outputMicroCnyPerMillionTokens ?? 0
  );
  return assertSafeAddition(inputCost, outputCost, 'estimatedCostMicroCny');
}

export function computeBillableOutputTokens({
  completionTokens = 0,
  reasoningTokens = 0,
  completionIncludesReasoning = true
}) {
  assertSafeNonNegativeInt(completionTokens, 'completionTokens');
  assertSafeNonNegativeInt(reasoningTokens, 'reasoningTokens');
  if (completionIncludesReasoning) {
    return completionTokens;
  }
  return assertSafeAddition(completionTokens, reasoningTokens, 'billableOutputTokens');
}

export function computeActualCostMicroCny({
  actualInputTokens,
  actualOutputTokens = 0,
  actualReasoningTokens = 0,
  completionIncludesReasoning = true,
  pricing
}) {
  assertSafeNonNegativeInt(actualInputTokens, 'actualInputTokens');
  const billableOutputTokens = computeBillableOutputTokens({
    completionTokens: actualOutputTokens,
    reasoningTokens: actualReasoningTokens,
    completionIncludesReasoning
  });
  const inputCost = ceilPerMillionMicroCny(
    actualInputTokens,
    pricing.inputMicroCnyPerMillionTokens
  );
  const outputCost = ceilPerMillionMicroCny(
    billableOutputTokens,
    pricing.outputMicroCnyPerMillionTokens ?? 0
  );
  return {
    billableOutputTokens,
    billedCostMicroCny: assertSafeAddition(inputCost, outputCost, 'billedCostMicroCny')
  };
}

export function computeCloudApprovalIntegrityHash(record) {
  const canonicalPayload = JSON.stringify({
    cloud_approval_id: record.cloud_approval_id,
    purpose: record.purpose,
    scope_ref: record.scope_ref,
    corpus_digest: record.corpus_digest,
    bound_vault_id: record.bound_vault_id,
    bound_data_id: record.bound_data_id,
    query_egress_allowed: record.query_egress_allowed,
    provider: record.provider,
    endpoint_url: record.endpoint_url,
    model_id: record.model_id,
    pricing_version: record.pricing_version,
    allowed_fields_json: record.allowed_fields_json,
    approved_by: record.approved_by,
    issuer_channel: record.issuer_channel,
    approval_token_sha256: record.approval_token_sha256,
    max_calls: record.max_calls,
    max_input_tokens: record.max_input_tokens,
    max_output_tokens: record.max_output_tokens,
    max_output_tokens_per_call: record.max_output_tokens_per_call,
    max_cost_micro_cny: record.max_cost_micro_cny,
    created_at: record.created_at,
    expires_at: record.expires_at
  });
  return crypto.createHash('sha256').update(canonicalPayload, 'utf8').digest('hex');
}

export function migrateCloudEgressSchema(db) {
  if (!db) {
    throw createCloudError('ERR_DB_REQUIRED', 'SQLite DatabaseSync instance is required');
  }
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloud_egress_schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS cloud_egress_approvals (
      cloud_approval_id TEXT PRIMARY KEY,
      purpose TEXT NOT NULL CHECK(purpose IN ('distill','embed_doc','embed_query','rerank','judge')),
      scope_ref TEXT NOT NULL,
      corpus_digest TEXT NOT NULL,
      bound_vault_id TEXT NOT NULL,
      bound_data_id TEXT NOT NULL,
      query_egress_allowed INTEGER NOT NULL DEFAULT 0 CHECK(query_egress_allowed IN (0,1)),
      provider TEXT NOT NULL,
      endpoint_url TEXT NOT NULL,
      model_id TEXT NOT NULL,
      pricing_version TEXT NOT NULL,
      allowed_fields_json TEXT NOT NULL,
      approved_by TEXT NOT NULL,
      issuer_channel TEXT NOT NULL CHECK(issuer_channel IN ('operator_cli','operator_tty_ps1','test_harness')),
      approval_token_sha256 TEXT NOT NULL,
      max_calls INTEGER NOT NULL CHECK(max_calls > 0),
      reserved_calls INTEGER NOT NULL DEFAULT 0 CHECK(reserved_calls >= 0),
      used_calls INTEGER NOT NULL DEFAULT 0 CHECK(used_calls >= 0),
      max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens > 0),
      reserved_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK(reserved_input_tokens >= 0),
      used_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK(used_input_tokens >= 0),
      max_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK(max_output_tokens >= 0),
      reserved_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK(reserved_output_tokens >= 0),
      used_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK(used_output_tokens >= 0),
      max_output_tokens_per_call INTEGER NOT NULL DEFAULT 0 CHECK(max_output_tokens_per_call >= 0),
      max_cost_micro_cny INTEGER NOT NULL CHECK(max_cost_micro_cny >= 0),
      reserved_cost_micro_cny INTEGER NOT NULL DEFAULT 0 CHECK(reserved_cost_micro_cny >= 0),
      used_cost_micro_cny INTEGER NOT NULL DEFAULT 0 CHECK(used_cost_micro_cny >= 0),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','exhausted','overrun_paused','expired','restore_locked')),
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS cloud_egress_usage_ledger (
      request_id TEXT PRIMARY KEY,
      parent_request_id TEXT,
      attempt_no INTEGER NOT NULL DEFAULT 1 CHECK(attempt_no >= 1),
      run_plan_id TEXT,
      cloud_approval_id TEXT NOT NULL,
      purpose TEXT NOT NULL,
      query_egress_allowed INTEGER NOT NULL DEFAULT 0 CHECK(query_egress_allowed IN (0,1)),
      provider TEXT NOT NULL,
      endpoint_url TEXT NOT NULL,
      model_id TEXT NOT NULL,
      pricing_version TEXT NOT NULL,
      reservation_state TEXT NOT NULL CHECK(reservation_state IN (
        'reserved','settled','retained_on_timeout','retained_on_unknown_bill','released_precheck_failed'
      )),
      http_status INTEGER,
      reserved_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK(reserved_input_tokens >= 0),
      reserved_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK(reserved_output_tokens >= 0),
      prompt_tokens INTEGER NOT NULL DEFAULT 0 CHECK(prompt_tokens >= 0),
      completion_tokens INTEGER NOT NULL DEFAULT 0 CHECK(completion_tokens >= 0),
      reasoning_tokens INTEGER NOT NULL DEFAULT 0 CHECK(reasoning_tokens >= 0),
      billable_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK(billable_output_tokens >= 0),
      total_tokens INTEGER NOT NULL DEFAULT 0 CHECK(total_tokens >= 0),
      reserved_cost_micro_cny INTEGER NOT NULL DEFAULT 0 CHECK(reserved_cost_micro_cny >= 0),
      billed_cost_micro_cny INTEGER NOT NULL DEFAULT 0 CHECK(billed_cost_micro_cny >= 0),
      egress_bytes INTEGER NOT NULL DEFAULT 0 CHECK(egress_bytes >= 0),
      latency_ms REAL NOT NULL DEFAULT 0 CHECK(latency_ms >= 0),
      outcome TEXT NOT NULL DEFAULT 'pending' CHECK(outcome IN ('pending','ok','denied','timeout','http_error','invalid_response','crash_retained')),
      created_at TEXT NOT NULL,
      settled_at TEXT,
      FOREIGN KEY(cloud_approval_id) REFERENCES cloud_egress_approvals(cloud_approval_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS cloud_egress_approval_meta (
      cloud_approval_id TEXT PRIMARY KEY,
      pricing_snapshot_json TEXT NOT NULL,
      revoked_at TEXT,
      lock_reason TEXT,
      integrity_sha256 TEXT NOT NULL,
      FOREIGN KEY(cloud_approval_id) REFERENCES cloud_egress_approvals(cloud_approval_id)
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_cloud_usage_approval_state
      ON cloud_egress_usage_ledger (cloud_approval_id, reservation_state);
    CREATE INDEX IF NOT EXISTS idx_cloud_usage_run_plan
      ON cloud_egress_usage_ledger (run_plan_id);
  `);

  db.prepare(
    `INSERT OR IGNORE INTO cloud_egress_schema_migrations (version, applied_at) VALUES (?, ?)`
  ).run(CLOUD_EGRESS_MIGRATION_VERSION, new Date().toISOString());

  return { version: CLOUD_EGRESS_MIGRATION_VERSION };
}

export function openOperatorDatabase(dbPath, { readOnly = false, autoMigrate = false } = {}) {
  if (!dbPath || typeof dbPath !== 'string') {
    throw createCloudError('ERR_DB_PATH_REQUIRED', 'Operator database path is required');
  }
  const resolved = path.resolve(dbPath);
  if (readOnly) {
    if (!fs.existsSync(resolved)) {
      throw createCloudError('ERR_DB_NOT_FOUND', `Operator DB does not exist: ${resolved}`);
    }
    const db = new DatabaseSync(resolved, { readOnly: true });
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec('PRAGMA foreign_keys = ON;');
    return db;
  }

  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const db = new DatabaseSync(resolved);
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec('PRAGMA foreign_keys = ON;');
  const jm = db.prepare('PRAGMA journal_mode;').get();
  if (!jm || String(jm.journal_mode).toLowerCase() !== 'wal') {
    db.exec('PRAGMA journal_mode = WAL;');
  }
  db.exec('PRAGMA synchronous = NORMAL;');
  if (autoMigrate) {
    migrateCloudEgressSchema(db);
  }
  return db;
}

function runImmediateTransaction(db, fn) {
  db.exec('BEGIN IMMEDIATE;');
  try {
    const result = fn();
    db.exec('COMMIT;');
    return result;
  } catch (err) {
    try {
      db.exec('ROLLBACK;');
    } catch {
      // Ignore rollback failure if connection already closed
    }
    throw err;
  }
}

function parseJsonSafe(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function getApprovalMeta(db, cloudApprovalId) {
  try {
    return db
      .prepare('SELECT * FROM cloud_egress_approval_meta WHERE cloud_approval_id = ?')
      .get(cloudApprovalId) || null;
  } catch {
    return null;
  }
}

function resolveModelPricingForApproval(db, approval, meta) {
  if (meta?.pricing_snapshot_json) {
    const snapshot = parseJsonSafe(meta.pricing_snapshot_json);
    if (!snapshot || typeof snapshot !== 'object') {
      throw createCloudError(
        'ERR_CORRUPT_PRICING_SNAPSHOT',
        `Invalid pricing_snapshot_json on approval ${approval.cloud_approval_id}`
      );
    }
    return resolvePricingSpec({
      provider: approval.provider,
      modelId: approval.model_id,
      pricingVersion: approval.pricing_version,
      pricingOverride: snapshot
    });
  }
  return resolvePricingSpec({
    provider: approval.provider,
    modelId: approval.model_id,
    pricingVersion: approval.pricing_version
  });
}

function generateCloudApprovalId(createdAtIso) {
  const datePart = String(createdAtIso).slice(0, 10).replace(/-/g, '') || '00000000';
  const randHex = crypto.randomBytes(8).toString('hex');
  return `CEGR-${datePart}-${randHex}`;
}

export function issueCloudEgressApproval(
  db,
  {
    cloudApprovalId = null,
    purpose,
    scopeRef,
    corpusDigest,
    boundVaultId,
    boundDataId,
    queryEgressAllowed = 0,
    provider,
    endpointUrl,
    modelId,
    pricingVersion = DEFAULT_PRICING_VERSION,
    allowedFields = null,
    approvedBy = 'human-operator',
    issuerChannel = 'operator_cli',
    approvalToken = null,
    approvalTokenSha256 = null,
    maxCalls,
    maxInputTokens,
    maxOutputTokens = 0,
    maxOutputTokensPerCall = null,
    maxCostMicroCny,
    pricingCatalog = DEFAULT_PRICING_CATALOG,
    pricingOverride = null,
    createdAt = new Date().toISOString(),
    expiresAt,
    trustedHumanContext = false,
    argv = null,
    allowTestHarnessInProd = false
  } = {}
) {
  if (!db) {
    throw createCloudError('ERR_DB_REQUIRED', 'Database handle is required');
  }
  if (trustedHumanContext !== true) {
    throw createCloudError(
      'ERR_CLOUD_APPROVAL_UNTRUSTED_CONTEXT',
      'issueCloudEgressApproval requires trustedHumanContext === true'
    );
  }
  if (Array.isArray(argv)) {
    assertNoForbiddenCliFlags(argv);
  }
  if (!CLOUD_ISSUER_CHANNELS.includes(issuerChannel)) {
    throw createCloudError(
      'ERR_INVALID_ISSUER_CHANNEL',
      `Unsupported issuer_channel: ${String(issuerChannel)}`
    );
  }
  if (
    issuerChannel === 'test_harness' &&
    isProductionCliRuntime() &&
    !allowTestHarnessInProd
  ) {
    throw createCloudError(
      'ERR_TEST_HARNESS_FORBIDDEN_IN_PROD',
      'test_harness issuer_channel is forbidden in production CLI runtime'
    );
  }

  const cleanPurpose = assertNonEmptyString(purpose, 'purpose');
  if (!CLOUD_EGRESS_PURPOSES.includes(cleanPurpose)) {
    throw createCloudError('ERR_INVALID_PURPOSE', `Unsupported purpose: ${cleanPurpose}`);
  }
  const cleanScopeRef = assertNonEmptyString(scopeRef, 'scopeRef');
  const cleanCorpusDigest = assertNonEmptyString(corpusDigest, 'corpusDigest');
  const cleanVaultId = assertNonEmptyString(boundVaultId, 'boundVaultId');
  const cleanDataId = assertNonEmptyString(boundDataId, 'boundDataId');
  const cleanQueryEgressAllowed = assertZeroOrOne(queryEgressAllowed, 'queryEgressAllowed');
  const cleanProvider = assertNonEmptyString(provider, 'provider');
  const cleanEndpointUrl = validateApprovedEndpointUrl(endpointUrl, { issuerChannel });
  const cleanModelId = assertNonEmptyString(modelId, 'modelId');
  const cleanPricingVersion = assertNonEmptyString(pricingVersion, 'pricingVersion');
  const cleanAllowedFields = validateAllowedFields(allowedFields, cleanPurpose);
  const cleanApprovedBy = assertNonEmptyString(approvedBy, 'approvedBy');
  const cleanCreatedAt = assertNonEmptyString(createdAt, 'createdAt');
  const cleanExpiresAt = assertNonEmptyString(expiresAt, 'expiresAt');

  const createdMs = Date.parse(cleanCreatedAt);
  const expiresMs = Date.parse(cleanExpiresAt);
  if (!Number.isFinite(createdMs) || !Number.isFinite(expiresMs) || expiresMs <= createdMs) {
    throw createCloudError(
      'ERR_INVALID_EXPIRATION',
      'expiresAt must be a valid ISO timestamp strictly after createdAt'
    );
  }

  assertSafePositiveInt(maxCalls, 'maxCalls');
  assertSafePositiveInt(maxInputTokens, 'maxInputTokens');
  assertSafeNonNegativeInt(maxOutputTokens, 'maxOutputTokens');
  assertSafeNonNegativeInt(maxCostMicroCny, 'maxCostMicroCny');

  const pricingSpec = resolvePricingSpec({
    provider: cleanProvider,
    modelId: cleanModelId,
    pricingVersion: cleanPricingVersion,
    pricingCatalog,
    pricingOverride
  });

  const isZeroOutputPurpose =
    cleanPurpose === 'embed_doc' || cleanPurpose === 'embed_query' || cleanPurpose === 'rerank';
  const effectivePerCallOutCap =
    maxOutputTokensPerCall === null || maxOutputTokensPerCall === undefined
      ? isZeroOutputPurpose
        ? 0
        : Math.min(maxOutputTokens, pricingSpec.defaultMaxOutputTokens || maxOutputTokens)
      : assertSafeNonNegativeInt(maxOutputTokensPerCall, 'maxOutputTokensPerCall');

  if (isZeroOutputPurpose && (maxOutputTokens !== 0 || effectivePerCallOutCap !== 0)) {
    throw createCloudError(
      'ERR_INVALID_OUTPUT_TOKEN_CAP',
      `Purpose ${cleanPurpose} requires maxOutputTokens === 0 and maxOutputTokensPerCall === 0`
    );
  }
  if (!isZeroOutputPurpose && (maxOutputTokens <= 0 || effectivePerCallOutCap <= 0)) {
    throw createCloudError(
      'ERR_INVALID_OUTPUT_TOKEN_CAP',
      `Purpose ${cleanPurpose} requires positive maxOutputTokens and maxOutputTokensPerCall`
    );
  }
  if (effectivePerCallOutCap > maxOutputTokens) {
    throw createCloudError(
      'ERR_INVALID_OUTPUT_TOKEN_CAP',
      `maxOutputTokensPerCall (${effectivePerCallOutCap}) cannot exceed maxOutputTokens (${maxOutputTokens})`
    );
  }

  const finalApprovalId = cloudApprovalId
    ? assertNonEmptyString(cloudApprovalId, 'cloudApprovalId')
    : generateCloudApprovalId(cleanCreatedAt);
  if (!finalApprovalId.startsWith('CEGR-')) {
    throw createCloudError(
      'ERR_INVALID_CLOUD_APPROVAL_ID',
      'Cloud egress cloud_approval_id must start with CEGR-'
    );
  }

  const tokenHash = approvalTokenSha256
    ? assertNonEmptyString(approvalTokenSha256, 'approvalTokenSha256')
    : approvalToken
      ? crypto.createHash('sha256').update(assertNonEmptyString(approvalToken, 'approvalToken'), 'utf8').digest('hex')
      : crypto
          .createHash('sha256')
          .update(
            `${finalApprovalId}|${cleanPurpose}|${cleanScopeRef}|${cleanCorpusDigest}|${cleanVaultId}|${cleanDataId}|${cleanApprovedBy}|${cleanCreatedAt}`,
            'utf8'
          )
          .digest('hex');

  const allowedFieldsJson = JSON.stringify(cleanAllowedFields);
  const pricingSnapshotJson = JSON.stringify(pricingSpec);

  const record = {
    cloud_approval_id: finalApprovalId,
    purpose: cleanPurpose,
    scope_ref: cleanScopeRef,
    corpus_digest: cleanCorpusDigest,
    bound_vault_id: cleanVaultId,
    bound_data_id: cleanDataId,
    query_egress_allowed: cleanQueryEgressAllowed,
    provider: cleanProvider,
    endpoint_url: cleanEndpointUrl,
    model_id: cleanModelId,
    pricing_version: pricingSpec.pricingVersion,
    allowed_fields_json: allowedFieldsJson,
    approved_by: cleanApprovedBy,
    issuer_channel: issuerChannel,
    approval_token_sha256: tokenHash,
    max_calls: maxCalls,
    reserved_calls: 0,
    used_calls: 0,
    max_input_tokens: maxInputTokens,
    reserved_input_tokens: 0,
    used_input_tokens: 0,
    max_output_tokens: maxOutputTokens,
    reserved_output_tokens: 0,
    used_output_tokens: 0,
    max_output_tokens_per_call: effectivePerCallOutCap,
    max_cost_micro_cny: maxCostMicroCny,
    reserved_cost_micro_cny: 0,
    used_cost_micro_cny: 0,
    status: 'active',
    created_at: cleanCreatedAt,
    expires_at: cleanExpiresAt
  };
  const integritySha256 = computeCloudApprovalIntegrityHash(record);

  runImmediateTransaction(db, () => {
    db.prepare(
      `INSERT INTO cloud_egress_approvals (
        cloud_approval_id, purpose, scope_ref, corpus_digest,
        bound_vault_id, bound_data_id, query_egress_allowed,
        provider, endpoint_url, model_id, pricing_version,
        allowed_fields_json, approved_by, issuer_channel, approval_token_sha256,
        max_calls, reserved_calls, used_calls,
        max_input_tokens, reserved_input_tokens, used_input_tokens,
        max_output_tokens, reserved_output_tokens, used_output_tokens,
        max_output_tokens_per_call,
        max_cost_micro_cny, reserved_cost_micro_cny, used_cost_micro_cny,
        status, created_at, expires_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, 0, 0,
        ?, 0, 0,
        ?, 0, 0,
        ?,
        ?, 0, 0,
        'active', ?, ?
      )`
    ).run(
      record.cloud_approval_id,
      record.purpose,
      record.scope_ref,
      record.corpus_digest,
      record.bound_vault_id,
      record.bound_data_id,
      record.query_egress_allowed,
      record.provider,
      record.endpoint_url,
      record.model_id,
      record.pricing_version,
      record.allowed_fields_json,
      record.approved_by,
      record.issuer_channel,
      record.approval_token_sha256,
      record.max_calls,
      record.max_input_tokens,
      record.max_output_tokens,
      record.max_output_tokens_per_call,
      record.max_cost_micro_cny,
      record.created_at,
      record.expires_at
    );

    db.prepare(
      `INSERT INTO cloud_egress_approval_meta (
        cloud_approval_id, pricing_snapshot_json, revoked_at, lock_reason, integrity_sha256
      ) VALUES (?, ?, NULL, NULL, ?)`
    ).run(record.cloud_approval_id, pricingSnapshotJson, integritySha256);
  });

  return {
    ...record,
    integrity_sha256: integritySha256,
    pricing_snapshot_json: pricingSnapshotJson
  };
}

function evaluateApprovalRow(
  db,
  row,
  {
    provider = null,
    modelId = null,
    purpose = null,
    endpointUrl = null,
    pricingVersion = null,
    vaultId = null,
    dataId = null,
    requiresQueryEgress = null,
    nowIso = new Date().toISOString()
  } = {}
) {
  if (!row) {
    return { valid: false, code: 'ERR_CLOUD_APPROVAL_NOT_FOUND', reason: 'approval not found' };
  }
  const meta = getApprovalMeta(db, row.cloud_approval_id);
  const expectedHash = computeCloudApprovalIntegrityHash(row);
  if (!meta || meta.integrity_sha256 !== expectedHash) {
    return {
      valid: false,
      code: 'ERR_CLOUD_APPROVAL_TAMPERED',
      reason: 'integrity_sha256 mismatch or missing approval meta'
    };
  }
  if (row.issuer_channel === 'test_harness' && isProductionCliRuntime()) {
    return {
      valid: false,
      code: 'ERR_TEST_HARNESS_FORBIDDEN_IN_PROD',
      reason: 'test_harness approval rejected in production CLI'
    };
  }
  if (row.status === 'restore_locked') {
    return {
      valid: false,
      code: 'ERR_APPROVAL_RESTORE_LOCKED',
      reason: meta.lock_reason || 'approval is restore_locked'
    };
  }
  if (row.status === 'overrun_paused') {
    return {
      valid: false,
      code: 'ERR_APPROVAL_OVERRUN_PAUSED',
      reason: 'approval is overrun_paused due to prior overrun billing'
    };
  }
  if (row.status === 'revoked') {
    return {
      valid: false,
      code: 'ERR_APPROVAL_REVOKED',
      reason: 'approval has been revoked'
    };
  }
  if (row.status === 'exhausted') {
    return {
      valid: false,
      code: 'ERR_CLOUD_BUDGET_EXCEEDED',
      reason: 'approval budget is exhausted'
    };
  }
  if (row.status === 'expired') {
    return {
      valid: false,
      code: 'ERR_APPROVAL_EXPIRED',
      reason: 'approval is expired'
    };
  }
  if (row.status !== 'active') {
    return {
      valid: false,
      code: 'ERR_APPROVAL_INACTIVE',
      reason: `unexpected status: ${row.status}`
    };
  }

  const nowMs = Date.parse(nowIso);
  const expMs = Date.parse(row.expires_at);
  if (!Number.isFinite(nowMs) || !Number.isFinite(expMs) || nowMs >= expMs) {
    return {
      valid: false,
      code: 'ERR_APPROVAL_EXPIRED',
      reason: `approval expired at ${row.expires_at}`
    };
  }

  if (vaultId !== null && row.bound_vault_id !== vaultId) {
    return {
      valid: false,
      code: 'ERR_INSTANCE_MISMATCH',
      reason: `bound_vault_id mismatch (${row.bound_vault_id} != ${vaultId})`
    };
  }
  if (dataId !== null && row.bound_data_id !== dataId) {
    return {
      valid: false,
      code: 'ERR_INSTANCE_MISMATCH',
      reason: `bound_data_id mismatch (${row.bound_data_id} != ${dataId})`
    };
  }
  if (provider !== null && row.provider !== provider) {
    return {
      valid: false,
      code: 'ERR_PROVIDER_MISMATCH',
      reason: `provider mismatch (${row.provider} != ${provider})`
    };
  }
  if (purpose !== null && row.purpose !== purpose) {
    return {
      valid: false,
      code: 'ERR_PURPOSE_MISMATCH',
      reason: `purpose mismatch (${row.purpose} != ${purpose})`
    };
  }
  if (modelId !== null && row.model_id !== modelId) {
    return {
      valid: false,
      code: 'ERR_MODEL_NOT_APPROVED',
      reason: `model_id ${modelId} != approved ${row.model_id}`
    };
  }
  if (endpointUrl !== null) {
    const cleanTarget = String(endpointUrl).trim().replace(/\/+$/, '');
    if (row.endpoint_url !== cleanTarget) {
      return {
        valid: false,
        code: 'ERR_ENDPOINT_MISMATCH',
        reason: `endpoint_url mismatch (${cleanTarget} != ${row.endpoint_url})`
      };
    }
  }
  if (pricingVersion !== null && row.pricing_version !== pricingVersion) {
    return {
      valid: false,
      code: 'ERR_PRICING_VERSION_MISMATCH',
      reason: `pricing_version mismatch (${pricingVersion} != ${row.pricing_version})`
    };
  }

  const effectivePurpose = purpose ?? row.purpose;
  const needsQueryEgress =
    effectivePurpose === 'embed_query' || Boolean(requiresQueryEgress);
  if (needsQueryEgress && row.query_egress_allowed !== 1) {
    return {
      valid: false,
      code: 'ERR_QUERY_EGRESS_FORBIDDEN',
      reason: `query_egress_allowed=0 forbids sending query for purpose=${effectivePurpose}`
    };
  }

  const allowedFields = parseJsonSafe(row.allowed_fields_json, null);
  if (!Array.isArray(allowedFields) || allowedFields.length === 0) {
    return {
      valid: false,
      code: 'ERR_INVALID_ALLOWED_FIELDS',
      reason: 'corrupt allowed_fields_json'
    };
  }

  return {
    valid: true,
    code: 'OK',
    row,
    meta,
    allowedFields
  };
}

export function verifyCloudEgressApproval(
  db,
  {
    cloudApprovalId,
    provider = null,
    modelId = null,
    purpose = null,
    endpointUrl = null,
    pricingVersion = null,
    vaultId = null,
    dataId = null,
    requiresQueryEgress = null,
    nowIso = new Date().toISOString()
  } = {}
) {
  if (!db) {
    return { valid: false, code: 'ERR_DB_REQUIRED', reason: 'database handle missing' };
  }
  if (typeof cloudApprovalId !== 'string' || !cloudApprovalId.startsWith('CEGR-')) {
    return {
      valid: false,
      code: 'ERR_INVALID_CLOUD_APPROVAL_PREFIX',
      reason: 'cloud egress approval must start with CEGR- (V2.5 EGR-/LSI- IDs rejected)'
    };
  }
  const row = db
    .prepare('SELECT * FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(cloudApprovalId);
  return evaluateApprovalRow(db, row, {
    provider,
    modelId,
    purpose,
    endpointUrl,
    pricingVersion,
    vaultId,
    dataId,
    requiresQueryEgress,
    nowIso
  });
}

export function revokeCloudEgressApproval(
  db,
  { cloudApprovalId, reason = 'revoked_by_operator', nowIso = new Date().toISOString() }
) {
  assertNonEmptyString(cloudApprovalId, 'cloudApprovalId');
  return runImmediateTransaction(db, () => {
    const existing = db
      .prepare('SELECT cloud_approval_id, status FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
      .get(cloudApprovalId);
    if (!existing) {
      throw createCloudError('ERR_CLOUD_APPROVAL_NOT_FOUND', `Approval not found: ${cloudApprovalId}`);
    }
    if (existing.status === 'restore_locked') {
      return { cloudApprovalId, status: 'restore_locked', changed: false };
    }
    db.prepare(
      `UPDATE cloud_egress_approvals
       SET status = 'revoked'
       WHERE cloud_approval_id = ?`
    ).run(cloudApprovalId);
    db.prepare(
      `UPDATE cloud_egress_approval_meta
       SET revoked_at = ?, lock_reason = ?
       WHERE cloud_approval_id = ?`
    ).run(nowIso, reason, cloudApprovalId);
    return { cloudApprovalId, status: 'revoked', changed: true };
  });
}

function reserveStageInActiveTransaction(
  db,
  {
    cloudApprovalId,
    runPlanId,
    requestId,
    parentRequestId = null,
    attemptNo = 1,
    provider,
    modelId,
    purpose,
    endpointUrl = null,
    pricingVersion = null,
    requiresQueryEgress = null,
    reservedInputTokens,
    maxOutputTokens = null,
    vaultId,
    dataId,
    nowIso
  }
) {
  assertNonEmptyString(cloudApprovalId, 'cloudApprovalId');
  assertNonEmptyString(requestId, 'requestId');
  assertSafePositiveInt(attemptNo, 'attemptNo');
  assertNonEmptyString(provider, 'provider');
  assertNonEmptyString(modelId, 'modelId');
  assertNonEmptyString(purpose, 'purpose');
  assertSafeNonNegativeInt(reservedInputTokens, 'reservedInputTokens');

  if (!cloudApprovalId.startsWith('CEGR-')) {
    throw createCloudError(
      'ERR_INVALID_CLOUD_APPROVAL_PREFIX',
      `Invalid cloud approval ID prefix: ${cloudApprovalId}`
    );
  }

  const approval = db
    .prepare('SELECT * FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(cloudApprovalId);
  const check = evaluateApprovalRow(db, approval, {
    provider,
    modelId,
    purpose,
    endpointUrl,
    pricingVersion,
    vaultId,
    dataId,
    requiresQueryEgress,
    nowIso
  });
  if (!check.valid) {
    throw createCloudError(check.code, check.reason, { cloudApprovalId });
  }

  const pricing = resolveModelPricingForApproval(db, approval, check.meta);
  const isZeroOutputPurpose =
    purpose === 'embed_doc' || purpose === 'embed_query' || purpose === 'rerank';

  const effectiveMaxOutput =
    maxOutputTokens === null || maxOutputTokens === undefined
      ? approval.max_output_tokens_per_call
      : assertSafeNonNegativeInt(maxOutputTokens, 'maxOutputTokens');

  if (isZeroOutputPurpose && effectiveMaxOutput > 0) {
    throw createCloudError(
      'ERR_OUTPUT_TOKENS_PER_CALL_EXCEEDED',
      `Purpose ${purpose} forbids non-zero maxOutputTokens (got ${effectiveMaxOutput})`
    );
  }
  if (effectiveMaxOutput > approval.max_output_tokens_per_call) {
    throw createCloudError(
      'ERR_OUTPUT_TOKENS_PER_CALL_EXCEEDED',
      `Requested maxOutputTokens (${effectiveMaxOutput}) exceeds max_output_tokens_per_call (${approval.max_output_tokens_per_call})`,
      {
        cloudApprovalId,
        requestedMaxOutputTokens: effectiveMaxOutput,
        maxOutputTokensPerCall: approval.max_output_tokens_per_call
      }
    );
  }

  const reservedCostMicroCny = estimateWorstCaseCostMicroCny({
    inputTokens: reservedInputTokens,
    maxOutputTokens: effectiveMaxOutput,
    pricing
  });

  const nextReservedCalls = assertSafeAddition(approval.reserved_calls, 1, 'reserved_calls');
  const nextReservedInputTokens = assertSafeAddition(
    approval.reserved_input_tokens,
    reservedInputTokens,
    'reserved_input_tokens'
  );
  const nextReservedOutputTokens = assertSafeAddition(
    approval.reserved_output_tokens,
    effectiveMaxOutput,
    'reserved_output_tokens'
  );
  const nextReservedCostMicroCny = assertSafeAddition(
    approval.reserved_cost_micro_cny,
    reservedCostMicroCny,
    'reserved_cost_micro_cny'
  );

  const projectedCalls = assertSafeAddition(approval.used_calls, nextReservedCalls, 'projected_calls');
  const projectedInputTokens = assertSafeAddition(
    approval.used_input_tokens,
    nextReservedInputTokens,
    'projected_input_tokens'
  );
  const projectedOutputTokens = assertSafeAddition(
    approval.used_output_tokens,
    nextReservedOutputTokens,
    'projected_output_tokens'
  );
  const projectedCostMicroCny = assertSafeAddition(
    approval.used_cost_micro_cny,
    nextReservedCostMicroCny,
    'projected_cost_micro_cny'
  );

  if (
    projectedCalls > approval.max_calls ||
    projectedInputTokens > approval.max_input_tokens ||
    projectedOutputTokens > approval.max_output_tokens ||
    projectedCostMicroCny > approval.max_cost_micro_cny
  ) {
    throw createCloudError(
      'ERR_CLOUD_BUDGET_EXCEEDED',
      `Insufficient cloud budget on ${cloudApprovalId} for request ${requestId}`,
      {
        cloudApprovalId,
        projectedCalls,
        maxCalls: approval.max_calls,
        projectedInputTokens,
        maxInputTokens: approval.max_input_tokens,
        projectedOutputTokens,
        maxOutputTokens: approval.max_output_tokens,
        projectedCostMicroCny,
        maxCostMicroCny: approval.max_cost_micro_cny
      }
    );
  }

  const existingLedger = db
    .prepare('SELECT request_id FROM cloud_egress_usage_ledger WHERE request_id = ?')
    .get(requestId);
  if (existingLedger) {
    throw createCloudError(
      'ERR_DUPLICATE_REQUEST_ID',
      `Ledger already contains request_id ${requestId}`
    );
  }

  // Reservation writes ONLY to reserved_* columns (never mutates used_*!)
  db.prepare(
    `UPDATE cloud_egress_approvals
     SET reserved_calls = ?,
         reserved_input_tokens = ?,
         reserved_output_tokens = ?,
         reserved_cost_micro_cny = ?
     WHERE cloud_approval_id = ?`
  ).run(
    nextReservedCalls,
    nextReservedInputTokens,
    nextReservedOutputTokens,
    nextReservedCostMicroCny,
    cloudApprovalId
  );

  db.prepare(
    `INSERT INTO cloud_egress_usage_ledger (
      request_id, parent_request_id, attempt_no, run_plan_id,
      cloud_approval_id, purpose, query_egress_allowed,
      provider, endpoint_url, model_id, pricing_version,
      reservation_state, http_status,
      reserved_input_tokens, reserved_output_tokens,
      prompt_tokens, completion_tokens, reasoning_tokens, billable_output_tokens, total_tokens,
      reserved_cost_micro_cny, billed_cost_micro_cny,
      egress_bytes, latency_ms, outcome, created_at, settled_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?, ?,
      'reserved', NULL,
      ?, ?,
      0, 0, 0, 0, 0,
      ?, 0,
      0, 0, 'pending', ?, NULL
    )`
  ).run(
    requestId,
    parentRequestId,
    attemptNo,
    runPlanId || null,
    cloudApprovalId,
    purpose,
    approval.query_egress_allowed,
    provider,
    approval.endpoint_url,
    modelId,
    approval.pricing_version,
    reservedInputTokens,
    effectiveMaxOutput,
    reservedCostMicroCny,
    nowIso
  );

  return {
    requestId,
    parentRequestId,
    attemptNo,
    runPlanId: runPlanId || null,
    cloudApprovalId,
    provider,
    endpointUrl: approval.endpoint_url,
    modelId,
    purpose,
    pricingVersion: approval.pricing_version,
    queryEgressAllowed: approval.query_egress_allowed,
    reservedInputTokens,
    reservedOutputTokens: effectiveMaxOutput,
    reservedCostMicroCny,
    pricing
  };
}

export function reserveCloudEgressBudget(
  db,
  {
    cloudApprovalId,
    runPlanId = `run-${crypto.randomUUID()}`,
    requestId = `req-${crypto.randomUUID()}`,
    parentRequestId = null,
    attemptNo = 1,
    provider,
    modelId,
    purpose,
    endpointUrl = null,
    pricingVersion = null,
    requiresQueryEgress = null,
    reservedInputTokens,
    maxOutputTokens = null,
    vaultId,
    dataId,
    nowIso = new Date().toISOString()
  }
) {
  return runImmediateTransaction(db, () =>
    reserveStageInActiveTransaction(db, {
      cloudApprovalId,
      runPlanId,
      requestId,
      parentRequestId,
      attemptNo,
      provider,
      modelId,
      purpose,
      endpointUrl,
      pricingVersion,
      requiresQueryEgress,
      reservedInputTokens,
      maxOutputTokens,
      vaultId,
      dataId,
      nowIso
    })
  );
}

export function reserveRunPlanBudgets(
  db,
  {
    runPlanId = `run-${crypto.randomUUID()}`,
    stages,
    vaultId,
    dataId,
    nowIso = new Date().toISOString()
  }
) {
  if (!Array.isArray(stages) || stages.length === 0) {
    throw createCloudError('ERR_INVALID_RUN_PLAN', 'stages must be a non-empty array');
  }
  return runImmediateTransaction(db, () => {
    const reservations = [];
    for (const stage of stages) {
      const requestId = stage.requestId || `req-${crypto.randomUUID()}`;
      reservations.push(
        reserveStageInActiveTransaction(db, {
          cloudApprovalId: stage.cloudApprovalId,
          runPlanId,
          requestId,
          parentRequestId: stage.parentRequestId ?? null,
          attemptNo: stage.attemptNo ?? 1,
          provider: stage.provider,
          modelId: stage.modelId,
          purpose: stage.purpose,
          endpointUrl: stage.endpointUrl ?? null,
          pricingVersion: stage.pricingVersion ?? null,
          requiresQueryEgress: stage.requiresQueryEgress ?? null,
          reservedInputTokens: stage.reservedInputTokens,
          maxOutputTokens: stage.maxOutputTokens ?? null,
          vaultId,
          dataId,
          nowIso
        })
      );
    }
    return {
      runPlanId,
      reservations
    };
  });
}

function releasePrecheckFailedInTxn(
  db,
  { requestId, httpStatus = null, nowIso }
) {
  const row = db
    .prepare('SELECT * FROM cloud_egress_usage_ledger WHERE request_id = ?')
    .get(requestId);
  if (!row) {
    throw createCloudError('ERR_LEDGER_NOT_FOUND', `Ledger row not found: ${requestId}`);
  }
  if (row.reservation_state !== 'reserved') {
    return {
      released: false,
      idempotent: true,
      requestId,
      reservationState: row.reservation_state,
      outcome: row.outcome
    };
  }

  const res = db
    .prepare(
      `UPDATE cloud_egress_usage_ledger
       SET reservation_state = 'released_precheck_failed',
           outcome = 'denied',
           http_status = COALESCE(?, http_status),
           egress_bytes = 0,
           latency_ms = 0,
           settled_at = ?
       WHERE request_id = ? AND reservation_state = 'reserved'`
    )
    .run(httpStatus, nowIso, requestId);

  if (res.changes !== 1) {
    return {
      released: false,
      idempotent: true,
      requestId,
      reservationState: row.reservation_state,
      outcome: row.outcome
    };
  }

  const approval = db
    .prepare('SELECT * FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(row.cloud_approval_id);
  if (approval) {
    const nextReservedCalls = Math.max(0, approval.reserved_calls - 1);
    const nextReservedIn = Math.max(0, approval.reserved_input_tokens - row.reserved_input_tokens);
    const nextReservedOut = Math.max(0, approval.reserved_output_tokens - row.reserved_output_tokens);
    const nextReservedCost = Math.max(0, approval.reserved_cost_micro_cny - row.reserved_cost_micro_cny);
    db.prepare(
      `UPDATE cloud_egress_approvals
       SET reserved_calls = ?,
           reserved_input_tokens = ?,
           reserved_output_tokens = ?,
           reserved_cost_micro_cny = ?
       WHERE cloud_approval_id = ?`
    ).run(
      nextReservedCalls,
      nextReservedIn,
      nextReservedOut,
      nextReservedCost,
      approval.cloud_approval_id
    );
  }

  return {
    released: true,
    idempotent: false,
    requestId,
    reservationState: 'released_precheck_failed',
    outcome: 'denied'
  };
}

export function releasePrecheckFailedReservation(
  db,
  { requestId, httpStatus = null, nowIso = new Date().toISOString() }
) {
  assertNonEmptyString(requestId, 'requestId');
  return runImmediateTransaction(db, () =>
    releasePrecheckFailedInTxn(db, { requestId, httpStatus, nowIso })
  );
}

export function recheckApprovalBeforeSend(
  db,
  {
    cloudApprovalId,
    requestId,
    provider = null,
    modelId = null,
    purpose = null,
    endpointUrl = null,
    pricingVersion = null,
    requiresQueryEgress = null,
    vaultId,
    dataId,
    nowIso = new Date().toISOString()
  }
) {
  return runImmediateTransaction(db, () => {
    const ledger = db
      .prepare('SELECT * FROM cloud_egress_usage_ledger WHERE request_id = ?')
      .get(requestId);
    if (!ledger || ledger.reservation_state !== 'reserved') {
      return {
        allowed: false,
        code: 'ERR_RESERVATION_NOT_ACTIVE',
        reason: `reservation ${requestId} is not in reserved state`,
        released: false
      };
    }

    const approval = db
      .prepare('SELECT * FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
      .get(cloudApprovalId);
    const check = evaluateApprovalRow(db, approval, {
      provider: provider ?? ledger.provider,
      modelId: modelId ?? ledger.model_id,
      purpose: purpose ?? ledger.purpose,
      endpointUrl: endpointUrl ?? ledger.endpoint_url,
      pricingVersion: pricingVersion ?? ledger.pricing_version,
      requiresQueryEgress,
      vaultId,
      dataId,
      nowIso
    });
    if (!check.valid) {
      const rel = releasePrecheckFailedInTxn(db, {
        requestId,
        nowIso
      });
      return {
        allowed: false,
        code: check.code,
        reason: check.reason,
        released: rel.released
      };
    }
    return {
      allowed: true,
      code: 'OK',
      released: false
    };
  });
}

function settleRowInTxn(
  db,
  {
    requestId,
    allowedFromStates,
    actualInputTokens,
    actualOutputTokens = 0,
    actualReasoningTokens = 0,
    completionIncludesReasoning = true,
    httpStatus = 200,
    egressBytes = null,
    latencyMs = null,
    outcome = 'ok',
    countCall = true,
    nowIso
  }
) {
  assertSafeNonNegativeInt(actualInputTokens, 'actualInputTokens');
  assertSafeNonNegativeInt(actualOutputTokens, 'actualOutputTokens');
  assertSafeNonNegativeInt(actualReasoningTokens, 'actualReasoningTokens');
  if (!['ok', 'http_error', 'invalid_response', 'timeout', 'crash_retained'].includes(outcome)) {
    throw createCloudError('ERR_INVALID_OUTCOME', `Invalid settlement outcome: ${String(outcome)}`);
  }

  const ledger = db
    .prepare('SELECT * FROM cloud_egress_usage_ledger WHERE request_id = ?')
    .get(requestId);
  if (!ledger) {
    throw createCloudError('ERR_LEDGER_NOT_FOUND', `Ledger row not found: ${requestId}`);
  }
  if (!allowedFromStates.includes(ledger.reservation_state)) {
    return {
      settled: false,
      idempotent: true,
      requestId,
      reservationState: ledger.reservation_state,
      outcome: ledger.outcome,
      billedCostMicroCny: ledger.billed_cost_micro_cny,
      overrunPaused: false
    };
  }

  const approval = db
    .prepare('SELECT * FROM cloud_egress_approvals WHERE cloud_approval_id = ?')
    .get(ledger.cloud_approval_id);
  if (!approval) {
    throw createCloudError(
      'ERR_CLOUD_APPROVAL_NOT_FOUND',
      `Approval not found for ledger ${requestId}: ${ledger.cloud_approval_id}`
    );
  }
  const meta = getApprovalMeta(db, approval.cloud_approval_id);
  const pricing = resolveModelPricingForApproval(db, approval, meta);
  const { billableOutputTokens, billedCostMicroCny } = computeActualCostMicroCny({
    actualInputTokens,
    actualOutputTokens,
    actualReasoningTokens,
    completionIncludesReasoning,
    pricing
  });
  const totalTokens = assertSafeAddition(actualInputTokens, billableOutputTokens, 'totalTokens');
  const validHttpStatus =
    httpStatus === null || httpStatus === undefined
      ? null
      : assertSafePositiveInt(httpStatus, 'httpStatus');
  const finalEgressBytes =
    egressBytes === null || egressBytes === undefined
      ? ledger.egress_bytes
      : assertSafeNonNegativeInt(egressBytes, 'egressBytes');
  const finalLatencyMs =
    latencyMs === null || latencyMs === undefined
      ? ledger.latency_ms
      : assertSafeNonNegativeReal(latencyMs, 'latencyMs');

  const placeholders = allowedFromStates.map(() => '?').join(', ');
  const updateRes = db
    .prepare(
      `UPDATE cloud_egress_usage_ledger
       SET reservation_state = 'settled',
           http_status = COALESCE(?, http_status),
           prompt_tokens = ?,
           completion_tokens = ?,
           reasoning_tokens = ?,
           billable_output_tokens = ?,
           total_tokens = ?,
           billed_cost_micro_cny = ?,
           egress_bytes = ?,
           latency_ms = ?,
           outcome = ?,
           settled_at = ?
       WHERE request_id = ? AND reservation_state IN (${placeholders})`
    )
    .run(
      validHttpStatus,
      actualInputTokens,
      actualOutputTokens,
      actualReasoningTokens,
      billableOutputTokens,
      totalTokens,
      billedCostMicroCny,
      finalEgressBytes,
      finalLatencyMs,
      outcome,
      nowIso,
      requestId,
      ...allowedFromStates
    );

  if (updateRes.changes !== 1) {
    return {
      settled: false,
      idempotent: true,
      requestId,
      reservationState: ledger.reservation_state,
      outcome: ledger.outcome,
      billedCostMicroCny: ledger.billed_cost_micro_cny,
      overrunPaused: false
    };
  }

  const nextReservedCalls = Math.max(0, approval.reserved_calls - 1);
  const nextReservedInputTokens = Math.max(0, approval.reserved_input_tokens - ledger.reserved_input_tokens);
  const nextReservedOutputTokens = Math.max(0, approval.reserved_output_tokens - ledger.reserved_output_tokens);
  const nextReservedCostMicroCny = Math.max(0, approval.reserved_cost_micro_cny - ledger.reserved_cost_micro_cny);

  const nextUsedCalls = assertSafeAddition(approval.used_calls, countCall ? 1 : 0, 'used_calls');
  const nextUsedInputTokens = assertSafeAddition(approval.used_input_tokens, actualInputTokens, 'used_input_tokens');
  const nextUsedOutputTokens = assertSafeAddition(approval.used_output_tokens, billableOutputTokens, 'used_output_tokens');
  const nextUsedCostMicroCny = assertSafeAddition(approval.used_cost_micro_cny, billedCostMicroCny, 'used_cost_micro_cny');

  const committedPlusReservedCost = assertSafeAddition(
    nextUsedCostMicroCny,
    nextReservedCostMicroCny,
    'total_cost'
  );
  const committedPlusReservedInput = assertSafeAddition(
    nextUsedInputTokens,
    nextReservedInputTokens,
    'total_input'
  );
  const committedPlusReservedOutput = assertSafeAddition(
    nextUsedOutputTokens,
    nextReservedOutputTokens,
    'total_output'
  );

  const overrunTriggered =
    billedCostMicroCny > ledger.reserved_cost_micro_cny ||
    actualInputTokens > ledger.reserved_input_tokens ||
    billableOutputTokens > ledger.reserved_output_tokens ||
    committedPlusReservedCost > approval.max_cost_micro_cny ||
    committedPlusReservedInput > approval.max_input_tokens ||
    committedPlusReservedOutput > approval.max_output_tokens;

  let nextStatus = approval.status;
  let lockReason = meta?.lock_reason ?? null;
  if (overrunTriggered) {
    if (approval.status !== 'restore_locked' && approval.status !== 'revoked') {
      nextStatus = 'overrun_paused';
      lockReason = `overrun: billed=${billedCostMicroCny}, reserved=${ledger.reserved_cost_micro_cny}, totalCost=${committedPlusReservedCost}/${approval.max_cost_micro_cny}, billableOut=${billableOutputTokens}/${ledger.reserved_output_tokens}`;
    }
  } else if (approval.status === 'active') {
    if (
      nextUsedCalls >= approval.max_calls ||
      nextUsedCostMicroCny >= approval.max_cost_micro_cny ||
      nextUsedInputTokens >= approval.max_input_tokens ||
      (approval.max_output_tokens > 0 && nextUsedOutputTokens >= approval.max_output_tokens)
    ) {
      nextStatus = 'exhausted';
    }
  }

  db.prepare(
    `UPDATE cloud_egress_approvals
     SET reserved_calls = ?,
         used_calls = ?,
         reserved_input_tokens = ?,
         used_input_tokens = ?,
         reserved_output_tokens = ?,
         used_output_tokens = ?,
         reserved_cost_micro_cny = ?,
         used_cost_micro_cny = ?,
         status = ?
     WHERE cloud_approval_id = ?`
  ).run(
    nextReservedCalls,
    nextUsedCalls,
    nextReservedInputTokens,
    nextUsedInputTokens,
    nextReservedOutputTokens,
    nextUsedOutputTokens,
    nextReservedCostMicroCny,
    nextUsedCostMicroCny,
    nextStatus,
    approval.cloud_approval_id
  );

  if (lockReason !== (meta?.lock_reason ?? null)) {
    db.prepare(
      `UPDATE cloud_egress_approval_meta SET lock_reason = ? WHERE cloud_approval_id = ?`
    ).run(lockReason, approval.cloud_approval_id);
  }

  return {
    settled: true,
    idempotent: false,
    requestId,
    cloudApprovalId: approval.cloud_approval_id,
    reservationState: 'settled',
    outcome,
    actualOutputTokens,
    billableOutputTokens,
    totalTokens,
    billedCostMicroCny,
    reservedCalls: nextReservedCalls,
    usedCalls: nextUsedCalls,
    reservedInputTokens: nextReservedInputTokens,
    usedInputTokens: nextUsedInputTokens,
    reservedOutputTokens: nextReservedOutputTokens,
    usedOutputTokens: nextUsedOutputTokens,
    reservedCostMicroCny: nextReservedCostMicroCny,
    usedCostMicroCny: nextUsedCostMicroCny,
    status: nextStatus,
    overrunPaused: nextStatus === 'overrun_paused'
  };
}

export function settleCloudEgressUsage(
  db,
  {
    requestId,
    actualInputTokens,
    actualOutputTokens = 0,
    actualReasoningTokens = 0,
    completionIncludesReasoning = true,
    httpStatus = 200,
    egressBytes = null,
    latencyMs = null,
    outcome = 'ok',
    countCall = true,
    nowIso = new Date().toISOString()
  }
) {
  assertNonEmptyString(requestId, 'requestId');
  return runImmediateTransaction(db, () =>
    settleRowInTxn(db, {
      requestId,
      allowedFromStates: ['reserved'],
      actualInputTokens,
      actualOutputTokens,
      actualReasoningTokens,
      completionIncludesReasoning,
      httpStatus,
      egressBytes,
      latencyMs,
      outcome,
      countCall,
      nowIso
    })
  );
}

export function retainCloudEgressReservation(
  db,
  {
    requestId,
    state = 'retained_on_timeout',
    outcome = 'timeout',
    httpStatus = null,
    egressBytes = null,
    latencyMs = null,
    nowIso = new Date().toISOString()
  }
) {
  assertNonEmptyString(requestId, 'requestId');
  if (state !== 'retained_on_timeout' && state !== 'retained_on_unknown_bill') {
    throw createCloudError(
      'ERR_INVALID_RETENTION_STATE',
      `Retention state must be 'retained_on_timeout' or 'retained_on_unknown_bill', got ${String(state)}`
    );
  }
  if (!['timeout', 'http_error', 'invalid_response', 'crash_retained'].includes(outcome)) {
    throw createCloudError('ERR_INVALID_OUTCOME', `Invalid retention outcome: ${String(outcome)}`);
  }
  const validHttpStatus =
    httpStatus === null || httpStatus === undefined
      ? null
      : assertSafePositiveInt(httpStatus, 'httpStatus');
  const validEgressBytes =
    egressBytes === null || egressBytes === undefined
      ? null
      : assertSafeNonNegativeInt(egressBytes, 'egressBytes');
  const validLatencyMs =
    latencyMs === null || latencyMs === undefined
      ? null
      : assertSafeNonNegativeReal(latencyMs, 'latencyMs');

  return runImmediateTransaction(db, () => {
    const row = db
      .prepare('SELECT reservation_state, outcome FROM cloud_egress_usage_ledger WHERE request_id = ?')
      .get(requestId);
    if (!row) {
      throw createCloudError('ERR_LEDGER_NOT_FOUND', `Ledger row not found: ${requestId}`);
    }
    if (row.reservation_state !== 'reserved') {
      return {
        retained: false,
        idempotent: true,
        requestId,
        reservationState: row.reservation_state,
        outcome: row.outcome
      };
    }
    const res = db
      .prepare(
        `UPDATE cloud_egress_usage_ledger
         SET reservation_state = ?,
             outcome = ?,
             http_status = COALESCE(?, http_status),
             egress_bytes = COALESCE(?, egress_bytes),
             latency_ms = COALESCE(?, latency_ms),
             settled_at = ?
         WHERE request_id = ? AND reservation_state = 'reserved'`
      )
      .run(state, outcome, validHttpStatus, validEgressBytes, validLatencyMs, nowIso, requestId);

    return {
      retained: res.changes === 1,
      idempotent: res.changes === 0,
      requestId,
      reservationState: state,
      outcome
    };
  });
}

export function recoverCrashRetainedReservations(
  db,
  {
    staleBeforeIso = null,
    nowIso = new Date().toISOString()
  } = {}
) {
  return runImmediateTransaction(db, () => {
    const targets = staleBeforeIso
      ? db
          .prepare(
            `SELECT request_id FROM cloud_egress_usage_ledger
             WHERE reservation_state = 'reserved' AND created_at <= ?`
          )
          .all(staleBeforeIso)
      : db
          .prepare(
            `SELECT request_id FROM cloud_egress_usage_ledger
             WHERE reservation_state = 'reserved'`
          )
          .all();

    const res = staleBeforeIso
      ? db
          .prepare(
            `UPDATE cloud_egress_usage_ledger
             SET reservation_state = 'retained_on_unknown_bill',
                 outcome = 'crash_retained',
                 settled_at = ?
             WHERE reservation_state = 'reserved' AND created_at <= ?`
          )
          .run(nowIso, staleBeforeIso)
      : db
          .prepare(
            `UPDATE cloud_egress_usage_ledger
             SET reservation_state = 'retained_on_unknown_bill',
                 outcome = 'crash_retained',
                 settled_at = ?
             WHERE reservation_state = 'reserved'`
          )
          .run(nowIso);

    return {
      recoveredCount: res.changes,
      recoveredRequestIds: targets.map((r) => r.request_id)
    };
  });
}

export function reconcileRetainedLedgerEntry(
  db,
  {
    requestId,
    outcome,
    actualInputTokens = 0,
    actualOutputTokens = 0,
    actualReasoningTokens = 0,
    completionIncludesReasoning = true,
    httpStatus = null,
    egressBytes = null,
    latencyMs = null,
    nowIso = new Date().toISOString()
  }
) {
  assertNonEmptyString(requestId, 'requestId');
  if (outcome !== 'confirmed_unbilled' && outcome !== 'confirmed_billed') {
    throw createCloudError(
      'ERR_INVALID_RECONCILE_OUTCOME',
      `outcome must be 'confirmed_unbilled' or 'confirmed_billed', got ${String(outcome)}`
    );
  }
  return runImmediateTransaction(db, () => {
    const row = db
      .prepare('SELECT reservation_state, outcome FROM cloud_egress_usage_ledger WHERE request_id = ?')
      .get(requestId);
    if (!row) {
      throw createCloudError('ERR_LEDGER_NOT_FOUND', `Ledger row not found: ${requestId}`);
    }
    if (
      row.reservation_state !== 'retained_on_timeout' &&
      row.reservation_state !== 'retained_on_unknown_bill'
    ) {
      return {
        reconciled: false,
        idempotent: true,
        requestId,
        reservationState: row.reservation_state,
        outcome: row.outcome
      };
    }

    if (outcome === 'confirmed_unbilled') {
      const preservedOutcome = ['timeout', 'http_error', 'invalid_response', 'crash_retained'].includes(
        row.outcome
      )
        ? row.outcome
        : row.reservation_state === 'retained_on_timeout'
          ? 'timeout'
          : 'http_error';

      const settledZero = settleRowInTxn(db, {
        requestId,
        allowedFromStates: ['retained_on_timeout', 'retained_on_unknown_bill'],
        actualInputTokens: 0,
        actualOutputTokens: 0,
        actualReasoningTokens: 0,
        completionIncludesReasoning: true,
        httpStatus,
        egressBytes,
        latencyMs,
        outcome: preservedOutcome,
        countCall: false,
        nowIso
      });
      return {
        reconciled: settledZero.settled,
        idempotent: settledZero.idempotent,
        requestId,
        reservationState: settledZero.reservationState,
        outcome: settledZero.outcome,
        billedCostMicroCny: settledZero.billedCostMicroCny
      };
    }

    const billedOutcome = row.outcome === 'crash_retained' ? 'crash_retained' : 'ok';
    const settled = settleRowInTxn(db, {
      requestId,
      allowedFromStates: ['retained_on_timeout', 'retained_on_unknown_bill'],
      actualInputTokens,
      actualOutputTokens,
      actualReasoningTokens,
      completionIncludesReasoning,
      httpStatus: httpStatus ?? 200,
      egressBytes,
      latencyMs,
      outcome: billedOutcome,
      countCall: true,
      nowIso
    });
    return {
      reconciled: settled.settled,
      idempotent: settled.idempotent,
      requestId,
      reservationState: settled.reservationState,
      outcome: settled.outcome,
      billedCostMicroCny: settled.billedCostMicroCny,
      overrunPaused: settled.overrunPaused
    };
  });
}

export function lockRestoredCloudApprovals(
  db,
  {
    newVaultId = null,
    newDataId = null,
    reason = 'whole_db_restore_locked',
    nowIso = new Date().toISOString()
  } = {}
) {
  if (!db) {
    return { hasSchema: false, lockedCount: 0, recoveredRetainedCount: 0 };
  }
  const hasTable = db
    .prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'cloud_egress_approvals'`
    )
    .get();
  if (!hasTable) {
    return { hasSchema: false, lockedCount: 0, recoveredRetainedCount: 0 };
  }

  return runImmediateTransaction(db, () => {
    const recovered = db
      .prepare(
        `UPDATE cloud_egress_usage_ledger
         SET reservation_state = 'retained_on_unknown_bill',
             outcome = 'crash_retained',
             settled_at = ?
         WHERE reservation_state = 'reserved'`
      )
      .run(nowIso);

    const detailReason =
      newVaultId && newDataId
        ? `${reason}:new_instance=${newVaultId}/${newDataId}`
        : reason;

    const toLock = db
      .prepare(
        `SELECT cloud_approval_id FROM cloud_egress_approvals
         WHERE status IN ('active', 'exhausted', 'overrun_paused')`
      )
      .all();

    const locked = db
      .prepare(
        `UPDATE cloud_egress_approvals
         SET status = 'restore_locked'
         WHERE status IN ('active', 'exhausted', 'overrun_paused')`
      )
      .run();

    for (const row of toLock) {
      db.prepare(
        `UPDATE cloud_egress_approval_meta
         SET lock_reason = COALESCE(lock_reason, ?)
         WHERE cloud_approval_id = ?`
      ).run(detailReason, row.cloud_approval_id);
    }

    return {
      hasSchema: true,
      lockedCount: locked.changes,
      recoveredRetainedCount: recovered.changes
    };
  });
}

export function restoreOperatorDatabase({
  sourceDbPath,
  targetDbPath,
  newVaultId,
  newDataId,
  reason = 'operator_db_rollback_locked',
  nowIso = new Date().toISOString()
}) {
  const resolvedSrc = path.resolve(assertNonEmptyString(sourceDbPath, 'sourceDbPath'));
  const resolvedDst = path.resolve(assertNonEmptyString(targetDbPath, 'targetDbPath'));
  const samePath = process.platform === 'win32'
    ? resolvedSrc.toLowerCase() === resolvedDst.toLowerCase()
    : resolvedSrc === resolvedDst;
  if (samePath) {
    throw createCloudError(
      'ERR_INVALID_RESTORE_TARGET',
      `Operator DB restore target cannot equal source path: ${resolvedDst}`
    );
  }
  if (!fs.existsSync(resolvedSrc)) {
    throw createCloudError('ERR_OPERATOR_BACKUP_NOT_FOUND', `Missing backup DB: ${resolvedSrc}`);
  }
  fs.mkdirSync(path.dirname(resolvedDst), { recursive: true });
  fs.copyFileSync(resolvedSrc, resolvedDst);

  for (const suffix of ['-wal', '-shm']) {
    const staleSidecar = `${resolvedDst}${suffix}`;
    if (fs.existsSync(staleSidecar)) {
      fs.unlinkSync(staleSidecar);
    }
  }

  const db = openOperatorDatabase(resolvedDst, { autoMigrate: false });
  try {
    const lockRes = lockRestoredCloudApprovals(db, {
      newVaultId,
      newDataId,
      reason,
      nowIso
    });
    return {
      restored: true,
      targetDbPath: resolvedDst,
      ...lockRes
    };
  } finally {
    db.close();
  }
}
