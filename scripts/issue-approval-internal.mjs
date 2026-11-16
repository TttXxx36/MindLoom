#!/usr/bin/env node
import path from 'node:path';
import {
  openOperatorDatabase,
  issueCloudEgressApproval,
  DEFAULT_PRICING_VERSION
} from '../src/security/cloud-approvals.mjs';
import {
  DEFAULT_OPERATOR_ROOT,
  buildOperatorIsolationTargets,
  isCurrentWindowsProcessElevated
} from '../src/security/isolation-sentinel.mjs';
import {
  EMRANK_DEFAULT_ENDPOINT_URL,
  EMRANK_DEFAULT_MODEL_ID,
  initEmrankTrialWorkspace
} from '../src/benchmark/emrank-trial.mjs';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1];
      if (val !== undefined && !String(val).startsWith('--')) {
        out[key] = val;
        i++;
      } else {
        out[key] = true;
      }
    }
  }
  return out;
}

if (process.env.OAM_APPROVE_HUMAN_TTY !== '1') {
  throw new Error('ERR_UNTRUSTED_APPROVAL_INVOCATION: Must be invoked exclusively via interactive approve-human.ps1');
}
if (!isCurrentWindowsProcessElevated()) {
  throw new Error('ERR_ELEVATION_REQUIRED: Interactive approval issuer requires elevated Administrator privileges');
}

const args = parseArgs(process.argv.slice(2));
const operatorRoot = path.resolve(String(args['operator-root'] || DEFAULT_OPERATOR_ROOT));
const targets = buildOperatorIsolationTargets({ operatorRoot });
const workspaceDir = path.resolve(String(args.workspace || targets.trialWorkspaceDir));
const meta = initEmrankTrialWorkspace({ workspaceDir });

const provider = String(args.provider || 'emrank');
const endpointUrl = String(args['endpoint-url'] || EMRANK_DEFAULT_ENDPOINT_URL);
const modelId = String(args['model-id'] || EMRANK_DEFAULT_MODEL_ID);
const priceMicroCnyPerM = Number(args['price-micro-cny'] || 140_000);
const maxDocCalls = Number(args['doc-calls'] || 4);
const maxDocTokens = Number(args['doc-tokens'] || 6_000);
const maxDocCostMicroCny = Number(args['doc-cost'] || 20_000);
const maxQueryCalls = Number(args['query-calls'] || 16);
const maxQueryTokens = Number(args['query-tokens'] || 14_000);
const maxQueryCostMicroCny = Number(args['query-cost'] || 80_000);
const ttlHours = Number(args['ttl-hours'] || 24);
const approvedBy = String(args['approved-by'] || 'human-operator-tty');
const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();

const db = openOperatorDatabase(targets.operatorDbPath, { autoMigrate: true });
try {
  const pricingOverride = {
    pricingVersion: DEFAULT_PRICING_VERSION,
    inputMicroCnyPerMillionTokens: priceMicroCnyPerM,
    outputMicroCnyPerMillionTokens: 0,
    completionIncludesReasoning: true,
    defaultMaxOutputTokens: 0
  };

  const docApproval = issueCloudEgressApproval(db, {
    purpose: 'embed_doc',
    scopeRef: meta.scope_ref,
    corpusDigest: meta.corpus_digest,
    boundVaultId: meta.vault_id,
    boundDataId: meta.data_id,
    queryEgressAllowed: 0,
    provider,
    endpointUrl,
    modelId,
    pricingVersion: DEFAULT_PRICING_VERSION,
    pricingOverride,
    approvedBy,
    issuerChannel: 'operator_tty_ps1',
    maxCalls: maxDocCalls,
    maxInputTokens: maxDocTokens,
    maxOutputTokens: 0,
    maxOutputTokensPerCall: 0,
    maxCostMicroCny: maxDocCostMicroCny,
    expiresAt,
    trustedHumanContext: true
  });

  const queryApproval = issueCloudEgressApproval(db, {
    purpose: 'embed_query',
    scopeRef: meta.scope_ref,
    corpusDigest: meta.corpus_digest,
    boundVaultId: meta.vault_id,
    boundDataId: meta.data_id,
    queryEgressAllowed: 1,
    provider,
    endpointUrl,
    modelId,
    pricingVersion: DEFAULT_PRICING_VERSION,
    pricingOverride,
    approvedBy,
    issuerChannel: 'operator_tty_ps1',
    maxCalls: maxQueryCalls,
    maxInputTokens: maxQueryTokens,
    maxOutputTokens: 0,
    maxOutputTokensPerCall: 0,
    maxCostMicroCny: maxQueryCostMicroCny,
    expiresAt,
    trustedHumanContext: true
  });

  process.stdout.write(
    JSON.stringify(
      {
        issuedAt: new Date().toISOString(),
        operatorDbPath: targets.operatorDbPath,
        workspaceDir,
        boundVaultId: meta.vault_id,
        boundDataId: meta.data_id,
        corpusDigest: meta.corpus_digest,
        embedDocApprovalId: docApproval.cloud_approval_id,
        embedQueryApprovalId: queryApproval.cloud_approval_id,
        expiresAt,
        totalMaxCalls: maxDocCalls + maxQueryCalls,
        totalMaxInputTokens: maxDocTokens + maxQueryTokens,
        totalMaxCostMicroCny: maxDocCostMicroCny + maxQueryCostMicroCny
      },
      null,
      2
    ) + '\n'
  );
} finally {
  db.close();
}
