#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  openOperatorDatabase,
  issueCloudEgressApproval
} from '../src/security/cloud-approvals.mjs';
import { assertNoForbiddenCliFlags } from '../src/security/trusted-approvals.mjs';
import {
  DEFAULT_OPERATOR_ROOT,
  buildOperatorIsolationTargets,
  isCurrentWindowsProcessElevated,
  runFourPointCloudIsolationSentinel,
  verifyElevatedWindowsOperatorAclIsolation,
  assertRealCloudApiGate
} from '../src/security/isolation-sentinel.mjs';
import {
  EMRANK_DEFAULT_ENDPOINT_URL,
  EMRANK_DEFAULT_MODEL_ID,
  initEmrankTrialWorkspace,
  runEmrankControlledTrial
} from '../src/benchmark/emrank-trial.mjs';
import { DEFAULT_VAULT_PATH, DEFAULT_DATA_PATH } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { readInstanceIdentity } from '../src/storage/instance-identity.mjs';
import { distillSessionWithLlmAsync } from '../src/distill/llm-distiller.mjs';
import { sanitizeOutputText } from '../src/security/sanitizer.mjs';

process.env.OAM_PRODUCTION_CLI = '1';

function parseCliArgs(argv) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = String(argv[i]);
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx > 0) {
        flags[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
      } else {
        const key = arg.slice(2);
        const next = argv[i + 1];
        if (next !== undefined && !String(next).startsWith('--')) {
          flags[key] = next;
          i++;
        } else {
          flags[key] = true;
        }
      }
    } else {
      positionals.push(arg);
    }
  }
  return { command: positionals[0] || '', positionals: positionals.slice(1), flags };
}

function loadOperatorConfig(targets) {
  const cfgPath = targets.operatorPackage.configPaths[0];
  if (!cfgPath || !fs.existsSync(cfgPath)) {
    return {
      provider: 'emrank',
      endpointUrl: EMRANK_DEFAULT_ENDPOINT_URL,
      modelId: EMRANK_DEFAULT_MODEL_ID
    };
  }
  const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  return {
    provider: parsed.provider || 'emrank',
    endpointUrl: parsed.endpointUrl || EMRANK_DEFAULT_ENDPOINT_URL,
    modelId: parsed.modelId || EMRANK_DEFAULT_MODEL_ID
  };
}

function readProviderApiKey(keyFilePath, provider) {
  if (!fs.existsSync(keyFilePath)) {
    throw new Error(`[ERR_MISSING_API_KEY] Key file not found: ${keyFilePath}`);
  }
  const raw = fs.readFileSync(keyFilePath, 'utf8');
  const parsed = JSON.parse(raw);
  const key = parsed?.providers?.[provider]?.apiKey;
  if (typeof key !== 'string' || key.trim().length === 0) {
    throw new Error(`[ERR_MISSING_API_KEY] No apiKey configured for provider=${provider}`);
  }
  return key.trim();
}

export async function runOperatorCli(argv = process.argv.slice(2)) {
  assertNoForbiddenCliFlags(argv);
  const { command, flags } = parseCliArgs(argv);
  const operatorRoot = path.resolve(String(flags['operator-root'] || DEFAULT_OPERATOR_ROOT));
  const targets = buildOperatorIsolationTargets({ operatorRoot });
  const asJson = Boolean(flags.json);

  if (command === 'sentinel-check') {
    const elevated = isCurrentWindowsProcessElevated();
    if (elevated && !flags['allow-elevated']) {
      throw new Error(
        '[ERR_ELEVATED_SENTINEL_INVALID] sentinel-check must execute from a non-elevated ordinary host terminal (not elevated Admin). Pass --allow-elevated only to inspect Windows NTFS ACLs.'
      );
    }

    let report;
    if (elevated) {
      report = verifyElevatedWindowsOperatorAclIsolation({
        keyFilePath: targets.keyFilePath,
        operatorDbPath: targets.operatorDbPath,
        operatorPackage: targets.operatorPackage,
        approveScriptPath: targets.approveScriptPath
      });
    } else {
      const sentinel = runFourPointCloudIsolationSentinel({
        keyFilePath: targets.keyFilePath,
        operatorDbPath: targets.operatorDbPath,
        operatorPackage: targets.operatorPackage,
        selfIssueAttemptFn: () => {
          let untrustedRejected = false;
          try {
            issueCloudEgressApproval(
              { prepare: () => ({ get: () => null, run: () => ({ changes: 0 }) }), exec: () => {} },
              {
                purpose: 'embed_query',
                scopeRef: 'query-session:host-probe',
                corpusDigest: '0'.repeat(64),
                boundVaultId: 'v1',
                boundDataId: 'd1',
                queryEgressAllowed: 1,
                provider: 'emrank',
                endpointUrl: EMRANK_DEFAULT_ENDPOINT_URL,
                modelId: EMRANK_DEFAULT_MODEL_ID,
                maxCalls: 1,
                maxInputTokens: 100,
                maxOutputTokens: 0,
                maxCostMicroCny: 100,
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                trustedHumanContext: false
              }
            );
          } catch (err) {
            if (err?.code === 'ERR_CLOUD_APPROVAL_UNTRUSTED_CONTEXT') untrustedRejected = true;
          }

          let flagRejected = false;
          try {
            assertNoForbiddenCliFlags(['search', '--approve-cloud-egress']);
          } catch {
            flagRejected = true;
          }

          let ps1Refused = true;
          if (fs.existsSync(targets.approveScriptPath)) {
            ps1Refused = false;
            try {
              execFileSync(
                'pwsh',
                ['-NoProfile', '-NonInteractive', '-File', targets.approveScriptPath],
                { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
              );
            } catch {
              ps1Refused = true;
            }
          }

          let dbOpenBlocked = false;
          try {
            const fd = fs.openSync(targets.operatorDbPath, 'r+');
            fs.closeSync(fd);
          } catch (err) {
            if (err && (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EROFS')) {
              dbOpenBlocked = true;
            }
          }

          const blocked = untrustedRejected && flagRejected && ps1Refused && dbOpenBlocked;
          return {
            blocked,
            reason: blocked
              ? 'untrusted_context_cli_flag_ps1_non_interactive_and_db_blocked'
              : `incomplete_block(untrusted=${untrustedRejected},flag=${flagRejected},ps1=${ps1Refused},db=${dbOpenBlocked})`
          };
        }
      });
      report = {
        verificationMode: 'ordinary_host_os_probe',
        elevatedProcess: false,
        operatorRoot: targets.operatorRoot,
        ...sentinel
      };
    }

    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return { exitCode: report.allFourPassed ? 0 : 2, report };
  }

  if (command === 'init-operator-db') {
    const db = openOperatorDatabase(targets.operatorDbPath, { autoMigrate: true });
    try {
      const out = { initialized: true, operatorDbPath: targets.operatorDbPath };
      process.stdout.write(JSON.stringify(out, null, 2) + '\n');
      return { exitCode: 0, out };
    } finally {
      db.close();
    }
  }

  if (command === 'init-trial-workspace') {
    const workspaceDir = path.resolve(String(flags.workspace || targets.trialWorkspaceDir));
    const meta = initEmrankTrialWorkspace({ workspaceDir });
    if (asJson) {
      process.stdout.write(JSON.stringify(meta, null, 2) + '\n');
    } else {
      process.stdout.write(
        `[mem-operator init-trial-workspace] vault=${meta.vault_dir} vault_id=${meta.vault_id} data_id=${meta.data_id}\n`
      );
    }
    return { exitCode: 0, meta };
  }

  if (command === 'list-approvals') {
    const operatorDb = openOperatorDatabase(targets.operatorDbPath, { readOnly: true });
    try {
      const approvals = operatorDb
        .prepare(
          `SELECT cloud_approval_id, purpose, provider, model_id, endpoint_url, status,
                  max_calls, reserved_calls, used_calls, max_input_tokens, used_input_tokens,
                  max_cost_micro_cny, used_cost_micro_cny, query_egress_allowed, created_at, expires_at
           FROM cloud_egress_approvals
           ORDER BY created_at DESC`
        )
        .all();
      const out = { operatorDbPath: targets.operatorDbPath, count: approvals.length, approvals };
      process.stdout.write(JSON.stringify(out, null, 2) + '\n');
      return { exitCode: 0, out };
    } finally {
      operatorDb.close();
    }
  }

  if (command === 'trial-emrank') {
    if (!isCurrentWindowsProcessElevated()) {
      throw new Error(
        '[ERR_OPERATOR_ELEVATION_REQUIRED] trial-emrank must be run inside an elevated Administrator PowerShell terminal.'
      );
    }
    const embedDocApprovalId = String(flags['embed-doc-approval'] || '').trim();
    const embedQueryApprovalId = String(flags['embed-query-approval'] || '').trim();
    if (!embedDocApprovalId || !embedQueryApprovalId) {
      throw new Error(
        'Missing required flags: --embed-doc-approval <CEGR-...> --embed-query-approval <CEGR-...>'
      );
    }

    const aclReport = verifyElevatedWindowsOperatorAclIsolation({
      keyFilePath: targets.keyFilePath,
      operatorDbPath: targets.operatorDbPath,
      operatorPackage: targets.operatorPackage,
      approveScriptPath: targets.approveScriptPath
    });
    assertRealCloudApiGate(aclReport);

    const cfg = loadOperatorConfig(targets);
    const modelId = String(flags.model || cfg.modelId || EMRANK_DEFAULT_MODEL_ID).trim();
    const workspaceDir = path.resolve(String(flags.workspace || targets.trialWorkspaceDir));
    const deadlineMs = flags['deadline-ms'] !== undefined ? Number(flags['deadline-ms']) : 45_000;
    if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) {
      throw new Error(`Invalid --deadline-ms value: ${String(flags['deadline-ms'])}`);
    }
    const runProbes = flags['no-probes'] ? false : true;
    const apiKeyProvider = () => readProviderApiKey(targets.keyFilePath, cfg.provider);

    const operatorDb = openOperatorDatabase(targets.operatorDbPath, { autoMigrate: false });
    try {
      const report = await runEmrankControlledTrial({
        workspaceDir,
        operatorDb,
        embedDocApprovalId,
        embedQueryApprovalId,
        endpointUrl: cfg.endpointUrl,
        modelId,
        apiKeyProvider,
        sentinelReport: aclReport,
        testContext: false,
        overallDeadlineMs: deadlineMs,
        runProbes
      });
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      return { exitCode: 0, report };
    } finally {
      operatorDb.close();
    }
  }

  if (command === 'distill') {
    if (!isCurrentWindowsProcessElevated()) {
      throw new Error(
        '[ERR_OPERATOR_ELEVATION_REQUIRED] distill must be run inside an elevated Administrator PowerShell terminal.'
      );
    }
    const approvalId = String(flags.approval || '').trim();
    const sessionRef = String(flags.session || '').trim();
    if (!approvalId || !sessionRef) {
      throw new Error(
        'Missing required flags: --session <SES-id|path> --approval <CEGR-...> [--provider deepseek] [--model deepseek-chat]'
      );
    }

    const aclReport = verifyElevatedWindowsOperatorAclIsolation({
      keyFilePath: targets.keyFilePath,
      operatorDbPath: targets.operatorDbPath,
      operatorPackage: targets.operatorPackage,
      approveScriptPath: targets.approveScriptPath
    });
    assertRealCloudApiGate(aclReport);

    const effVaultPath = path.resolve(String(flags.vault || process.env.AGENT_MEMORY_VAULT || DEFAULT_VAULT_PATH));
    const effDataPath = path.resolve(String(flags.data || process.env.AGENT_MEMORY_DATA || DEFAULT_DATA_PATH));
    const effVaultDbPath = path.join(effDataPath, 'runtime', 'state.sqlite');
    if (!fs.existsSync(effVaultDbPath)) {
      throw new Error(`[ERR_VAULT_DB_MISSING] Vault state database not found: ${effVaultDbPath}`);
    }

    const provider = String(flags.provider || 'deepseek').trim();
    const modelId = String(flags.model || (provider === 'deepseek' ? 'deepseek-chat' : 'gpt-4o-mini')).trim();
    const deadlineMs = flags['deadline-ms'] !== undefined ? Number(flags['deadline-ms']) : 45_000;
    let parsedRange = null;
    if (flags.range) {
      const m = String(flags.range).trim().match(/^(\d+):(\d+)$/);
      if (!m) throw new Error(`Invalid --range format "${String(flags.range)}". Expected start:end`);
      parsedRange = { start: Number(m[1]), end: Number(m[2]) };
    }

    const instance = readInstanceIdentity({ vaultPath: effVaultPath, dataPath: effDataPath });
    const apiKeyProvider = () => readProviderApiKey(targets.keyFilePath, provider);
    const vaultDb = openExistingDatabase(effVaultDbPath, { autoMigrate: false });
    const operatorDb = openOperatorDatabase(targets.operatorDbPath, { autoMigrate: false });
    try {
      let resolvedSessionPath = null;
      const candPath = path.resolve(sessionRef);
      if (fs.existsSync(candPath)) {
        resolvedSessionPath = candPath;
      } else {
        const row = vaultDb
          .prepare("SELECT path FROM notes WHERE note_type = 'session' AND status = 'active' AND (id = ? OR title = ?)")
          .get(sessionRef, sessionRef);
        if (!row) {
          throw new Error(`[ERR_SESSION_NOT_FOUND] Active session not found: ${sessionRef}`);
        }
        resolvedSessionPath = row.path;
      }

      const result = await distillSessionWithLlmAsync({
        db: vaultDb,
        operatorDb,
        vaultDir: effVaultPath,
        dataDir: effDataPath,
        sessionPath: resolvedSessionPath,
        cloudApprovalId: approvalId,
        provider,
        modelId,
        vaultId: instance.vaultId,
        dataId: instance.dataId,
        apiKeyProvider,
        range: parsedRange,
        knowledgeSubdir: String(flags.subdir || 'Playbooks'),
        publishAcceptedFacts: Boolean(flags['publish-accepted']),
        overallDeadlineMs: deadlineMs,
        sentinelReport: aclReport,
        testContext: false
      });
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      return { exitCode: 0, result };
    } finally {
      operatorDb.close();
      vaultDb.close();
    }
  }

  throw new Error(
    `Unknown mem-operator command "${command}". Supported: sentinel-check | init-operator-db | init-trial-workspace | list-approvals | trial-emrank | distill`
  );
}

const isEntrypoint =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isEntrypoint) {
  runOperatorCli(process.argv.slice(2))
    .then((res) => {
      process.exitCode = res?.exitCode ?? 0;
    })
    .catch((err) => {
      process.stderr.write(`${sanitizeOutputText(err?.message || String(err))}\n`);
      process.exitCode = 1;
    });
}
