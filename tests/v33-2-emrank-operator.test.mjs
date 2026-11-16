import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  DEFAULT_PRICING_CATALOG,
  openOperatorDatabase,
  issueCloudEgressApproval,
  migrateCloudEgressSchema
} from '../src/security/cloud-approvals.mjs';
import { getAdapterForPurpose } from '../src/providers/adapters/index.mjs';
import { emrankAdapter } from '../src/providers/adapters/emrank.mjs';
import {
  buildOperatorIsolationTargets,
  verifyElevatedWindowsOperatorAclIsolation,
  runFourPointCloudIsolationSentinel,
  isCurrentWindowsProcessElevated
} from '../src/security/isolation-sentinel.mjs';
import {
  EMRANK_DEFAULT_MODEL_ID,
  EMRANK_TRIAL_QUESTIONS,
  LOCAL_ONLY_CANARY,
  UNREGISTERED_CANARY,
  initEmrankTrialWorkspace,
  runEmrankControlledTrial
} from '../src/benchmark/emrank-trial.mjs';
import { buildDeployPlan } from '../cli/deploy.mjs';

function makeTempDir(prefix) {
  const dir = path.resolve('.tmp', `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function deterministicTopicVector(text) {
  const s = String(text || '');
  const topics = [
    /(PgBouncer|PostgreSQL|关系型库|连接池|连接数|socket)/i,
    /(openSync|NTFS|accessSync|只读保护|微软系统|写入限制)/i,
    /(-wal|-shm|WAL|SQLite|预写日志|嵌入式数据库|临时文件)/i,
    /(Zstd|多帧|Skippable|0x184D2A50)/i,
    /(redirect|302|Authorization|Bearer|跨域名|跳转|凭据)/i,
    /(CreateHardLinkW|硬链接|R1|staging)/i
  ];
  const vec = topics.map((re) => (re.test(s) ? 1.0 : 0.0));
  vec.push(0.05);
  return vec;
}

test('V3.3-2 EMRank & Operator Isolation Suite', async (t) => {
  await t.test('1. emrankAdapter & DEFAULT_PRICING_CATALOG contract checks', () => {
    const adapter = getAdapterForPurpose({ provider: 'emrank', purpose: 'embed_doc' });
    assert.equal(adapter, emrankAdapter);
    assert.deepEqual(adapter.getAcceptedEndpointPaths('embed_query'), ['/v1/embeddings', '/embeddings']);
    assert.throws(() => getAdapterForPurpose({ provider: 'emrank', purpose: 'rerank' }), /ERR_UNSUPPORTED_PURPOSE/);

    const req = adapter.buildRequest({
      purpose: 'embed_query',
      model: 'Qwen/Qwen3-Embedding-8B',
      inputs: ['hello emrank']
    });
    assert.equal(req.path, '/v1/embeddings');
    assert.equal(req.body.encoding_format, 'float');

    assert.throws(
      () =>
        adapter.buildRequest({
          purpose: 'embed_doc',
          model: 'Qwen/Qwen3-Embedding-8B',
          inputs: Array.from({ length: 33 }, (_, i) => `chunk-${i}`)
        }),
      /ERR_EMBED_BATCH_LIMIT_EXCEEDED/
    );

    assert.equal(EMRANK_DEFAULT_MODEL_ID, 'Qwen/Qwen3-Embedding-0.6B');
    const priceSpec8b = DEFAULT_PRICING_CATALOG.emrank['Qwen/Qwen3-Embedding-8B'];
    assert.equal(priceSpec8b.inputMicroCnyPerMillionTokens, 140_000);
    assert.equal(priceSpec8b.outputMicroCnyPerMillionTokens, 0);
    const priceSpec06b = DEFAULT_PRICING_CATALOG.emrank['Qwen/Qwen3-Embedding-0.6B'];
    assert.equal(priceSpec06b.inputMicroCnyPerMillionTokens, 140_000);
    assert.equal(priceSpec06b.outputMicroCnyPerMillionTokens, 0);
  });

  await t.test('2. PowerShell AST validation, non-interactive guard, and deploy exclusion', () => {
    const setupPs1 = path.resolve('scripts/setup-operator-isolation.ps1');
    const approvePs1 = path.resolve('scripts/approve-human.ps1');
    assert.equal(fs.existsSync(setupPs1), true);
    assert.equal(fs.existsSync(approvePs1), true);

    const astCheckCmd = `
$errors = $null
$tokens = $null
foreach ($p in @('${setupPs1.replace(/'/g, "''")}', '${approvePs1.replace(/'/g, "''")}')) {
  [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors)
  if ($errors -and $errors.Count -gt 0) {
    throw ($errors | Out-String)
  }
}
Write-Output 'AST_OK'
`.trim();
    const astOut = execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', astCheckCmd], {
      encoding: 'utf8'
    });
    assert.match(astOut, /AST_OK/);

    let failedNonInteractive = false;
    try {
      execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', approvePs1], {
        encoding: 'utf8',
        env: { ...process.env, ANTIGRAVITY_AGENT: '1' },
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (err) {
      failedNonInteractive = err.status !== 0;
    }
    assert.equal(failedNonInteractive, true, 'approve-human.ps1 must fail non-interactively');

    // Verify issue-approval-internal.mjs resolves all ESM imports cleanly and enforces ERR_UNTRUSTED_APPROVAL_INVOCATION
    const issueHelper = path.resolve('scripts/issue-approval-internal.mjs');
    let helperStderr = '';
    try {
      execFileSync(process.execPath, [issueHelper], {
        encoding: 'utf8',
        env: { ...process.env, OAM_APPROVE_HUMAN_TTY: '' },
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (err) {
      helperStderr = String(err.stderr || err.message || '');
    }
    assert.match(helperStderr, /ERR_UNTRUSTED_APPROVAL_INVOCATION/);
    assert.doesNotMatch(helperStderr, /ERR_MODULE_NOT_FOUND/);

    // Ordinary host deploy.mjs MUST NOT include privileged scripts/*
    const plan = buildDeployPlan();
    const deployedPaths = plan.actions.map((a) => a.destRel);
    assert.equal(deployedPaths.some((p) => p.startsWith('scripts/')), false);
  });

  await t.test('3. Windows NTFS ACL inspector enforces strict 4-point boundaries', () => {
    const tmpRoot = makeTempDir('v33-2-acl');
    t.after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

    const targets = buildOperatorIsolationTargets({ operatorRoot: tmpRoot });
    const allFiles = [
      targets.keyFilePath,
      targets.operatorDbPath,
      targets.operatorPackage.entrypointPath,
      ...targets.operatorPackage.modulePaths,
      ...targets.operatorPackage.configPaths
    ];
    for (const f of allFiles) {
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, 'placeholder', 'utf8');
    }

    const strictPrivateAcl = () => ({
      exists: true,
      ownerSid: 'S-1-5-32-544',
      areAccessRulesProtected: true,
      access: [
        { sid: 'S-1-5-18', accessControlType: 'Allow', rightsMask: 0x1f01ff, rightsText: 'FullControl' },
        { sid: 'S-1-5-32-544', accessControlType: 'Allow', rightsMask: 0x1f01ff, rightsText: 'FullControl' }
      ]
    });
    const strictReadOnlyPackageAcl = () => ({
      exists: true,
      ownerSid: 'S-1-5-32-544',
      areAccessRulesProtected: true,
      access: [
        { sid: 'S-1-5-18', accessControlType: 'Allow', rightsMask: 0x1f01ff, rightsText: 'FullControl' },
        { sid: 'S-1-5-32-544', accessControlType: 'Allow', rightsMask: 0x1f01ff, rightsText: 'FullControl' },
        { sid: 'S-1-5-32-545', accessControlType: 'Allow', rightsMask: 0x1200a9, rightsText: 'ReadAndExecute' }
      ]
    });

    const passReport = verifyElevatedWindowsOperatorAclIsolation({
      keyFilePath: targets.keyFilePath,
      operatorDbPath: targets.operatorDbPath,
      operatorPackage: targets.operatorPackage,
      aclInspectorFn: (p) => {
        if (p === targets.keyFilePath || p === targets.operatorDbPath) {
          return strictPrivateAcl();
        }
        return strictReadOnlyPackageAcl();
      }
    });
    assert.equal(passReport.allFourPassed, true);

    // Runtime-created SQLite -wal/-shm inherit Admin+SYSTEM ACL from protected operator-state/
    const walPath = `${targets.operatorDbPath}-wal`;
    const shmPath = `${targets.operatorDbPath}-shm`;
    fs.writeFileSync(walPath, 'wal', 'utf8');
    fs.writeFileSync(shmPath, 'shm', 'utf8');
    const inheritedSidecarAcl = () => ({
      exists: true,
      ownerSid: 'S-1-5-32-544',
      areAccessRulesProtected: false,
      access: strictPrivateAcl().access
    });
    const sidecarPassReport = verifyElevatedWindowsOperatorAclIsolation({
      keyFilePath: targets.keyFilePath,
      operatorDbPath: targets.operatorDbPath,
      operatorPackage: targets.operatorPackage,
      aclInspectorFn: (p) => {
        if (p === targets.keyFilePath || p === targets.operatorDbPath || p === path.dirname(targets.operatorDbPath)) {
          return strictPrivateAcl();
        }
        if (p === walPath || p === shmPath) {
          return inheritedSidecarAcl();
        }
        return strictReadOnlyPackageAcl();
      }
    });
    assert.equal(sidecarPassReport.allFourPassed, true);

    const unprotectedParentSidecarReport = verifyElevatedWindowsOperatorAclIsolation({
      keyFilePath: targets.keyFilePath,
      operatorDbPath: targets.operatorDbPath,
      operatorPackage: targets.operatorPackage,
      aclInspectorFn: (p) => {
        if (p === targets.keyFilePath || p === targets.operatorDbPath) {
          return strictPrivateAcl();
        }
        if (p === path.dirname(targets.operatorDbPath) || p === walPath || p === shmPath) {
          return inheritedSidecarAcl();
        }
        return strictReadOnlyPackageAcl();
      }
    });
    assert.equal(unprotectedParentSidecarReport.allFourPassed, false);
    assert.ok(unprotectedParentSidecarReport.failedSentinels.includes('operator_db_unwritable'));
    fs.rmSync(walPath, { force: true });
    fs.rmSync(shmPath, { force: true });

    // Reject if Users has Write access on operator-cli or Read access on keys
    const leakyReport = verifyElevatedWindowsOperatorAclIsolation({
      keyFilePath: targets.keyFilePath,
      operatorDbPath: targets.operatorDbPath,
      operatorPackage: targets.operatorPackage,
      aclInspectorFn: (p) => {
        if (p === targets.keyFilePath) {
          return strictReadOnlyPackageAcl(); // Users shouldn't even read keys!
        }
        if (p === targets.operatorPackage.entrypointPath) {
          return {
            exists: true,
            ownerSid: 'S-1-5-32-544',
            areAccessRulesProtected: true,
            access: [
              { sid: 'S-1-5-32-545', accessControlType: 'Allow', rightsMask: 0x1301bf, rightsText: 'Modify' }
            ]
          };
        }
        return strictPrivateAcl();
      }
    });
    assert.equal(leakyReport.allFourPassed, false);
    assert.ok(leakyReport.failedSentinels.includes('key_file_unreadable'));
    assert.ok(leakyReport.failedSentinels.includes('operator_package_unwritable'));

    // mem-operator.mjs production guard rejects --approve-cloud-egress and fails sentinel-check when targets unlocked
    let cliFlagFailed = false;
    try {
      execFileSync(
        process.execPath,
        [path.resolve('cli/mem-operator.mjs'), 'sentinel-check', '--approve-cloud-egress'],
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
    } catch {
      cliFlagFailed = true;
    }
    assert.equal(cliFlagFailed, true);

    let unlockedSentinelFailed = false;
    const sentinelArgs = [path.resolve('cli/mem-operator.mjs'), 'sentinel-check', '--operator-root', tmpRoot, '--json'];
    if (isCurrentWindowsProcessElevated()) {
      sentinelArgs.push('--allow-elevated');
    }
    try {
      execFileSync(
        process.execPath,
        sentinelArgs,
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
    } catch (err) {
      unlockedSentinelFailed = err.status === 2;
    }
    assert.equal(unlockedSentinelFailed, true, 'Unlocked directory must fail 4-point sentinel-check with exit code 2');

    // Regression: when parent dir ACL denies traversal on Windows, fs.existsSync() returns false
    // even though the file exists and fs.openSync() throws EPERM. Default probes MUST report os_denied_EPERM.
    const existsMock = t.mock.method(fs, 'existsSync', () => false);
    const openMock = t.mock.method(fs, 'openSync', (targetPath) => {
      if (String(targetPath).endsWith('-wal') || String(targetPath).endsWith('-shm')) {
        const enoent = new Error(`ENOENT: ${targetPath}`);
        enoent.code = 'ENOENT';
        throw enoent;
      }
      const eperm = new Error(`EPERM: ${targetPath}`);
      eperm.code = 'EPERM';
      throw eperm;
    });
    try {
      const mockedEpermReport = runFourPointCloudIsolationSentinel({
        keyFilePath: targets.keyFilePath,
        operatorDbPath: targets.operatorDbPath,
        operatorPackage: targets.operatorPackage,
        selfIssueAttemptFn: () => ({ blocked: true, reason: 'mock_self_issue_blocked' })
      });
      assert.equal(mockedEpermReport.allFourPassed, true);
      assert.equal(mockedEpermReport.sentinels.key_file_unreadable.reason, 'os_denied_EPERM');
      assert.equal(mockedEpermReport.sentinels.operator_db_unwritable.reason, 'os_denied_EPERM');
      assert.equal(mockedEpermReport.sentinels.operator_db_unwritable.walChecked, false);
    } finally {
      openMock.mock.restore();
      existsMock.mock.restore();
    }
  });

  await t.test('4. Isolated EMRank trial harness against 127.0.0.1 OpenAI-compatible mock', async () => {
    const tmpDir = makeTempDir('v33-2-emrank-trial');
    const serverSockets = new Set();
    let capturedInputs = [];

    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        if (req.url === '/v1/embeddings' && req.method === 'POST') {
          const parsed = JSON.parse(body);
          capturedInputs.push(...parsed.input);
          const data = parsed.input.map((text, index) => ({
            object: 'embedding',
            index,
            embedding: deterministicTopicVector(text)
          }));
          const promptTokens = parsed.input.reduce(
            (sum, text) => sum + Math.max(4, Math.ceil(Buffer.byteLength(String(text), 'utf8') / 2)),
            0
          );
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              object: 'list',
              data,
              model: parsed.model,
              usage: { prompt_tokens: promptTokens, total_tokens: promptTokens }
            })
          );
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });
    server.on('connection', (sock) => {
      serverSockets.add(sock);
      sock.on('close', () => serverSockets.delete(sock));
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const mockEndpoint = `http://127.0.0.1:${port}/v1/embeddings`;

    t.after(async () => {
      for (const s of serverSockets) s.destroy();
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    const workspaceDir = path.join(tmpDir, 'trial-workspace');
    const meta = initEmrankTrialWorkspace({ workspaceDir });
    const operatorDbPath = path.join(tmpDir, 'operator-state.sqlite');
    const operatorDb = openOperatorDatabase(operatorDbPath, { autoMigrate: true });
    migrateCloudEgressSchema(operatorDb);

    try {
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      const docApp = issueCloudEgressApproval(operatorDb, {
        purpose: 'embed_doc',
        scopeRef: meta.scope_ref,
        corpusDigest: meta.corpus_digest,
        boundVaultId: meta.vault_id,
        boundDataId: meta.data_id,
        queryEgressAllowed: 0,
        provider: 'emrank',
        endpointUrl: mockEndpoint,
        modelId: 'Qwen/Qwen3-Embedding-8B',
        issuerChannel: 'test_harness',
        maxCalls: 4,
        maxInputTokens: 6000,
        maxOutputTokens: 0,
        maxCostMicroCny: 20_000,
        expiresAt,
        trustedHumanContext: true
      });
      const queryApp = issueCloudEgressApproval(operatorDb, {
        purpose: 'embed_query',
        scopeRef: meta.scope_ref,
        corpusDigest: meta.corpus_digest,
        boundVaultId: meta.vault_id,
        boundDataId: meta.data_id,
        queryEgressAllowed: 1,
        provider: 'emrank',
        endpointUrl: mockEndpoint,
        modelId: 'Qwen/Qwen3-Embedding-8B',
        issuerChannel: 'test_harness',
        maxCalls: 16,
        maxInputTokens: 14000,
        maxOutputTokens: 0,
        maxCostMicroCny: 80_000,
        expiresAt,
        trustedHumanContext: true
      });

      const syntheticSentinel = runFourPointCloudIsolationSentinel({
        keyFilePath: 'locked-key',
        operatorDbPath: 'locked-db',
        operatorPackage: { entrypointPath: 'a', modulePaths: ['b'], configPaths: ['c'] },
        probeReadFn: () => ({ blocked: true, reason: 'mock_denied', code: 'EACCES' }),
        probeWriteFn: () => ({ blocked: true, reason: 'mock_denied', code: 'EACCES' }),
        selfIssueAttemptFn: () => ({ blocked: true, reason: 'mock_denied' })
      });

      const report = await runEmrankControlledTrial({
        workspaceDir,
        operatorDb,
        embedDocApprovalId: docApp.cloud_approval_id,
        embedQueryApprovalId: queryApp.cloud_approval_id,
        endpointUrl: mockEndpoint,
        modelId: 'Qwen/Qwen3-Embedding-8B',
        apiKeyProvider: () => 'test-emrank-key',
        sentinelReport: syntheticSentinel,
        testContext: true,
        overallDeadlineMs: 5000,
        runProbes: true
      });

      assert.equal(report.dailyDefaultModeMaintained, 'literal');
      assert.equal(report.liveVaultMutated, false);
      assert.equal(report.privacyAudit.trapVectorCount, 0);
      assert.equal(report.privacyAudit.localOnlyCanaryLeaked, false);
      assert.equal(report.privacyAudit.unregisteredCanaryLeaked, false);
      assert.equal(report.privacyAudit.noteUuidLeaked, false);

      assert.equal(report.comparison.mode0.total, EMRANK_TRIAL_QUESTIONS.length);
      assert.ok(
        report.comparison.mode1Hybrid.hitAt5 > report.comparison.mode0.hitAt5,
        'EMRank hybrid must recover semantic paraphrase queries missed by Mode 0'
      );
      assert.equal(report.comparison.mode1Hybrid.hitAt5, 1);
      assert.ok(report.comparison.literalMissSemanticRecovered >= 4);

      assert.equal(report.probes.endpointMismatchProbe.errorCode, 'ERR_ENDPOINT_MISMATCH');
      assert.equal(report.probes.endpointMismatchProbe.blocked, true);
      assert.equal(report.probes.endpointMismatchProbe.outboundNetworkCallsTriggered, 0);

      assert.equal(report.probes.budgetExhaustionProbe.blocked, true);
      assert.equal(report.probes.budgetExhaustionProbe.errorCode, 'ERR_CLOUD_BUDGET_EXCEEDED');
      assert.equal(report.probes.budgetExhaustionProbe.outboundNetworkCallsTriggered, 0);

      assert.ok(report.billing.totalCallsSettled >= 6);
      assert.equal(fs.existsSync(report.reportPath), true);
      assert.equal(fs.existsSync(report.modelReportPath), true);
      assert.ok(report.timingSummary && report.timingSummary.avgMode1QueryMs >= 0);
      assert.equal(capturedInputs.some((t) => t.includes(LOCAL_ONLY_CANARY) || t.includes(UNREGISTERED_CANARY)), false);

      // Sequential 0.6B A/B trial in the same isolated workspace preserves 8B archive and compares results
      const docApp06b = issueCloudEgressApproval(operatorDb, {
        purpose: 'embed_doc',
        scopeRef: meta.scope_ref,
        corpusDigest: meta.corpus_digest,
        boundVaultId: meta.vault_id,
        boundDataId: meta.data_id,
        queryEgressAllowed: 0,
        provider: 'emrank',
        endpointUrl: mockEndpoint,
        modelId: 'Qwen/Qwen3-Embedding-0.6B',
        issuerChannel: 'test_harness',
        maxCalls: 4,
        maxInputTokens: 6000,
        maxOutputTokens: 0,
        maxCostMicroCny: 20_000,
        expiresAt,
        trustedHumanContext: true
      });
      const queryApp06b = issueCloudEgressApproval(operatorDb, {
        purpose: 'embed_query',
        scopeRef: meta.scope_ref,
        corpusDigest: meta.corpus_digest,
        boundVaultId: meta.vault_id,
        boundDataId: meta.data_id,
        queryEgressAllowed: 1,
        provider: 'emrank',
        endpointUrl: mockEndpoint,
        modelId: 'Qwen/Qwen3-Embedding-0.6B',
        issuerChannel: 'test_harness',
        maxCalls: 16,
        maxInputTokens: 14000,
        maxOutputTokens: 0,
        maxCostMicroCny: 80_000,
        expiresAt,
        trustedHumanContext: true
      });
      const report06b = await runEmrankControlledTrial({
        workspaceDir,
        operatorDb,
        embedDocApprovalId: docApp06b.cloud_approval_id,
        embedQueryApprovalId: queryApp06b.cloud_approval_id,
        endpointUrl: mockEndpoint,
        modelId: 'Qwen/Qwen3-Embedding-0.6B',
        apiKeyProvider: () => 'test-emrank-key',
        sentinelReport: syntheticSentinel,
        testContext: true,
        overallDeadlineMs: 5000,
        runProbes: true
      });
      assert.equal(report06b.modelId, 'Qwen/Qwen3-Embedding-0.6B');
      assert.equal(report06b.comparison.mode1Hybrid.hitAt5, 1);
      assert.equal(fs.existsSync(report06b.modelReportPath), true);
      assert.equal(fs.existsSync(report.modelReportPath), true, '8B baseline archive must be preserved');
      assert.equal(report06b.abComparisonVsBaseline?.baselineModelId, 'Qwen/Qwen3-Embedding-8B');
      assert.equal(report06b.abComparisonVsBaseline?.currentModelId, 'Qwen/Qwen3-Embedding-0.6B');
      assert.equal(typeof report06b.timingSummary?.avgEmbedQueryGatewayMs, 'number');
    } finally {
      operatorDb.close();
    }
  });
});
