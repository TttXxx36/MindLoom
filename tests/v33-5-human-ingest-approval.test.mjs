import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import {
  issueTrustedLowSensitivityApproval,
  verifyLowSensitivityIngestApproval
} from '../src/security/trusted-approvals.mjs';
import { resolveProjectFromMap } from '../src/ingest/session-ingestor.mjs';
import { sanitizeOutputText } from '../src/security/sanitizer.mjs';
import { buildDeployPlan } from '../cli/deploy.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');
const APPROVE_PS1_PATH = path.resolve('scripts/approve-ingest-human.ps1');
const ISSUE_HELPER_PATH = path.resolve('scripts/issue-ingest-approval-internal.mjs');

test('V3.3-5 Human Interactive Local-Ingest Gate & Project Map Non-Collision', async (t) => {
  await t.test('1. approve-ingest-human.ps1 passes PowerShell AST parse and rejects non-interactive/agent execution', () => {
    assert.equal(fs.existsSync(APPROVE_PS1_PATH), true);
    assert.equal(fs.existsSync(ISSUE_HELPER_PATH), true);

    const astCmd = `
$errors = $null
$tokens = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('${APPROVE_PS1_PATH.replace(/'/g, "''")}', [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
  throw ($errors | Out-String)
}
Write-Output 'AST_OK'
`.trim();
    const astOut = execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', astCmd], {
      encoding: 'utf8'
    });
    assert.match(astOut, /AST_OK/);

    const psRes = spawnSync(
      'pwsh',
      ['-NoProfile', '-NonInteractive', '-File', APPROVE_PS1_PATH, '-SourceTool', 'codex', '-SessionId', 's-test'],
      {
        encoding: 'utf8',
        env: { ...process.env, ANTIGRAVITY_AGENT: '1' }
      }
    );
    assert.equal(psRes.status, 43, `Expected EXIT 43, got ${psRes.status}: ${psRes.stderr || psRes.stdout}`);
    assert.match(`${psRes.stderr || ''}\n${psRes.stdout || ''}`, /ACCESS_DENIED \(EXIT 43\)/);

    const noTtyRes = spawnSync(process.execPath, [ISSUE_HELPER_PATH], {
      encoding: 'utf8',
      env: { ...process.env, OAM_APPROVE_INGEST_HUMAN_TTY: '' }
    });
    assert.notEqual(noTtyRes.status, 0);
    assert.match(`${noTtyRes.stderr || ''}\n${noTtyRes.stdout || ''}`, /ERR_UNTRUSTED_INGEST_APPROVAL_INVOCATION/);
    assert.doesNotMatch(`${noTtyRes.stderr || ''}`, /ERR_MODULE_NOT_FOUND/);

    const agentEnvRes = spawnSync(process.execPath, [ISSUE_HELPER_PATH, '--source-tool', 'codex', '--session', 's1'], {
      encoding: 'utf8',
      env: { ...process.env, OAM_APPROVE_INGEST_HUMAN_TTY: '1', ANTIGRAVITY_AGENT: '1' }
    });
    assert.notEqual(agentEnvRes.status, 0);
    assert.match(`${agentEnvRes.stderr || ''}\n${agentEnvRes.stdout || ''}`, /ERR_UNTRUSTED_INGEST_AGENT_ENV/);

    const codexEnvRes = spawnSync(process.execPath, [ISSUE_HELPER_PATH, '--source-tool', 'codex', '--session', 's1'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        ANTIGRAVITY_AGENT: '',
        OAM_APPROVE_INGEST_HUMAN_TTY: '1',
        CODEX_SANDBOX: 'seatbelt'
      }
    });
    assert.notEqual(codexEnvRes.status, 0);
    assert.match(`${codexEnvRes.stderr || ''}\n${codexEnvRes.stdout || ''}`, /ERR_UNTRUSTED_INGEST_AGENT_ENV/);
  });

  await t.test('2. verifyLowSensitivityIngestApproval and E2E mem ingest --sensitivity approved_low_sensitivity', () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-v33-5-ingest-'));
    const vaultDir = path.join(tmpBase, 'Vault');
    const dataDir = path.join(tmpBase, 'Data');
    const srcDir = path.join(tmpBase, 'Sources');
    fs.mkdirSync(srcDir, { recursive: true });
    t.after(() => fs.rmSync(tmpBase, { recursive: true, force: true }));

    const env = { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir };
    execFileSync(process.execPath, [CLI_PATH, 'init', '--vault', vaultDir, '--data', dataDir], {
      env,
      encoding: 'utf8'
    });

    const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
    const rawSrc = path.join(srcDir, 'sess-alpha-01.jsonl');
    const dynSecret = ['sk', 'live', 'TestIngestGateToken123456'].join('-');
    fs.writeFileSync(
      rawSrc,
      [
        JSON.stringify({ type: 'user', content: `排查 V3.3 审批链路 token=${dynSecret}` }),
        JSON.stringify({ type: 'assistant', content: '使用 approve-ingest-human.ps1 签发 local_ingest 审批' })
      ].join('\n') + '\n',
      'utf8'
    );

    const noApprovalRes = spawnSync(
      process.execPath,
      [
        CLI_PATH,
        'ingest',
        '--source', 'codex',
        '--session', 'sess-alpha-01',
        '--source-file', rawSrc,
        '--project', 'ObsidianAgentMemory',
        '--sensitivity', 'approved_low_sensitivity'
      ],
      { env, encoding: 'utf8' }
    );
    assert.notEqual(noApprovalRes.status, 0);
    assert.match(
      `${noApprovalRes.stderr || ''}\n${noApprovalRes.stdout || ''}`,
      /INGEST_LOW_SENSITIVITY_APPROVAL_REQUIRED/
    );

    let issuedId = '';
    const db = openExistingDatabase(dbPath);
    try {
      assert.throws(() =>
        issueTrustedLowSensitivityApproval({
          db,
          sourceTool: 'codex',
          sessionId: 'sess-alpha-01',
          approvedBy: 'fake',
          trustedHumanContext: false
        })
      );

      assert.equal(
        verifyLowSensitivityIngestApproval({
          db,
          approvalId: 'AP-FORGED-0001',
          sourceTool: 'codex',
          sessionId: 'sess-alpha-01'
        }).valid,
        false
      );

      const issued = issueTrustedLowSensitivityApproval({
        db,
        sourceTool: 'codex',
        sessionId: 'sess-alpha-01',
        approvedBy: 'test-human',
        ttlHours: 24,
        trustedHumanContext: true
      });
      issuedId = issued.ingestApprovalId;
      assert.ok(issuedId);

      assert.equal(
        verifyLowSensitivityIngestApproval({
          db,
          approvalId: issuedId,
          sourceTool: 'antigravity',
          sessionId: 'sess-alpha-01'
        }).valid,
        false
      );
      assert.equal(
        verifyLowSensitivityIngestApproval({
          db,
          approvalId: issuedId,
          sourceTool: 'codex',
          sessionId: 'sess-other-99'
        }).valid,
        false
      );
      assert.equal(
        verifyLowSensitivityIngestApproval({
          db,
          approvalId: issuedId,
          sourceTool: 'codex',
          sessionId: 'sess-alpha-01'
        }).valid,
        true
      );

      const wildcard = issueTrustedLowSensitivityApproval({
        db,
        sourceTool: 'antigravity',
        sessionId: '*',
        approvedBy: 'test-human',
        ttlHours: 24,
        trustedHumanContext: true
      });
      assert.equal(
        verifyLowSensitivityIngestApproval({
          db,
          approvalId: wildcard.ingestApprovalId,
          sourceTool: 'antigravity',
          sessionId: 'any-ag-session-123'
        }).valid,
        true
      );
      assert.equal(
        verifyLowSensitivityIngestApproval({
          db,
          approvalId: wildcard.ingestApprovalId,
          sourceTool: 'codex',
          sessionId: 'any-ag-session-123'
        }).valid,
        false
      );
    } finally {
      db.close();
    }

    const ingestOut = execFileSync(
      process.execPath,
      [
        CLI_PATH,
        'ingest',
        '--source', 'codex',
        '--session', 'sess-alpha-01',
        '--source-file', rawSrc,
        '--project', 'ObsidianAgentMemory',
        '--title', '审批网关验证会话',
        '--sensitivity', 'approved_low_sensitivity',
        '--approval', issuedId
      ],
      { env, encoding: 'utf8' }
    );
    const ingestJson = JSON.parse(ingestOut);
    assert.equal(ingestJson.status, 'ingested');
    assert.equal(ingestJson.project, 'ObsidianAgentMemory');
    assert.ok(fs.existsSync(ingestJson.readableSessionPath));
  });

  await t.test('3. deploy.mjs continues excluding scripts/* and project-map paths stay non-overlapping', () => {
    const plan = buildDeployPlan();
    const deployedPaths = plan.actions.map((a) => a.destRel);
    assert.equal(deployedPaths.some((p) => p.startsWith('scripts/')), false);

    const tmpData = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-v33-5-pmap-'));
    t.after(() => fs.rmSync(tmpData, { recursive: true, force: true }));
    fs.mkdirSync(path.join(tmpData, 'manifests'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpData, 'manifests', 'project-map.json'),
      JSON.stringify(
        {
          schema_version: 1,
          default_unmapped_project: 'unmapped',
          projects: [
            {
              project: 'AlphaService',
              paths: ['C:\\Work\\projects\\alpha-service'],
              git_roots: ['C:\\Work\\projects\\alpha-service'],
              workspace_slugs: ['alpha-service']
            },
            {
              project: 'BetaApp',
              paths: ['C:\\Work\\sandboxes\\beta-app'],
              git_roots: [],
              workspace_slugs: ['beta-app']
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );

    assert.equal(
      resolveProjectFromMap({
        dataDir: tmpData,
        explicitProject: 'auto',
        sessionHints: { cwd: 'C:\\Work\\projects\\alpha-service' }
      }),
      'AlphaService'
    );
    assert.equal(
      resolveProjectFromMap({
        dataDir: tmpData,
        explicitProject: 'auto',
        sessionHints: { cwd: 'C:\\Work\\sandboxes\\beta-app' }
      }),
      'BetaApp'
    );
    assert.equal(
      resolveProjectFromMap({
        dataDir: tmpData,
        explicitProject: 'auto',
        sessionHints: { cwd: 'C:\\Work\\sandboxes' }
      }),
      'unmapped'
    );
    assert.equal(
      resolveProjectFromMap({
        dataDir: tmpData,
        explicitProject: 'BetaApp',
        sessionHints: { cwd: 'C:\\Work\\sandboxes' }
      }),
      'BetaApp'
    );
  });

  await t.test('4. sanitizeOutputText avoids O(N^2) backtracking on large unbroken lines and scripts strip surrounding quotes', () => {
    const hugeContiguous = 'A'.repeat(120_000) + '_raw_marker_' + 'B'.repeat(20_000);
    const t0 = performance.now();
    const clean = sanitizeOutputText(hugeContiguous, { scrubRawPaths: true });
    const elapsedMs = performance.now() - t0;
    assert.ok(elapsedMs < 250, `Expected linear sanitize < 250ms, got ${elapsedMs.toFixed(1)}ms`);
    assert.equal(clean.length, hugeContiguous.length);

    const leaked = 'failed reading C:\\Obsidian\\MindLoom-Data\\raw\\codex\\secret.jsonl and ../raw/a.jsonl';
    const scrubbed = sanitizeOutputText(leaked, { scrubRawPaths: true });
    assert.equal(scrubbed.includes('MindLoom-Data\\raw'), false);
    assert.equal(scrubbed.includes('../raw/a.jsonl'), false);
    assert.ok(scrubbed.includes('[REDACTED_RAW_PATH]'));

    const ps1Text = fs.readFileSync(APPROVE_PS1_PATH, 'utf8');
    const mjsText = fs.readFileSync(ISSUE_HELPER_PATH, 'utf8');
    assert.match(ps1Text, /\.Trim\(\[char\]'"',\s*\[char\]"'"\)/);
    assert.ok(mjsText.includes("replace(/^[\"']+|[\"']+$/g, '')"));
  });
});
