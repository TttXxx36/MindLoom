import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { initRepository } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import {
  extractHumanDigestTurnsFromMarkdown,
  refreshSessionHumanDigestHeader,
  rebuildVaultMocAndHome
} from '../src/ingest/human-digest.mjs';
import { runWhitelistAutoSync } from '../src/ingest/auto-sync.mjs';
import {
  parseRenderedSessionEvents,
  previewDistillSession
} from '../src/distill/llm-distiller.mjs';
import { issueTrustedLowSensitivityApproval } from '../src/security/trusted-approvals.mjs';
import { validateEngineeringCommitPaths } from '../src/git/repo-manager.mjs';
import { isCurrentWindowsProcessElevated } from '../src/security/isolation-sentinel.mjs';

const MEM_CLI_PATH = path.resolve('cli/mem.mjs');
const OPERATOR_CLI_PATH = path.resolve('cli/mem-operator.mjs');
const AUTO_SYNC_PS1_PATH = path.resolve('scripts/auto-sync-memory.ps1');
const REGISTER_TASK_PS1_PATH = path.resolve('scripts/register-auto-sync-task.ps1');

function initLocalVaultGit(vaultDir) {
  execFileSync('git', ['init'], { cwd: vaultDir, stdio: ['pipe', 'pipe', 'pipe'] });
  execFileSync('git', ['config', 'user.name', 'Test User'], { cwd: vaultDir, stdio: ['pipe', 'pipe', 'pipe'] });
  execFileSync('git', ['config', 'user.email', 'test@local.invalid'], { cwd: vaultDir, stdio: ['pipe', 'pipe', 'pipe'] });
}

function writeCodexJsonl(filePath, { sessionId, cwd, userText, assistantText }) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const lines = [
    JSON.stringify({
      timestamp: '2026-11-16T03:00:00.000Z',
      type: 'session_meta',
      payload: { id: sessionId, cwd, originator: 'codex_cli_rs' }
    }),
    JSON.stringify({
      timestamp: '2026-11-16T03:00:05.000Z',
      type: 'event_msg',
      payload: { type: 'user_message', message: userText }
    }),
    JSON.stringify({
      timestamp: '2026-11-16T03:00:10.000Z',
      type: 'response_item',
      payload: {
        type: 'message',
        role: 'assistant',
        content: [{ type: 'output_text', text: assistantText }]
      }
    })
  ];
  fs.writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
}

test('V3.4 Human Digest, MOC Navigation, Whitelist Auto-Sync & Distill CLI Suite', async (t) => {
  await t.test('1. extractHumanDigestTurnsFromMarkdown strips instruction wrappers & tool JSON while preserving ^event anchors', () => {
    const sampleMd = `---
schema_version: 1
id: SES-019316a8-0000-7000-8000-000000000001
note_type: session
title: "测试会话"
project: "AlphaProject"
privacy: sanitized
source_tool: codex
session_id: "sess-digest-01"
snapshot_id: "codex-sess-digest-01-abc"
coverage:
  total_events: 4
  rendered_events: 4
  placeholder_events: 0
created_at: "2026-11-16T03:00:00.000Z"
---

# 测试会话

## 会话事件记录

### 事件 #1 · USER_INPUT (user)
> <USER_REQUEST>
> 请帮我排查 PgBouncer 连接池耗尽的原因。
> <ADDITIONAL_METADATA>secret metadata</ADDITIONAL_METADATA>
> </USER_REQUEST>
^event-000001

### 事件 #2 · GENERIC
> {"step_index":2,"tool_calls":[{"name":"run_command"}]}
^event-000002

### 事件 #3 · PLANNER_RESPONSE (assistant)
> 建议将 max_client_conn 与 default_pool_size 按服务并发独立配置，并开启 server_idle_timeout。
^event-000003

### 事件 #4 · EPHEMERAL_MESSAGE
> ephemeral checkpoint noise
^event-000004
`;

    const beforeParsed = parseRenderedSessionEvents(sampleMd);
    assert.equal(beforeParsed.events.length, 4);

    const turns = extractHumanDigestTurnsFromMarkdown(sampleMd);
    assert.equal(turns.length, 2);
    assert.equal(turns[0].role, 'user');
    assert.match(turns[0].excerpt, /PgBouncer 连接池耗尽/);
    assert.doesNotMatch(turns[0].excerpt, /ADDITIONAL_METADATA|USER_REQUEST/);
    assert.equal(turns[1].role, 'assistant');
    assert.match(turns[1].excerpt, /default_pool_size/);

    const tmpFile = path.join(os.tmpdir(), `oam-digest-${Date.now()}.md`);
    fs.writeFileSync(tmpFile, sampleMd, 'utf8');
    t.after(() => fs.rmSync(tmpFile, { force: true }));

    const refreshed = refreshSessionHumanDigestHeader(tmpFile);
    assert.equal(refreshed.updated, true);
    assert.equal(refreshed.turnsCount, 2);

    const updatedMd = fs.readFileSync(tmpFile, 'utf8');
    assert.match(updatedMd, /## 人类精读摘要（对话要点与结论）/);
    const afterParsed = parseRenderedSessionEvents(updatedMd);
    assert.equal(afterParsed.events.length, 4);
    assert.deepEqual(
      afterParsed.events.map((e) => e.anchor),
      beforeParsed.events.map((e) => e.anchor)
    );
  });

  await t.test('2. runWhitelistAutoSync + rebuildVaultMocAndHome respect whitelist, skip unmapped/DSH, and exclude local_only from MOC', () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-v34-autosync-'));
    t.after(() => fs.rmSync(tmpBase, { recursive: true, force: true }));

    const vaultDir = path.join(tmpBase, 'Vault');
    const dataDir = path.join(tmpBase, 'Data');
    const codexHome = path.join(tmpBase, 'CodexHome');
    const dshHome = path.join(tmpBase, 'DshHome');
    const agBrain = path.join(tmpBase, 'AgBrain');
    fs.mkdirSync(dshHome, { recursive: true });
    fs.mkdirSync(agBrain, { recursive: true });

    initRepository({ vaultPath: vaultDir, dataPath: dataDir });
    initLocalVaultGit(vaultDir);
    assert.equal(fs.existsSync(path.join(vaultDir, '00_MOC')), true);

    fs.writeFileSync(
      path.join(dataDir, 'manifests', 'project-map.json'),
      JSON.stringify(
        {
          schema_version: 1,
          default_unmapped_project: 'unmapped',
          projects: [
            {
              project: 'AlphaProject',
              paths: ['D:\\Work\\proj-alpha'],
              git_roots: [],
              workspace_slugs: []
            }
          ]
        },
        null,
        2
      ) + '\n',
      'utf8'
    );

    const mappedFile = path.join(codexHome, 'sessions', '2026', '11', '16', 'rollout-2026-11-16T03-00-00-019316a8-aaaa-7000-8000-000000000101.jsonl');
    writeCodexJsonl(mappedFile, {
      sessionId: '019316a8-aaaa-7000-8000-000000000101',
      cwd: 'D:\\Work\\proj-alpha\\service',
      userText: '如何设计双目录 SQLite WAL 备份窗口？',
      assistantText: '先停写加锁检查点 sqlite3_wal_checkpoint(TRUNCATE)，再校验 SHA-256 指纹。'
    });

    const unmappedFile = path.join(codexHome, 'sessions', '2026', '11', '16', 'rollout-2026-11-16T03-00-00-019316a8-bbbb-7000-8000-000000000102.jsonl');
    writeCodexJsonl(unmappedFile, {
      sessionId: '019316a8-bbbb-7000-8000-000000000102',
      cwd: 'D:\\Work\\unmapped-playground',
      userText: '未知目录的测试对话',
      assistantText: '不应被白名单自动导入。'
    });

    // Insert a DSH session to confirm sourceTool='all' ignores DSH
    const dshSessionDir = path.join(dshHome, 'sessions', 'dsh-sess-999');
    fs.mkdirSync(dshSessionDir, { recursive: true });
    fs.writeFileSync(
      path.join(dshSessionDir, 'events.jsonl'),
      JSON.stringify({ type: 'user', content: 'DSH 私有桌面对话不应被 auto-sync 扫描' }) + '\n',
      'utf8'
    );

    const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
    const db = openExistingDatabase(dbPath);
    try {
      // Plant a local_only confidential session note to test MOC privacy boundary
      const localOnlyPath = path.join(vaultDir, '10_Readable_Sessions', 'SES-local-secret.md');
      fs.writeFileSync(
        localOnlyPath,
        `---
schema_version: 1
id: SES-019316a8-cccc-7000-8000-000000000103
note_type: session
title: "SECRET_LOCAL_ONLY_TITLE_999"
project: "AlphaProject"
privacy: local_only
source_tool: codex
session_id: "local-only-01"
snapshot_id: "snap-local-only-01"
created_at: "2026-11-16T02:00:00.000Z"
---

# SECRET_LOCAL_ONLY_TITLE_999
机密内容不应出现在 00_MOC 或 首页.md
`,
        'utf8'
      );
      db.prepare(
        `INSERT INTO notes (id, note_type, title, project, privacy, status, path, content_sha256, created_at, updated_at)
         VALUES (?, 'session', ?, 'AlphaProject', 'local_only', 'active', ?, 'abc', '2026-11-16T02:00:00.000Z', '2026-11-16T02:00:00.000Z')`
      ).run('SES-019316a8-cccc-7000-8000-000000000103', 'SECRET_LOCAL_ONLY_TITLE_999', localOnlyPath);

      // Dry-run classifies mapped vs unmapped without mutating
      const dryRes = runWhitelistAutoSync({
        db,
        vaultDir,
        dataDir,
        codexHome,
        codexArchivedDir: null,
        antigravityBrainDir: agBrain,
        dshHome,
        dryRun: true
      });
      assert.equal(dryRes.dryRunCandidatesCount, 1);
      assert.equal(dryRes.dryRunCandidates[0].project, 'AlphaProject');
      assert.equal(dryRes.skippedUnmappedCount, 1);

      // Without approval -> live ingest blocked
      const noApRes = runWhitelistAutoSync({
        db,
        vaultDir,
        dataDir,
        codexHome,
        codexArchivedDir: null,
        antigravityBrainDir: agBrain,
        dshHome,
        dryRun: false
      });
      assert.equal(noApRes.syncedCount, 0);
      assert.equal(noApRes.skippedUnapprovedCount, 1);

      // Issue trusted wildcard approval -> live whitelist sync succeeds
      const ap = issueTrustedLowSensitivityApproval({
        db,
        sourceTool: 'codex',
        sessionId: '*',
        approvedBy: 'test-tty',
        ttlHours: 24,
        trustedHumanContext: true
      });

      const liveRes = runWhitelistAutoSync({
        db,
        vaultDir,
        dataDir,
        codexHome,
        codexArchivedDir: null,
        antigravityBrainDir: agBrain,
        dshHome,
        codexApprovalId: ap.ingestApprovalId,
        dryRun: false,
        updateMoc: true
      });
      assert.equal(liveRes.syncedCount, 1);
      assert.equal(liveRes.synced[0].project, 'AlphaProject');
      assert.equal(liveRes.skippedUnmappedCount, 1);
      assert.equal(liveRes.mocUpdated, true);
      assert.equal(liveRes.errorsCount, 0);

      // Second run deduplicates cleanly
      const secondRes = runWhitelistAutoSync({
        db,
        vaultDir,
        dataDir,
        codexHome,
        codexArchivedDir: null,
        antigravityBrainDir: agBrain,
        dshHome,
        codexApprovalId: ap.ingestApprovalId,
        dryRun: false
      });
      assert.equal(secondRes.syncedCount, 0);
      assert.equal(secondRes.alreadySyncedCount, 1);

      // Verify generated MOC & Home exclude local_only title completely
      const alphaMoc = fs.readFileSync(path.join(vaultDir, '00_MOC', 'AlphaProject.md'), 'utf8');
      const briefMd = fs.readFileSync(path.join(vaultDir, '00_MOC', '学习简报_最新会话精华.md'), 'utf8');
      const homeMd = fs.readFileSync(path.join(vaultDir, '首页.md'), 'utf8');

      assert.doesNotMatch(alphaMoc, /SECRET_LOCAL_ONLY_TITLE_999/);
      assert.doesNotMatch(briefMd, /SECRET_LOCAL_ONLY_TITLE_999/);
      assert.doesNotMatch(homeMd, /SECRET_LOCAL_ONLY_TITLE_999/);
      assert.match(alphaMoc, /双目录 SQLite WAL 备份窗口|会话/);
      assert.match(briefMd, /AlphaProject/);
      assert.match(homeMd, /\[\[00_MOC\/AlphaProject\|AlphaProject\]\]/);

      // Ensure Vault git committed MOC, home page, and auto-synced readable session cleanly
      const scopedGitStatus = execFileSync(
        'git',
        ['status', '--short', '--', '00_MOC', '首页.md', liveRes.synced[0].readableSessionPath],
        { cwd: vaultDir, encoding: 'utf8' }
      ).trim();
      assert.equal(scopedGitStatus, '');
    } finally {
      db.close();
    }
  });

  await t.test('3. CLI mem render-moc / auto-sync --dry-run / distill --dry-run & mem-operator distill elevation boundary', () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-v34-cli-'));
    t.after(() => fs.rmSync(tmpBase, { recursive: true, force: true }));

    const vaultDir = path.join(tmpBase, 'Vault');
    const dataDir = path.join(tmpBase, 'Data');
    initRepository({ vaultPath: vaultDir, dataPath: dataDir });
    initLocalVaultGit(vaultDir);

    const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
    const db = openExistingDatabase(dbPath);
    let sanitizedSessId = null;
    const localSessId = 'SES-019316a8-dddd-7000-8000-000000000104';
    try {
      const sanPath = path.join(vaultDir, '10_Readable_Sessions', 'SES-20261116-sanitized-cli.md');
      sanitizedSessId = 'SES-019316a8-eeee-7000-8000-000000000105';
      fs.writeFileSync(
        sanPath,
        `---
schema_version: 1
id: ${sanitizedSessId}
note_type: session
title: "CLI Distill Preview Session"
project: "AlphaProject"
privacy: sanitized
source_tool: codex
session_id: "cli-sess-01"
snapshot_id: "snap-cli-01"
created_at: "2026-11-16T03:30:00.000Z"
---

# CLI Distill Preview Session

## 会话事件记录

### 事件 #1 — 2026-11-16T03:30:01Z (user)
^event-000001

请总结 EMRank 0.6B 模型切换经验。

### 事件 #2 — 2026-11-16T03:30:05Z (assistant)
^event-000002

Qwen3-Embedding-0.6B 在真实测试集上达成 Hit@1 100%，首篇延迟降低 19.1 倍。
`,
        'utf8'
      );
      db.prepare(
        `INSERT INTO notes (id, note_type, title, project, privacy, status, path, content_sha256, created_at, updated_at)
         VALUES (?, 'session', 'CLI Distill Preview Session', 'AlphaProject', 'sanitized', 'active', ?, 'sha-san', '2026-11-16T03:30:00.000Z', '2026-11-16T03:30:00.000Z')`
      ).run(sanitizedSessId, sanPath);

      const locPath = path.join(vaultDir, '10_Readable_Sessions', 'SES-20261116-local-cli.md');
      fs.writeFileSync(locPath, `---\nschema_version: 1\nid: ${localSessId}\nnote_type: session\ntitle: "LocalOnly"\nproject: "AlphaProject"\nprivacy: local_only\n---\nsecret\n`, 'utf8');
      db.prepare(
        `INSERT INTO notes (id, note_type, title, project, privacy, status, path, content_sha256, created_at, updated_at)
         VALUES (?, 'session', 'LocalOnly', 'AlphaProject', 'local_only', 'active', ?, 'sha-loc', '2026-11-16T03:30:00.000Z', '2026-11-16T03:30:00.000Z')`
      ).run(localSessId, locPath);
    } finally {
      db.close();
    }

    const env = { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir };

    // mem render-moc --update-digests --json
    const mocOut = execFileSync(
      process.execPath,
      [MEM_CLI_PATH, 'render-moc', '--update-digests', '--vault', vaultDir, '--data', dataDir, '--json'],
      { env, encoding: 'utf8' }
    );
    const mocJson = JSON.parse(mocOut);
    assert.equal(mocJson.status, 'ok');
    assert.equal(mocJson.sanitizedNotesCount, 1);

    // mem auto-sync --dry-run --json
    const syncOut = execFileSync(
      process.execPath,
      [MEM_CLI_PATH, 'auto-sync', '--dry-run', '--vault', vaultDir, '--data', dataDir, '--json'],
      { env, encoding: 'utf8' }
    );
    const syncJson = JSON.parse(syncOut);
    assert.equal(syncJson.dryRun, true);

    // mem distill --dry-run --json (egressBytes = 0)
    const distillOut = execFileSync(
      process.execPath,
      [MEM_CLI_PATH, 'distill', '--session', sanitizedSessId, '--dry-run', '--vault', vaultDir, '--data', dataDir, '--json'],
      { env, encoding: 'utf8' }
    );
    const distillJson = JSON.parse(distillOut);
    assert.equal(distillJson.status, 'dry_run_ok');
    assert.equal(distillJson.egressBytes, 0);
    assert.equal(distillJson.distillableEventsCount, 2);

    // mem distill live blocked in ordinary CLI
    const liveMemDistill = spawnSync(
      process.execPath,
      [MEM_CLI_PATH, 'distill', '--session', sanitizedSessId, '--vault', vaultDir, '--data', dataDir],
      { env, encoding: 'utf8' }
    );
    assert.notEqual(liveMemDistill.status, 0);
    assert.match(`${liveMemDistill.stderr || ''}\n${liveMemDistill.stdout || ''}`, /ERR_DISTILL_OPERATOR_REQUIRED/);

    // mem distill --dry-run blocks local_only note
    const locDistill = spawnSync(
      process.execPath,
      [MEM_CLI_PATH, 'distill', '--session', localSessId, '--dry-run', '--vault', vaultDir, '--data', dataDir],
      { env, encoding: 'utf8' }
    );
    assert.notEqual(locDistill.status, 0);
    assert.match(`${locDistill.stderr || ''}\n${locDistill.stdout || ''}`, /ERR_DISTILL_PRIVACY_NOT_SANITIZED/);

    // mem-operator distill recognized & enforces elevation / OS isolation gates
    const opDistill = spawnSync(
      process.execPath,
      [OPERATOR_CLI_PATH, 'distill', '--session', sanitizedSessId, '--approval', 'CEGR-test-only'],
      { env, encoding: 'utf8' }
    );
    assert.notEqual(opDistill.status, 0);
    const expectedOpPattern = isCurrentWindowsProcessElevated()
      ? /ERR_CLOUD_OS_ISOLATION_FAILED/
      : /ERR_OPERATOR_ELEVATION_REQUIRED/;
    assert.match(`${opDistill.stderr || ''}\n${opDistill.stdout || ''}`, expectedOpPattern);
  });

  await t.test('4. PowerShell auto-sync scripts AST parse, register-auto-sync-task EXIT 43 guard, and Gate-1 whitelist check', () => {
    for (const psPath of [AUTO_SYNC_PS1_PATH, REGISTER_TASK_PS1_PATH]) {
      assert.equal(fs.existsSync(psPath), true);
      const astCmd = `
$errors = $null
$tokens = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('${psPath.replace(/'/g, "''")}', [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
  throw ($errors | Out-String)
}
Write-Output 'AST_OK'
`.trim();
      const astOut = execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', astCmd], {
        encoding: 'utf8'
      });
      assert.match(astOut, /AST_OK/);
    }

    const regRefuse = spawnSync(
      'pwsh',
      ['-NoProfile', '-NonInteractive', '-File', REGISTER_TASK_PS1_PATH],
      {
        encoding: 'utf8',
        env: { ...process.env, ANTIGRAVITY_AGENT: '1' }
      }
    );
    assert.equal(regRefuse.status, 43);
    assert.match(`${regRefuse.stderr || ''}\n${regRefuse.stdout || ''}`, /ACCESS_DENIED \(EXIT 43\)/);

    const gate1 = validateEngineeringCommitPaths(process.cwd(), [
      'src/ingest/human-digest.mjs',
      'src/ingest/auto-sync.mjs',
      'src/ingest/session-ingestor.mjs',
      'src/distill/llm-distiller.mjs',
      'src/git/repo-manager.mjs',
      'src/init.mjs',
      'cli/mem.mjs',
      'cli/mem-operator.mjs',
      'scripts/auto-sync-memory.ps1',
      'scripts/register-auto-sync-task.ps1',
      'tests/v34-auto-sync-digest-distill.test.mjs'
    ]);
    assert.equal(gate1.valid, true, JSON.stringify(gate1));
  });
});
