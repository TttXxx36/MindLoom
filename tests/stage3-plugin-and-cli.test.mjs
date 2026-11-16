import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { initRepository } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';
import { confirmDeleteNote } from '../src/tombstone/tracker.mjs';
import { createProposal } from '../src/reconcile/engine.mjs';
import { runLeakScan } from '../scripts/check-leaks.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

test('Stage 3 & 4: Companion Plugin Console CLI Contracts, Bundle Size & Leak Scan', async (t) => {
  await t.test('1. Plugin build artifacts exist, main.js < 150KB, and zero leak scan findings', () => {
    const distDir = path.resolve('plugin/dist');
    assert.ok(fs.existsSync(path.join(distDir, 'main.js')));
    assert.ok(fs.existsSync(path.join(distDir, 'manifest.json')));
    assert.ok(fs.existsSync(path.join(distDir, 'styles.css')));

    const mainSize = fs.statSync(path.join(distDir, 'main.js')).size;
    assert.ok(mainSize > 1000 && mainSize < 153600, `Unexpected main.js size: ${mainSize}`);

    const leakRes = runLeakScan();
    assert.equal(leakRes.ok, true, `Leak scan failed: ${JSON.stringify(leakRes.findings)}`);
  });

  await t.test('2. CLI console commands: reconcile --json, restore --list/--json, project-map upsert/remove, cloud-budget --json', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-stage3-cli-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultDir = path.join(tmp, 'Vault');
    const dataDir = path.join(tmp, 'Vault-Data');
    initRepository({ vaultPath: vaultDir, dataPath: dataDir });
    const env = { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir };

    // Publish a note + create a proposal + delete note to test restore --list/--json
    const db = openExistingDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));
    const knId = 'KN-019316a8-5555-7000-8000-000000000001';
    const knPath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-20261116-000001_插件控制台测试.md');
    const knContent = `---
schema_version: 1
id: "${knId}"
note_type: "playbook"
title: "插件控制台测试"
project: "ConsoleProj"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env:
  os: "windows"
created_at: "2026-11-16T05:00:00Z"
---

# 插件控制台测试
old_buggy_step
`;
    const stg = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: knId, content: knContent });
    publishFile({
      db,
      operationId: 'op-s3-kn1',
      outputUuid: knId,
      stagingPath: stg.stagingPath,
      vaultTargetPath: knPath,
      contentSha256: stg.contentSha256,
      revisionsDir: path.join(dataDir, 'runtime', 'revisions')
    });

    createProposal({
      queueDir: path.join(vaultDir, '40_Review_Queue'),
      proposalUuid: 'PROP-019316a8-5555-7000-8000-000000000002',
      title: '控制台提案测试',
      project: 'ConsoleProj',
      targetId: knId,
      targetNoteLink: '[[30_Knowledge_Notes/Playbooks/KN-20261116-000001_插件控制台测试]]',
      baseRevisionId: 'rev-0001',
      proposalKind: 'supplement',
      proposalStatus: 'pending',
      sources: ['[[20_Evidence_Cards/EV-001]]'],
      preConditions: [{ type: 'absent', pattern: 'old_buggy_step' }],
      postConditions: [{ type: 'present', pattern: 'fixed_step' }],
      bodyContent: '建议更新为 fixed_step'
    });

    const recJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'reconcile', '--json'], { env, encoding: 'utf8' }));
    assert.equal(recJson.syncReport.conflictsCount, 0);

    // Delete note and verify restore --list --json + preview + confirm restore --json
    confirmDeleteNote({
      db,
      noteId: knId,
      revisionsDir: path.join(dataDir, 'runtime', 'revisions'),
      archiveAsRev1: true
    });
    db.close();

    const listDeleted = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'restore', '--list', '--json'], { env, encoding: 'utf8' })
    );
    assert.equal(listDeleted.count, 1);
    assert.equal(listDeleted.items[0].id, knId);

    const previewRes = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'restore', knId, '--revision', 'rev-0001', '--json'], { env, encoding: 'utf8' })
    );
    assert.equal(previewRes.restored, false);
    assert.ok(previewRes.revisionContent.includes('old_buggy_step'));

    const confirmRes = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'restore', knId, '--revision', 'rev-0001', '--confirm', '--json'], { env, encoding: 'utf8' })
    );
    assert.equal(confirmRes.restored, true);
    assert.ok(fs.existsSync(knPath));

    // project-map upsert / list / collision rejection / remove
    const upsertRes = JSON.parse(
      execFileSync(
        process.execPath,
        [CLI_PATH, 'project-map', 'upsert', '--project', 'ProjA', '--paths', path.join(tmp, 'proj-a'), '--slugs', 'proj-a'],
        { env, encoding: 'utf8' }
      )
    );
    assert.equal(upsertRes.updated, true);
    assert.equal(upsertRes.totalProjects, 1);

    assert.throws(() =>
      execFileSync(
        process.execPath,
        [CLI_PATH, 'project-map', 'upsert', '--project', 'ProjB', '--paths', path.join(tmp, 'proj-a', 'sub')],
        { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      )
    );

    const rmRes = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'project-map', 'remove', '--project', 'ProjA'], { env, encoding: 'utf8' })
    );
    assert.equal(rmRes.removed, 1);

    // cloud-budget read-only telemetry
    const budgetRes = JSON.parse(
      execFileSync(
        process.execPath,
        [CLI_PATH, 'cloud-budget', '--operator-root', path.join(tmp, 'op-root'), '--json'],
        { env, encoding: 'utf8' }
      )
    );
    assert.equal(budgetRes.readOnly, true);
    assert.equal(budgetRes.operatorDbIsolation, 'not_initialized');
    assert.ok(budgetRes.adminCommands.issueCloudApproval.includes('approve-human.ps1'));
  });

  await t.test('3. CliBridge & diff-utils TypeScript modules handle mock CLI, timeouts, and ^event anchors', async () => {
    const esbuildPath = path.resolve('plugin/node_modules/esbuild/lib/main.js');
    const { build } = await import(`file:///${esbuildPath.replace(/\\/g, '/')}`);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-bridge-test-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const outBridge = path.join(tmp, 'cli-bridge.mjs');
    const outDiff = path.join(tmp, 'diff-utils.mjs');
    await build({
      entryPoints: [path.resolve('plugin/src/cli-bridge.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      outfile: outBridge
    });
    await build({
      entryPoints: [path.resolve('plugin/src/diff-utils.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      outfile: outDiff
    });

    const { CliBridge } = await import(`file:///${outBridge.replace(/\\/g, '/')}`);
    const { computeSimpleLineDiff, extractEventWikilinks } = await import(`file:///${outDiff.replace(/\\/g, '/')}`);

    const fakeCli = path.join(tmp, 'fake-cli.mjs');
    fs.writeFileSync(fakeCli, '// placeholder', 'utf8');
    const settings = {
      vaultPath: path.join(tmp, 'V'),
      dataPath: path.join(tmp, 'D'),
      nodePath: process.execPath,
      cliPath: fakeCli,
      operatorRoot: '',
      timeoutMs: 250
    };

    // Mock execFn success
    const okBridge = new CliBridge(
      () => settings,
      () => settings.vaultPath,
      (_file, _args, _opts, cb) => cb(null, '[info] prefix\n{"ok":true,"count":3}\n', '')
    );
    const okRes = await okBridge.runJson(['status']);
    assert.equal(okRes.ok, true);
    assert.equal(okRes.data.count, 3);

    // Mock execFn timeout
    const timeoutBridge = new CliBridge(
      () => settings,
      () => settings.vaultPath,
      (_file, _args, opts, cb) => {
        const err = new Error('timed out');
        err.killed = true;
        cb(err, '', '');
        assert.equal(opts.timeout, 250);
      }
    );
    const toRes = await timeoutBridge.runJson(['status']);
    assert.equal(toRes.ok, false);
    assert.match(toRes.error, /timed out after 250ms/);

    // Missing CLI file returns clear error
    const missingBridge = new CliBridge(
      () => ({ ...settings, cliPath: path.join(tmp, 'does-not-exist.mjs') }),
      () => settings.vaultPath
    );
    const missRes = await missingBridge.runJson(['doctor']);
    assert.equal(missRes.ok, false);
    assert.match(missRes.error, /not found/);

    // diff-utils checks
    const diff = computeSimpleLineDiff('line1\noldLine', 'line1\nnewLine');
    assert.ok(diff.some((d) => d.kind === 'del' && d.text.includes('oldLine')));
    assert.ok(diff.some((d) => d.kind === 'add' && d.text.includes('newLine')));
    const links = extractEventWikilinks(['[[10_Readable_Sessions/SES-01#^event-000012]]', '[[20_Evidence_Cards/EV-01]]']);
    assert.deepEqual(links, ['10_Readable_Sessions/SES-01#^event-000012']);
  });
});
