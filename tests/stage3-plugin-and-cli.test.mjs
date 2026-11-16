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
import { verifyReleaseAssets } from '../scripts/verify-release-assets.mjs';

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
    assert.equal(listDeleted.items[0].revisions[0], 'rev-0001');
    assert.equal(listDeleted.items[0].revisions.includes('latest'), false);

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

    // Relative paths must be rejected so plugin CWD never causes ambiguous mappings
    assert.throws(() =>
      execFileSync(
        process.execPath,
        [CLI_PATH, 'project-map', 'upsert', '--project', 'RelProj', '--paths', 'relative-only'],
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

    // diff-utils checks (including LCS ordering, duplicate lines, and |alias stripping)
    const diff = computeSimpleLineDiff('---\nline1\noldLine\n---\n', '---\nline1\nnewLine\n---\n');
    assert.deepEqual(
      diff.map((d) => d.text),
      ['  ---', '  line1', '- oldLine', '+ newLine', '  ---', '  ']
    );
    const links = extractEventWikilinks([
      '[[10_Readable_Sessions/SES-01#^event-000012|事件 #12]]',
      '[[10_Readable_Sessions/SES-01#^event-000012]]',
      '[[20_Evidence_Cards/EV-01]]'
    ]);
    assert.deepEqual(links, ['10_Readable_Sessions/SES-01#^event-000012']);

    // readLastAutoSyncTime reads auto-sync-latest.json
    const logsDir = path.join(settings.dataPath, 'runtime', 'logs');
    fs.mkdirSync(logsDir, { recursive: true });
    fs.writeFileSync(
      path.join(logsDir, 'auto-sync-latest.json'),
      JSON.stringify({ executedAt: '2026-11-16T04:05:06.000Z' }),
      'utf8'
    );
    assert.equal(okBridge.readLastAutoSyncTime(), '2026-11-16T04:05:06.000Z');
  });

  await t.test('4. Deployed CLI cloud-budget resolves real setupIsolation script & search resolves sanitized 1-hop event_anchors', async () => {
    const { runSetupWizard } = await import('../src/setup/wizard.mjs');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-stage3-anchors-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultDir = path.join(tmp, 'Vault');
    const dataDir = path.join(tmp, 'Vault-Data');
    await runSetupWizard({
      vaultPath: vaultDir,
      dataPath: dataDir,
      configPath: path.join(tmp, 'cfg.json'),
      yes: true,
      skipPlugin: true,
      sourceRoots: { codexHome: path.join(tmp, 'no-cdx'), codexArchivedDir: null, antigravityBrainDir: path.join(tmp, 'no-agy'), dshHome: path.join(tmp, 'no-dsh') }
    });

    const deployedCli = path.join(dataDir, 'cli', 'mem.mjs');
    const budget = JSON.parse(
      execFileSync(process.execPath, [deployedCli, 'cloud-budget', '--vault', vaultDir, '--data', dataDir, '--json'], { encoding: 'utf8' })
    );
    const match = budget.adminCommands.setupIsolation.match(/-File\s+"([^"]+)"/);
    assert.ok(match && fs.existsSync(match[1]), `Expected existing setupIsolation script, got: ${budget.adminCommands.setupIsolation}`);

    // Seed sanitized + local_only sessions -> evidence -> knowledge note to verify 1-hop event_anchors privacy gate
    const db = openExistingDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));
    const sesSanId = 'SES-019316a8-8888-7000-8000-000000000001';
    const sesSanName = 'SES-20261116-codex-000001_san.md';
    const sesPrivId = 'SES-019316a8-8888-7000-8000-000000000002';
    const sesPrivName = 'SES-20261116-codex-000002_priv.md';
    const evId = 'EV-019316a8-8888-7000-8000-000000000003';
    const evName = 'EV-20261116-000003_ev.md';
    const knId = 'KN-019316a8-8888-7000-8000-000000000004';
    const knPath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-20261116-000004_anchor.md');

    const s1 = stageCandidate({
      stagingDir: path.join(dataDir, 'staging'),
      outputUuid: sesSanId,
      content: `---\nschema_version: 1\nid: "${sesSanId}"\nnote_type: "session"\ntitle: "san"\nproject: "P"\nprivacy: "sanitized"\nsource_tool: "codex"\nsession_id: "s1"\nsnapshot_id: "snap1"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n\n^event-000007\n`
    });
    publishFile({ db, operationId: 'op-a1', outputUuid: sesSanId, stagingPath: s1.stagingPath, vaultTargetPath: path.join(vaultDir, '10_Readable_Sessions', sesSanName), contentSha256: s1.contentSha256 });

    const s2 = stageCandidate({
      stagingDir: path.join(dataDir, 'staging'),
      outputUuid: sesPrivId,
      content: `---\nschema_version: 1\nid: "${sesPrivId}"\nnote_type: "session"\ntitle: "priv"\nproject: "P"\nprivacy: "local_only"\nsource_tool: "codex"\nsession_id: "s2"\nsnapshot_id: "snap2"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n\n^event-000009\n`
    });
    publishFile({ db, operationId: 'op-a2', outputUuid: sesPrivId, stagingPath: s2.stagingPath, vaultTargetPath: path.join(vaultDir, '10_Readable_Sessions', sesPrivName), contentSha256: s2.contentSha256 });

    const s3 = stageCandidate({
      stagingDir: path.join(dataDir, 'staging'),
      outputUuid: evId,
      content: `---\nschema_version: 1\nid: "${evId}"\nnote_type: "evidence"\ntitle: "ev"\nproject: "P"\nprivacy: "sanitized"\nsource_tool: "codex"\nevidence_level: "observed"\nsources:\n  - "[[10_Readable_Sessions/${sesSanName}#^event-000007]]"\n  - "[[10_Readable_Sessions/${sesPrivName}#^event-000009]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n\nev\n`
    });
    publishFile({ db, operationId: 'op-a3', outputUuid: evId, stagingPath: s3.stagingPath, vaultTargetPath: path.join(vaultDir, '20_Evidence_Cards', evName), contentSha256: s3.contentSha256 });

    const s4 = stageCandidate({
      stagingDir: path.join(dataDir, 'staging'),
      outputUuid: knId,
      content: `---\nschema_version: 1\nid: "${knId}"\nnote_type: "playbook"\ntitle: "Anchor Resolution Test"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\nsources:\n  - "[[20_Evidence_Cards/${evName}]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n\nFix anchor401\n`
    });
    publishFile({ db, operationId: 'op-a4', outputUuid: knId, stagingPath: s4.stagingPath, vaultTargetPath: knPath, contentSha256: s4.contentSha256 });
    db.close();

    const searchRes = JSON.parse(
      execFileSync(process.execPath, [deployedCli, 'search', 'anchor401', '--mode', 'literal', '--vault', vaultDir, '--data', dataDir, '--json'], { encoding: 'utf8' })
    );
    assert.equal(searchRes.items.length, 1);
    assert.deepEqual(searchRes.items[0].event_anchors, [`10_Readable_Sessions/${sesSanName}#^event-000007`]);
    assert.deepEqual(searchRes.items[0].openable_links, [
      `20_Evidence_Cards/${evName}`,
      `10_Readable_Sessions/${sesSanName}#^event-000007`
    ]);
  });

  await t.test('5. [Bug E, F, G3 & Round-2 C, E] Release asset env verification, block-ID existence/uniqueness filtering, QuickSearchModal & Sync/MOC notices', async () => {
    // (a) Bug E & Round-2 E: verifyReleaseAssets checks tag via RELEASE_TAG env & release.yml uses env + least privilege
    const manifestVer = JSON.parse(fs.readFileSync(path.resolve('plugin/manifest.json'), 'utf8')).version;
    const relOk = verifyReleaseAssets({ tag: `v${manifestVer}` });
    assert.equal(relOk.ok, true);
    assert.throws(() => verifyReleaseAssets({ tag: 'v99.99.99' }), /RELEASE_TAG_MISMATCH/);

    const envRes = execFileSync(process.execPath, [path.resolve('scripts/verify-release-assets.mjs')], {
      encoding: 'utf8',
      env: { ...process.env, RELEASE_TAG: `v${manifestVer}` }
    });
    assert.match(envRes, /RELEASE ASSETS OK/);

    const releaseYml = fs.readFileSync(path.resolve('.github/workflows/release.yml'), 'utf8');
    assert.match(releaseYml, /RELEASE_TAG:\s*\$\{\{\s*github\.ref_name\s*\}\}/);
    assert.equal(/--tag\s+"?\$\{\{\s*github\.ref_name/.test(releaseYml), false);
    assert.match(releaseYml, /permissions:\s*\r?\n\s*contents:\s*read/);

    // (b) Bug F: CLI searchKnowledge rejects private, deleted, missing, not-found, and duplicate/ambiguous targets on both direct & 1-hop paths
    const { runSetupWizard } = await import('../src/setup/wizard.mjs');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-stage3-links-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultDir = path.join(tmp, 'Vault');
    const dataDir = path.join(tmp, 'Vault-Data');
    await runSetupWizard({
      vaultPath: vaultDir,
      dataPath: dataDir,
      configPath: path.join(tmp, 'cfg.json'),
      yes: true,
      skipPlugin: true,
      sourceRoots: { codexHome: path.join(tmp, 'no-cdx'), codexArchivedDir: null, antigravityBrainDir: path.join(tmp, 'no-agy'), dshHome: path.join(tmp, 'no-dsh') }
    });

    const db = openExistingDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));
    const publishDoc = (id, relTarget, content, opId) => {
      const stg = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: id, content });
      publishFile({ db, operationId: opId, outputUuid: id, stagingPath: stg.stagingPath, vaultTargetPath: path.join(vaultDir, relTarget), contentSha256: stg.contentSha256 });
    };

    const sesOkId = 'SES-019316a8-9999-7000-8000-000000000001';
    const sesOkName = 'SES-20261116-codex-000001_ok.md';
    const sesDelId = 'SES-019316a8-9999-7000-8000-000000000002';
    const sesDelName = 'SES-20261116-codex-000002_del.md';
    const sesPrivId = 'SES-019316a8-9999-7000-8000-000000000003';
    const sesPrivName = 'SES-20261116-codex-000003_priv.md';
    const evOkId = 'EV-019316a8-9999-7000-8000-000000000004';
    const evOkName = 'EV-20261116-000004_ok.md';
    const evPrivId = 'EV-019316a8-9999-7000-8000-000000000005';
    const evPrivName = 'EV-20261116-000005_priv.md';

    publishDoc(sesOkId, `10_Readable_Sessions/${sesOkName}`, `---\nschema_version: 1\nid: "${sesOkId}"\nnote_type: "session"\ntitle: "ok"\nproject: "P"\nprivacy: "sanitized"\nsource_tool: "codex"\nsession_id: "s1"\nsnapshot_id: "sn1"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n^event-000001\n\n^event-000003\n\n^event-000003\n\n> ^event-000004\n`, 'op-f1');
    publishDoc(sesDelId, `10_Readable_Sessions/${sesDelName}`, `---\nschema_version: 1\nid: "${sesDelId}"\nnote_type: "session"\ntitle: "del"\nproject: "P"\nprivacy: "sanitized"\nsource_tool: "codex"\nsession_id: "s2"\nsnapshot_id: "sn2"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n^event-000002\n`, 'op-f2');
    confirmDeleteNote({ db, noteId: sesDelId, revisionsDir: path.join(dataDir, 'runtime', 'revisions'), archiveAsRev1: true });
    publishDoc(sesPrivId, `10_Readable_Sessions/${sesPrivName}`, `---\nschema_version: 1\nid: "${sesPrivId}"\nnote_type: "session"\ntitle: "priv"\nproject: "P"\nprivacy: "local_only"\nsource_tool: "codex"\nsession_id: "s3"\nsnapshot_id: "sn3"\ncreated_at: "2026-11-16T00:00:00Z"\n---\n^event-000003\n`, 'op-f3');

    // Duplicate basename in two subdirs of 10_Readable_Sessions
    fs.mkdirSync(path.join(vaultDir, '10_Readable_Sessions', 'subA'), { recursive: true });
    fs.mkdirSync(path.join(vaultDir, '10_Readable_Sessions', 'subB'), { recursive: true });
    fs.writeFileSync(path.join(vaultDir, '10_Readable_Sessions', 'subA', 'DUP-SES.md'), `---\nid: "SES-DUP-A"\nprivacy: "sanitized"\n---\n^event-000004\n`, 'utf8');
    fs.writeFileSync(path.join(vaultDir, '10_Readable_Sessions', 'subB', 'DUP-SES.md'), `---\nid: "SES-DUP-B"\nprivacy: "sanitized"\n---\n^event-000004\n`, 'utf8');

    publishDoc(evOkId, `20_Evidence_Cards/${evOkName}`, `---\nschema_version: 1\nid: "${evOkId}"\nnote_type: "evidence"\ntitle: "evok"\nproject: "P"\nprivacy: "sanitized"\nsource_tool: "codex"\nevidence_level: "observed"\nsources:\n  - "[[10_Readable_Sessions/${sesOkName}#^event-000001]]"\n  - "[[10_Readable_Sessions/${sesOkName}#^event-000002]]"\n  - "[[10_Readable_Sessions/${sesOkName}#^event-000003]]"\n  - "[[10_Readable_Sessions/${sesOkName}#^event-000004]]"\n  - "[[10_Readable_Sessions/${sesDelName}#^event-000002]]"\n  - "[[10_Readable_Sessions/${sesPrivName}#^event-000003]]"\n  - "[[10_Readable_Sessions/missing-ses#^event-000009]]"\n  - "[[DUP-SES#^event-000004]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\nevok\n`, 'op-f4');
    publishDoc(evPrivId, `20_Evidence_Cards/${evPrivName}`, `---\nschema_version: 1\nid: "${evPrivId}"\nnote_type: "evidence"\ntitle: "evpriv"\nproject: "P"\nprivacy: "local_only"\nsource_tool: "codex"\nevidence_level: "observed"\nsources:\n  - "[[10_Readable_Sessions/${sesOkName}#^event-000008]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\nevpriv\n`, 'op-f5');

    const knId = 'KN-019316a8-9999-7000-8000-000000000006';
    publishDoc(knId, '30_Knowledge_Notes/Playbooks/KN-filter.md', `---\nschema_version: 1\nid: "${knId}"\nnote_type: "playbook"\ntitle: "Link Filter Note"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\nsources:\n  - "[[20_Evidence_Cards/${evOkName}]]"\n  - "[[10_Readable_Sessions/${sesOkName}#^event-000099]]"\n  - "[[20_Evidence_Cards/${evPrivName}]]"\n  - "[[10_Readable_Sessions/${sesPrivName}#^event-000003]]"\n  - "[[10_Readable_Sessions/does-not-exist#^event-000099]]"\n  - "[[DUP-SES#^event-000004]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\nfilterprobe\n`, 'op-f6');

    const knBlockedOnlyId = 'KN-019316a8-9999-7000-8000-000000000007';
    publishDoc(knBlockedOnlyId, '30_Knowledge_Notes/Playbooks/KN-blocked-only.md', `---\nschema_version: 1\nid: "${knBlockedOnlyId}"\nnote_type: "playbook"\ntitle: "Blocked Sources Only"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\nsources:\n  - "[[20_Evidence_Cards/${evPrivName}]]"\n  - "[[10_Readable_Sessions/does-not-exist]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\nblockedprobe\n`, 'op-f7');
    db.close();

    const deployedCli = path.join(dataDir, 'cli', 'mem.mjs');
    const searchFiltered = JSON.parse(
      execFileSync(process.execPath, [deployedCli, 'search', 'filterprobe', '--mode', 'literal', '--vault', vaultDir, '--data', dataDir, '--json'], { encoding: 'utf8' })
    );
    assert.equal(searchFiltered.items.length, 1);
    assert.deepEqual(searchFiltered.items[0].event_anchors, [`10_Readable_Sessions/${sesOkName}#^event-000001`]);
    assert.deepEqual(searchFiltered.items[0].openable_links, [
      `20_Evidence_Cards/${evOkName}`,
      `10_Readable_Sessions/${sesOkName}#^event-000001`
    ]);

    const searchBlockedOnly = JSON.parse(
      execFileSync(process.execPath, [deployedCli, 'search', 'blockedprobe', '--mode', 'literal', '--vault', vaultDir, '--data', dataDir, '--json'], { encoding: 'utf8' })
    );
    assert.equal(searchBlockedOnly.items.length, 1);
    assert.deepEqual(searchBlockedOnly.items[0].event_anchors, []);
    assert.deepEqual(searchBlockedOnly.items[0].openable_links, []);

    // Round 3 Panel D: CommonMark nested longer fence + unclosed outer fence must NOT emit false ^event anchors
    const sesFenceId = 'SES-019316a8-9999-7000-8000-000000000010';
    const sesFenceName = 'SES-20261116-codex-000010_fence.md';
    const fenceSessionBody = [
      '---',
      'schema_version: 1',
      `id: "${sesFenceId}"`,
      'note_type: "session"',
      'title: "fence"',
      'project: "P"',
      'privacy: "sanitized"',
      'source_tool: "codex"',
      'session_id: "s10"',
      'snapshot_id: "sn10"',
      'created_at: "2026-11-16T00:00:00Z"',
      '---',
      '````md',
      '```',
      'inside inner 3-backtick fence ^event-000088',
      '````',
      '',
      'real outside event ^event-000001',
      '',
      '~~~~text',
      '~~~',
      'inside unclosed 4-tilde fence ^event-000077',
      ''
    ].join('\n');
    const db2 = openExistingDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));
    const stgFenceSes = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: sesFenceId, content: fenceSessionBody });
    publishFile({ db: db2, operationId: 'op-f8', outputUuid: sesFenceId, stagingPath: stgFenceSes.stagingPath, vaultTargetPath: path.join(vaultDir, `10_Readable_Sessions/${sesFenceName}`), contentSha256: stgFenceSes.contentSha256 });
    const knFenceId = 'KN-019316a8-9999-7000-8000-000000000011';
    const knFenceBody = `---\nschema_version: 1\nid: "${knFenceId}"\nnote_type: "playbook"\ntitle: "Fence Test Note"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\nsources:\n  - "[[10_Readable_Sessions/${sesFenceName}#^event-000088]]"\n  - "[[10_Readable_Sessions/${sesFenceName}#^event-000077]]"\n  - "[[10_Readable_Sessions/${sesFenceName}#^event-000001]]"\ncreated_at: "2026-11-16T00:00:00Z"\n---\nfenceprobe\n`;
    const stgFenceKn = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: knFenceId, content: knFenceBody });
    publishFile({ db: db2, operationId: 'op-f9', outputUuid: knFenceId, stagingPath: stgFenceKn.stagingPath, vaultTargetPath: path.join(vaultDir, '30_Knowledge_Notes/Playbooks/KN-fence.md'), contentSha256: stgFenceKn.contentSha256 });
    db2.close();

    const searchFence = JSON.parse(
      execFileSync(process.execPath, [deployedCli, 'search', 'fenceprobe', '--mode', 'literal', '--vault', vaultDir, '--data', dataDir, '--json'], { encoding: 'utf8' })
    );
    assert.equal(searchFence.items.length, 1);
    assert.deepEqual(searchFence.items[0].event_anchors, [`10_Readable_Sessions/${sesFenceName}#^event-000001`]);
    assert.deepEqual(searchFence.items[0].openable_links, [`10_Readable_Sessions/${sesFenceName}#^event-000001`]);

    // (c) Bug F & G3 UI tests: bundle modals.ts & main.ts with a lightweight obsidian shim
    const esbuildPath = path.resolve('plugin/node_modules/esbuild/lib/main.js');
    const { build } = await import(`file:///${esbuildPath.replace(/\\/g, '/')}`);
    const shimDir = path.join(tmp, 'obsidian-shim');
    fs.mkdirSync(shimDir, { recursive: true });
    const shimCode = `
      globalThis.__mindloomTestNotices = globalThis.__mindloomTestNotices || [];
      export const notices = globalThis.__mindloomTestNotices;
      export const openedLinks = [];
      export function createMockEl(tag = 'div') {
        const el = {
          tagName: tag.toUpperCase(),
          textContent: '',
          value: '',
          cls: '',
          style: {},
          title: '',
          disabled: false,
          children: [],
          listeners: new Map(),
          empty() { this.children = []; this.textContent = ''; },
          setText(t) { this.textContent = String(t ?? ''); },
          addClass(c) { this.cls = [this.cls, c].filter(Boolean).join(' '); },
          createEl(t, opts = {}) {
            const child = createMockEl(t);
            if (opts.text !== undefined) child.textContent = String(opts.text);
            if (opts.cls) child.cls = opts.cls;
            if (opts.value !== undefined) child.value = String(opts.value);
            this.children.push(child);
            return child;
          },
          createDiv(opts = {}) { return this.createEl('div', opts); },
          createSpan(opts = {}) { return this.createEl('span', opts); },
          addEventListener(ev, fn) {
            if (!this.listeners.has(ev)) this.listeners.set(ev, []);
            this.listeners.get(ev).push(fn);
          },
          async trigger(ev, evObj = {}) {
            const fns = this.listeners.get(ev) || [];
            for (const fn of fns) await fn({ preventDefault() {}, ...evObj });
          },
          focus() {},
          findAll(pred) {
            const out = [];
            const walk = (n) => {
              if (pred(n)) out.push(n);
              for (const c of n.children) walk(c);
            };
            walk(this);
            return out;
          }
        };
        return el;
      }
      export class Notice { constructor(msg) { notices.push(String(msg)); } }
      export class Modal {
        constructor(app) { this.app = app; this.contentEl = createMockEl('div'); }
        open() { this.onOpen(); }
        close() { this.onClose(); }
        onOpen() {}
        onClose() {}
      }
      export class Plugin {
        constructor(app) { this.app = app; }
        loadData() { return Promise.resolve({}); }
        saveData() { return Promise.resolve(); }
        addStatusBarItem() { return createMockEl('div'); }
        addRibbonIcon() {}
        addCommand() {}
        addSettingTab() {}
        registerView() {}
      }
      export class ItemView { constructor(leaf) { this.leaf = leaf; this.containerEl = { children: [createMockEl('div'), createMockEl('div')] }; } }
      export class PluginSettingTab { constructor(app, plugin) { this.app = app; this.plugin = plugin; this.containerEl = createMockEl('div'); } }
      export class Setting {
        constructor() {}
        setName() { return this; }
        setDesc() { return this; }
        addText(cb) { cb({ setPlaceholder() { return this; }, setValue() { return this; }, onChange() { return this; } }); return this; }
        addButton(cb) { cb({ setButtonText() { return this; }, setCta() { return this; }, onClick() { return this; } }); return this; }
      }
      export class FileSystemAdapter { getBasePath() { return ''; } }
      export class WorkspaceLeaf {}
    `;
    const shimFile = path.join(shimDir, 'obsidian.mjs');
    fs.writeFileSync(shimFile, shimCode, 'utf8');
    const outModals = path.join(tmp, 'modals.mjs');
    const outMain = path.join(tmp, 'main.mjs');
    const aliasPlugin = {
      name: 'obsidian-mock',
      setup(b) {
        b.onResolve({ filter: /^obsidian$/ }, () => ({ path: shimFile }));
      }
    };
    await build({
      entryPoints: [path.resolve('plugin/src/modals.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      outfile: outModals,
      plugins: [aliasPlugin]
    });
    await build({
      entryPoints: [path.resolve('plugin/src/main.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      outfile: outMain,
      plugins: [aliasPlugin]
    });

    const shimMod = await import(`file:///${shimFile.replace(/\\/g, '/')}`);
    const { QuickSearchModal } = await import(`file:///${outModals.replace(/\\/g, '/')}`);
    const { default: MindLoomPlugin } = await import(`file:///${outMain.replace(/\\/g, '/')}`);

    // Test QuickSearchModal never turns blocked item.sources into clickable buttons or Shift+Enter jumps
    const openedTargets = [];
    const fakeBridge = {
      async runJson() {
        return {
          ok: true,
          data: {
            mode: 'literal',
            noAnswer: false,
            items: [
              {
                id: 'KN-1',
                title: 'Blocked Sources Note',
                project: 'P',
                path: '30_Knowledge_Notes/Playbooks/KN-1.md',
                actionable: true,
                sources: ['[[10_Readable_Sessions/SES-PRIVATE#^event-000099]]'],
                event_anchors: [],
                openable_links: []
              },
              {
                id: 'KN-2',
                title: 'Verified Anchor Note',
                project: 'P',
                path: '30_Knowledge_Notes/Playbooks/KN-2.md',
                actionable: true,
                sources: ['[[10_Readable_Sessions/SES-PRIVATE#^event-000099]]'],
                event_anchors: ['10_Readable_Sessions/SES-OK.md#^event-000007'],
                openable_links: ['10_Readable_Sessions/SES-OK.md#^event-000007']
              }
            ]
          }
        };
      }
    };
    const modal = new QuickSearchModal({}, fakeBridge, async (fp, anchor) => {
      openedTargets.push({ fp, anchor: anchor || null });
    });
    modal.open();
    const inputs = modal.contentEl.findAll((n) => n.tagName === 'INPUT');
    const searchInput = inputs[0];
    searchInput.value = 'query';
    await searchInput.trigger('keydown', { key: 'Enter' });

    const buttonsAfterSearch = modal.contentEl.findAll((n) => n.tagName === 'BUTTON');
    const jumpButtons = buttonsAfterSearch.filter((b) => b.textContent.startsWith('Jump ') || b.textContent.startsWith('Open '));
    assert.deepEqual(jumpButtons.map((b) => b.textContent), ['Jump ^event-000007']);

    // Shift+Enter on selected item 0 (which only has blocked sources) must NOT open private anchor!
    await searchInput.trigger('keydown', { key: 'Enter', shiftKey: true });
    assert.deepEqual(openedTargets, [{ fp: '30_Knowledge_Notes/Playbooks/KN-1.md', anchor: null }]);

    // Re-open, move down to item 1, and Shift+Enter -> jumps to verified anchor!
    openedTargets.length = 0;
    modal.open();
    const input2 = modal.contentEl.findAll((n) => n.tagName === 'INPUT')[0];
    input2.value = 'query';
    await input2.trigger('keydown', { key: 'Enter' });
    await input2.trigger('keydown', { key: 'ArrowDown' });
    await input2.trigger('keydown', { key: 'Enter', shiftKey: true });
    assert.deepEqual(openedTargets, [
      { fp: '30_Knowledge_Notes/Playbooks/KN-2.md', anchor: '10_Readable_Sessions/SES-OK.md#^event-000007' }
    ]);

    // Mouse click on Jump button opens verified anchor
    openedTargets.length = 0;
    modal.open();
    const input3 = modal.contentEl.findAll((n) => n.tagName === 'INPUT')[0];
    input3.value = 'query';
    await input3.trigger('keydown', { key: 'Enter' });
    const jumpBtn = modal.contentEl.findAll((n) => n.tagName === 'BUTTON' && n.textContent === 'Jump ^event-000007')[0];
    await jumpBtn.trigger('click');
    assert.deepEqual(openedTargets, [
      { fp: '30_Knowledge_Notes/Playbooks/KN-2.md', anchor: '10_Readable_Sessions/SES-OK.md#^event-000007' }
    ]);

    // Test Bug G3: MindLoomPlugin.runSyncAndRebuildMoc surfaces sync warnings/errors separately and avoids duplicate rebuild
    const fakeApp = {
      vault: { adapter: {}, getAbstractFileByPath: () => null },
      workspace: { getLeavesOfType: () => [], onLayoutReady: () => {} }
    };
    const plugin = new MindLoomPlugin(fakeApp, { id: 'mindloom', name: 'MindLoom', version: '1.0.0' });
    plugin.statusBarEl = shimMod.createMockEl('div');
    const calls = [];
    plugin.bridge = {
      resolvePaths: () => ({ dataPath: '' }),
      readLastAutoSyncTime: () => null,
      async runJson(args) {
        calls.push(args);
        if (args[0] === 'auto-sync') {
          return { ok: true, data: { syncedCount: 0, errorsCount: 2, skippedUnapprovedCount: 1, skippedUnmappedCount: 3, mocUpdated: false } };
        }
        return { ok: true, data: { projectsCount: 1, sanitizedNotesCount: 4 } };
      }
    };
    shimMod.notices.length = 0;
    await plugin.runSyncAndRebuildMoc();
    assert.deepEqual(calls, [['auto-sync', '--no-moc'], ['render-moc', '--update-digests']]);
    assert.ok(shimMod.notices.some((n) => n.includes('errors=2') && n.includes('unapproved=1')));
    assert.ok(shimMod.notices.some((n) => n.includes('MOC rebuilt:')));

    // When auto-sync reports mocUpdated=true, render-moc must NOT be called a second time
    calls.length = 0;
    shimMod.notices.length = 0;
    plugin.bridge.runJson = async (args) => {
      calls.push(args);
      return { ok: true, data: { syncedCount: 1, errorsCount: 0, skippedUnapprovedCount: 0, skippedUnmappedCount: 0, mocUpdated: true } };
    };
    await plugin.runSyncAndRebuildMoc();
    assert.deepEqual(calls, [['auto-sync', '--no-moc']]);
    assert.ok(shimMod.notices.some((n) => n.includes('already updated')));
  });
});
