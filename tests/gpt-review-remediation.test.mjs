import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { initRepository } from '../src/init.mjs';
import { initGitRepo, commitPublishedFile } from '../src/git/repo-manager.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { writeInstallConfig, readInstallConfig } from '../src/config/paths.mjs';
import { deployCompanionPlugin } from '../src/setup/wizard.mjs';
import { runDeploy } from '../cli/deploy.mjs';
import { stageCandidate, publishFile, recoverInterruptedPublish } from '../src/storage/atomic-publisher.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { rebuildVaultMocAndHome } from '../src/ingest/human-digest.mjs';
import { evaluateSanitizedVisibility } from '../src/security/privacy-gate.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

test('GPT Architectural Review Remediations (P1 publish recovery, whole-vault restore & switch, MOC withdrawal)', async (t) => {
  await t.test('1. [P1 #1] publishFile commits atomically and recover-publish heals orphan files_published intents', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-gpt-p1-pub-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultDir = path.join(tmp, 'Vault');
    const dataDir = path.join(tmp, 'Vault-Data');
    const cfgPath = path.join(tmp, 'cfg.json');
    initRepository({ vaultPath: vaultDir, dataPath: dataDir });
    writeInstallConfig({ vaultPath: vaultDir, dataPath: dataDir, configPath: cfgPath });

    const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
    const stagingDir = path.join(dataDir, 'staging');
    const db = openExistingDatabase(dbPath);
    try {
      // Simulate historical partial-failure state: file written on disk, publish_intents = 'files_published', notes missing row
      const orphanUuid = 'KN-019316a8-aaaa-7000-8000-111111111111';
      const orphanPath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-20261116-111111_Orphan.md');
      const orphanContent = `---
schema_version: 1
id: "${orphanUuid}"
note_type: "playbook"
title: "Orphan Published Playbook"
project: "RecoveryOps"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "windows"
created_at: "2026-11-16T00:00:00Z"
---
OrphanKeywordToken
<!-- user appended local note -->
`;
      fs.writeFileSync(orphanPath, orphanContent, 'utf8');
      const sha = crypto.createHash('sha256').update(orphanContent, 'utf8').digest('hex');
      db.prepare(`
        INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
        VALUES ('op-orphan-pub', ?, ?, ?, ?, 'files_published', datetime('now'), datetime('now'))
      `).run(orphanUuid, path.join(stagingDir, `stg-${orphanUuid}.md`), orphanPath, sha);

      // Before recovery: search sees it only as unregistered_note_pending_enrollment (Channel 2)
      const preSearch = searchKnowledge({ db, vaultDir, query: 'OrphanKeywordToken' });
      assert.equal(preSearch.items.length, 1);
      assert.equal(preSearch.items[0].actionable, false);
      assert.equal(preSearch.items[0].reason, 'unregistered_note_pending_enrollment');
    } finally {
      db.close();
    }

    const env = { ...process.env, MINDLOOM_CONFIG: cfgPath };
    const doctorBefore = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'doctor', '--vault', vaultDir, '--data', dataDir, '--json'], {
        env,
        encoding: 'utf8'
      })
    );
    assert.equal(doctorBefore.pendingMissingNoteRecords, 1);
    assert.equal(doctorBefore.dbStatus, 'pending_recovery');

    // Run mem recover-publish -> heals orphan without overwriting user edits
    const recOut = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'recover-publish', '--vault', vaultDir, '--data', dataDir, '--json'], {
        env,
        encoding: 'utf8'
      })
    );
    assert.equal(recOut.recovered, true);
    assert.equal(recOut.count, 1);
    assert.equal(recOut.details[0].action, 'reconciled_missing_note_record');

    const dbCheck = openExistingDatabase(dbPath, { readOnly: true });
    try {
      const noteRow = dbCheck.prepare('SELECT id, status, review_state, privacy FROM notes WHERE id = ?').get(
        'KN-019316a8-aaaa-7000-8000-111111111111'
      );
      assert.equal(noteRow?.status, 'active');
      assert.equal(noteRow?.review_state, 'accepted');
      assert.equal(noteRow?.privacy, 'sanitized');

      const postSearch = searchKnowledge({ db: dbCheck, vaultDir, query: 'OrphanKeywordToken' });
      assert.equal(postSearch.items.length, 1);
      assert.equal(postSearch.items[0].actionable, true);
    } finally {
      dbCheck.close();
    }

    // Deleted note must NEVER be resurrected by recoverInterruptedPublish
    const dbDel = openExistingDatabase(dbPath);
    try {
      const delUuid = 'KN-019316a8-bbbb-7000-8000-222222222222';
      dbDel.prepare(`
        INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at)
        VALUES (?, 'playbook', 'Deleted Note', 'RecoveryOps', 'sanitized', ?, 'sha', 'deleted', datetime('now'))
      `).run(delUuid, path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'deleted.md'));
      dbDel.prepare(`
        INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
        VALUES ('op-del-intent', ?, 's', ?, 'sha', 'files_published', datetime('now'), datetime('now'))
      `).run(delUuid, path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'deleted.md'));
      const secondRec = recoverInterruptedPublish({ db: dbDel });
      assert.equal(secondRec.count, 0);

      // Atomic rollback check: if notes INSERT fails inside publishFile's SAVEPOINT, publish_intents must roll back to 'linking'
      const rollbackUuid = 'KN-019316a8-cccc-7000-8000-333333333333';
      const rbTarget = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-rollback.md');
      const rbContent = `---\nschema_version: 1\nid: "${rollbackUuid}"\nnote_type: "playbook"\ntitle: "RB"\nproject: "P"\nprivacy: "sanitized"\n---\nbody\n`;
      const rbStg = stageCandidate({ stagingDir, outputUuid: rollbackUuid, content: rbContent });
      dbDel.exec(`
        CREATE TEMP TRIGGER abort_notes_insert BEFORE INSERT ON notes
        WHEN NEW.id = '${rollbackUuid}'
        BEGIN
          SELECT RAISE(ABORT, 'simulated_notes_insert_failure');
        END;
      `);
      assert.throws(() =>
        publishFile({
          db: dbDel,
          operationId: 'op-rb-fail',
          outputUuid: rollbackUuid,
          stagingPath: rbStg.stagingPath,
          vaultTargetPath: rbTarget,
          contentSha256: rbStg.contentSha256
        }),
        /simulated_notes_insert_failure/
      );
      dbDel.exec('DROP TRIGGER temp.abort_notes_insert;');
      const rbIntent = dbDel.prepare('SELECT state FROM publish_intents WHERE operation_id = ?').get('op-rb-fail');
      assert.equal(rbIntent?.state, 'linking');
      assert.equal(dbDel.prepare('SELECT id FROM notes WHERE id = ?').get(rollbackUuid), undefined);

      // Now recoverInterruptedPublish heals it cleanly once DB is healthy
      const rbHealed = recoverInterruptedPublish({ db: dbDel, operationId: 'op-rb-fail' });
      assert.equal(rbHealed.recovered, true);
      assert.equal(dbDel.prepare('SELECT state FROM publish_intents WHERE operation_id = ?').get('op-rb-fail')?.state, 'files_published');
      assert.equal(dbDel.prepare('SELECT status FROM notes WHERE id = ?').get(rollbackUuid)?.status, 'active');
    } finally {
      dbDel.close();
    }
  });

  await t.test('2. [P1 #2] mem restore-backup rebinds internal manifests/plugin config without hijacking default, and mem use switches explicitly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-gpt-p1-rest-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const origVault = path.join(tmp, 'OrigVault');
    const origData = path.join(tmp, 'OrigVault-Data');
    const bkpRoot = path.join(tmp, 'Backups');
    const restVault = path.join(tmp, 'RestoredVault');
    const restData = path.join(tmp, 'RestoredVault-Data');
    const cfgPath = path.join(tmp, 'global-config.json');

    initRepository({ vaultPath: origVault, dataPath: origData });
    initGitRepo(origVault);
    writeInstallConfig({ vaultPath: origVault, dataPath: origData, configPath: cfgPath });
    fs.writeFileSync(
      path.join(origData, 'manifests', 'auto-sync-config.json'),
      JSON.stringify({ version: 1, vaultDir: origVault, dataDir: origData }, null, 2),
      'utf8'
    );
    const pluginDir = path.join(origVault, '.obsidian', 'plugins', 'mindloom');
    fs.mkdirSync(pluginDir, { recursive: true });
    fs.writeFileSync(
      path.join(pluginDir, 'data.json'),
      JSON.stringify({ vaultPath: origVault, dataPath: origData, cliPath: path.join(origData, 'cli', 'mem.mjs') }, null, 2),
      'utf8'
    );

    const db = openExistingDatabase(path.join(origData, 'runtime', 'state.sqlite'));
    try {
      const id = 'KN-019316a8-dddd-7000-8000-444444444444';
      const notePath = path.join(origVault, '30_Knowledge_Notes', 'Playbooks', 'KN-backup-note.md');
      const content = `---\nschema_version: 1\nid: "${id}"\nnote_type: "playbook"\ntitle: "Backup Search Note"\nproject: "Bkp"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\n---\nRestoreSelfCheckNeedle\n`;
      const stg = stageCandidate({ stagingDir: path.join(origData, 'staging'), outputUuid: id, content });
      publishFile({
        db,
        operationId: 'op-bkp-1',
        outputUuid: id,
        stagingPath: stg.stagingPath,
        vaultTargetPath: notePath,
        contentSha256: stg.contentSha256
      });
      commitPublishedFile({ vaultDir: origVault, filePath: notePath, commitMessage: 'add backup note' });
    } finally {
      db.close();
    }

    const env = { ...process.env, MINDLOOM_CONFIG: cfgPath };
    const bkpRes = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'backup', '--target', bkpRoot, '--approve-plugin-data', 'mindloom', '--json'], { env, encoding: 'utf8' })
    );
    assert.equal(bkpRes.status, 'complete');

    const restOut = JSON.parse(
      execFileSync(
        process.execPath,
        [
          CLI_PATH,
          'restore-backup',
          '--backup',
          bkpRes.backupDir,
          '--vault',
          restVault,
          '--data',
          restData,
          '--self-check',
          'RestoreSelfCheckNeedle',
          '--json'
        ],
        { env, encoding: 'utf8' }
      )
    );
    assert.equal(restOut.restored, true);
    assert.equal(restOut.switched, false);
    assert.equal(restOut.verification.selfCheckHits, 1);
    assert.equal(restOut.reboundConfig.autoSyncConfigRebound, true);
    assert.equal(restOut.reboundConfig.pluginDataRebound, true);

    // Internal files inside restored copy are rebound to RestoredVault / RestoredVault-Data
    const restInstall = readInstallConfig(path.join(restData, 'manifests', 'install-config.json'));
    assert.equal(path.resolve(restInstall.vaultPath), path.resolve(restVault));
    assert.equal(path.resolve(restInstall.dataPath), path.resolve(restData));
    const restAutoSync = JSON.parse(fs.readFileSync(path.join(restData, 'manifests', 'auto-sync-config.json'), 'utf8'));
    assert.equal(path.resolve(restAutoSync.vaultDir), path.resolve(restVault));
    assert.equal(path.resolve(restAutoSync.dataDir), path.resolve(restData));
    const restPlugin = JSON.parse(fs.readFileSync(path.join(restVault, '.obsidian', 'plugins', 'mindloom', 'data.json'), 'utf8'));
    assert.equal(path.resolve(restPlugin.vaultPath), path.resolve(restVault));
    assert.equal(path.resolve(restPlugin.dataPath), path.resolve(restData));
    assert.equal(path.resolve(restPlugin.cliPath), path.resolve(path.join(restData, 'cli', 'mem.mjs')));

    // Host default config STILL points to OrigVault unless explicitly switched
    const globalBeforeSwitch = readInstallConfig(cfgPath);
    assert.equal(path.resolve(globalBeforeSwitch.vaultPath), path.resolve(origVault));

    // Explicit `mem use` validates pairing and switches global default
    const useOut = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'use', '--vault', restVault, '--data', restData, '--json'], {
        env,
        encoding: 'utf8'
      })
    );
    assert.equal(useOut.switched, true);
    assert.equal(path.resolve(readInstallConfig(cfgPath).vaultPath), path.resolve(restVault));
    assert.equal(path.resolve(readInstallConfig(cfgPath).dataPath), path.resolve(restData));
  });

  await t.test('2b. [Panel C] Default backup (without --approve-plugin-data) + arbitrary restored directory names generates local MindLoom data.json so CliBridge resolves new Data cleanly', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-gpt-def-rest-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const origVault = path.join(tmp, 'LiveVault');
    const origData = path.join(tmp, 'LiveDataBucket');
    const bkpRoot = path.join(tmp, 'Backups');
    const restVault = path.join(tmp, 'RestoredCustomV');
    const restData = path.join(tmp, 'ArbitraryDataStore'); // intentionally NOT RestoredCustomV-Data
    const cfgPath = path.join(tmp, 'global-config.json');

    initRepository({ vaultPath: origVault, dataPath: origData });
    initGitRepo(origVault);
    writeInstallConfig({ vaultPath: origVault, dataPath: origData, configPath: cfgPath });
    runDeploy({ repoRoot: path.resolve('.'), targetDir: path.join(origData, 'cli'), apply: true });
    deployCompanionPlugin({ vaultPath: origVault, dataPath: origData });

    const env = { ...process.env, MINDLOOM_CONFIG: cfgPath };
    // Default backup per README (NO --approve-plugin-data) -> data.json excluded from backup
    const bkpRes = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'backup', '--target', bkpRoot, '--json'], { env, encoding: 'utf8' })
    );
    assert.equal(bkpRes.status, 'complete');
    assert.ok(bkpRes.excludedPluginConfigsCount >= 1);

    // Restore to arbitrarily named directories WITHOUT --switch
    const restOut = JSON.parse(
      execFileSync(
        process.execPath,
        [CLI_PATH, 'restore-backup', '--backup', bkpRes.backupDir, '--vault', restVault, '--data', restData, '--json'],
        { env, encoding: 'utf8' }
      )
    );
    assert.equal(restOut.restored, true);
    assert.equal(restOut.switched, false);
    assert.equal(restOut.reboundConfig.pluginDataRebound, true);
    assert.equal(restOut.reboundConfig.pluginDataGenerated, true);

    // Global default config stays bound to LiveVault / LiveDataBucket
    assert.equal(path.resolve(readInstallConfig(cfgPath).vaultPath), path.resolve(origVault));
    assert.equal(path.resolve(readInstallConfig(cfgPath).dataPath), path.resolve(origData));

    // Bundle plugin/src/cli-bridge.ts with mock obsidian and verify live CliBridge resolution for BOTH Vaults!
    const esbuildPath = path.resolve('plugin/node_modules/esbuild/lib/main.js');
    const { build } = await import(`file:///${esbuildPath.replace(/\\/g, '/')}`);
    const bundleOut = path.join(tmp, 'cli-bridge-bundle.mjs');
    await build({
      entryPoints: [path.resolve('plugin/src/cli-bridge.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      external: ['node:*'],
      outfile: bundleOut
    });
    const { CliBridge } = await import(`file:///${bundleOut.replace(/\\/g, '/')}`);

    const readPluginSettings = (vPath) =>
      JSON.parse(fs.readFileSync(path.join(vPath, '.obsidian', 'plugins', 'mindloom', 'data.json'), 'utf8'));

    const origBridge = new CliBridge(() => readPluginSettings(origVault), () => origVault);
    const restBridge = new CliBridge(() => readPluginSettings(restVault), () => restVault);

    const origResolved = origBridge.resolvePaths();
    const restResolved = restBridge.resolvePaths();
    assert.equal(path.resolve(origResolved.dataPath), path.resolve(origData));
    assert.equal(path.resolve(restResolved.vaultPath), path.resolve(restVault));
    assert.equal(path.resolve(restResolved.dataPath), path.resolve(restData));
    assert.equal(path.resolve(restResolved.cliPath), path.resolve(path.join(restData, 'cli', 'mem.mjs')));

    const origStatus = await origBridge.runJson(['status']);
    const restStatus = await restBridge.runJson(['status']);
    assert.equal(origStatus.ok, true);
    assert.equal(restStatus.ok, true);
  });

  await t.test('3. [P1 #3 & Panel B] MOC rebuild & mem delete withdraw stale generated MOC pages while preserving BOTH same-name and different-name handwritten pages cleanly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-gpt-p1-moc-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultDir = path.join(tmp, 'Vault');
    const dataDir = path.join(tmp, 'Vault-Data');
    const cfgPath = path.join(tmp, 'cfg.json');
    initRepository({ vaultPath: vaultDir, dataPath: dataDir });
    initGitRepo(vaultDir);
    execFileSync('git', ['add', '首页.md'], { cwd: vaultDir });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: vaultDir });
    writeInstallConfig({ vaultPath: vaultDir, dataPath: dataDir, configPath: cfgPath });

    const manualMocPath = path.join(vaultDir, '00_MOC', 'HandwrittenManualNotes.md');
    const sameNameManualPath = path.join(vaultDir, '00_MOC', 'AlphaProj.md');
    const sameNameManualContent = '# AlphaProj 手写个人索引\n\n用户亲自撰写的内容，绝不能被同名覆盖。\n';
    fs.mkdirSync(path.dirname(manualMocPath), { recursive: true });
    fs.writeFileSync(manualMocPath, '# 手写个人 MOC\n\n用户自己写的索引不应被删除。\n', 'utf8');
    fs.writeFileSync(sameNameManualPath, sameNameManualContent, 'utf8');

    const db = openExistingDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));
    const alphaId = 'KN-019316a8-eeee-7000-8000-555555555555';
    const betaId = 'KN-019316a8-ffff-7000-8000-666666666666';
    const alphaPath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-alpha.md');
    const betaPath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-beta.md');
    try {
      for (const [id, proj, notePath] of [
        [alphaId, 'AlphaProj', alphaPath],
        [betaId, 'BetaProj', betaPath]
      ]) {
        const content = `---\nschema_version: 1\nid: "${id}"\nnote_type: "playbook"\ntitle: "${proj} Note"\nproject: "${proj}"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\n---\n${proj} content\n`;
        const stg = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: id, content });
        publishFile({
          db,
          operationId: `op-${proj}`,
          outputUuid: id,
          stagingPath: stg.stagingPath,
          vaultTargetPath: notePath,
          contentSha256: stg.contentSha256
        });
        commitPublishedFile({ vaultDir, filePath: notePath, commitMessage: `add ${proj}` });
      }

      const moc1 = rebuildVaultMocAndHome({ db, vaultDir });
      assert.equal(moc1.projectsCount, 2);
      // Same-name handwritten file is preserved untouched, while MindLoom uses stable fallback AlphaProj__mindloom-moc.md
      assert.equal(fs.readFileSync(sameNameManualPath, 'utf8'), sameNameManualContent);
      assert.equal(fs.existsSync(path.join(vaultDir, '00_MOC', 'AlphaProj__mindloom-moc.md')), true);
      assert.equal(fs.existsSync(path.join(vaultDir, '00_MOC', 'BetaProj.md')), true);
      assert.equal(moc1.mocConflicts.length, 1);
      assert.equal(moc1.mocConflicts[0].resolvedFile, '00_MOC/AlphaProj__mindloom-moc.md');
      assert.match(fs.readFileSync(path.join(vaultDir, '首页.md'), 'utf8'), /\[\[00_MOC\/AlphaProj__mindloom-moc\|AlphaProj\]\]/);

      // Second rebuild is idempotent: no duplicate files generated and same-name handwritten file still intact
      const mocRepeat = rebuildVaultMocAndHome({ db, vaultDir });
      assert.equal(mocRepeat.projectsCount, 2);
      assert.equal(fs.readFileSync(sameNameManualPath, 'utf8'), sameNameManualContent);
      const mocFiles = fs.readdirSync(path.join(vaultDir, '00_MOC')).filter((f) => f.includes('AlphaProj'));
      assert.deepEqual(mocFiles.sort(), ['AlphaProj.md', 'AlphaProj__mindloom-moc.md']);
    } finally {
      db.close();
    }

    // 1) mem delete --confirm on last AlphaProj note withdraws ONLY the generated fallback page, keeping BOTH handwritten files
    const env = { ...process.env, MINDLOOM_CONFIG: cfgPath };
    execFileSync(process.execPath, [CLI_PATH, 'delete', alphaId, '--confirm'], { env, encoding: 'utf8' });
    assert.equal(fs.existsSync(path.join(vaultDir, '00_MOC', 'AlphaProj__mindloom-moc.md')), false, '撤回最后一条后旧生成项目 MOC 页必须同步撤下');
    assert.equal(fs.readFileSync(sameNameManualPath, 'utf8'), sameNameManualContent, '撤回不得删除同名手写 MOC 页');
    assert.equal(fs.existsSync(manualMocPath), true, '用户异名手写 00_MOC 页面必须完整保留');
    assert.doesNotMatch(fs.readFileSync(path.join(vaultDir, '首页.md'), 'utf8'), /AlphaProj/);

    // 2) Downgrading BetaProj note to local_only on disk causes rebuildVaultMocAndHome to withdraw BetaProj.md via shared visibility gate
    const db2 = openExistingDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));
    try {
      const betaRaw = fs.readFileSync(betaPath, 'utf8').replace('privacy: "sanitized"', 'privacy: "local_only"');
      fs.writeFileSync(betaPath, betaRaw, 'utf8');
      const gate = evaluateSanitizedVisibility({
        raw: betaRaw,
        frontmatter: { privacy: 'local_only' },
        checkResidualSecrets: true
      });
      assert.equal(gate.allowed, false);

      const moc2 = rebuildVaultMocAndHome({ db: db2, vaultDir });
      assert.deepEqual(moc2.withdrawnMocs, ['00_MOC/BetaProj.md']);
      assert.equal(fs.existsSync(path.join(vaultDir, '00_MOC', 'BetaProj.md')), false);
      assert.equal(fs.existsSync(manualMocPath), true);
    } finally {
      db2.close();
    }
  });
});
