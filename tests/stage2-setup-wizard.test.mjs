import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  runSetupWizard,
  discoverCandidateWorkspaces,
  extractAntigravityCwdHint,
  deployCompanionPlugin
} from '../src/setup/wizard.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { runWhitelistAutoSync } from '../src/ingest/auto-sync.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');
const INSTALL_PS1 = path.resolve('scripts/install.ps1');
const INSTALL_SH = path.resolve('scripts/install.sh');

test('Stage 2: One-Click Setup Wizard, Workspace Discovery, Plugin Merge & EXIT 43 Guard', async (t) => {
  await t.test('1. mem setup --yes initializes clean Vault + Data, discovers workspaces, and injects plugin', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-setup-clean-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultPath = path.join(tmp, 'MindLoom');
    const dataPath = path.join(tmp, 'MindLoom-Data');
    const configPath = path.join(tmp, 'home', '.mindloom', 'config.json');
    const codexHome = path.join(tmp, 'home', '.codex', 'sessions');
    const agyBrain = path.join(tmp, 'home', '.gemini', 'antigravity', 'brain');
    const projDir = path.join(tmp, 'workspace', 'rocket-api');
    fs.mkdirSync(path.join(projDir, '.git'), { recursive: true });
    fs.mkdirSync(codexHome, { recursive: true });
    fs.mkdirSync(agyBrain, { recursive: true });

    const rolloutFile = path.join(codexHome, 'rollout-2026-11-16T01-00-00-019316a8-1111-7000-8000-000000000001.jsonl');
    fs.writeFileSync(
      rolloutFile,
      [
        JSON.stringify({ type: 'session_meta', payload: { id: '019316a8-1111-7000-8000-000000000001', cwd: path.join(projDir, 'src') } }),
        JSON.stringify({ type: 'event_msg', payload: { type: 'user_message', message: 'check api' } })
      ].join('\n') + '\n',
      'utf8'
    );

    const discovered = discoverCandidateWorkspaces({
      sourceRoots: {
        codexHome,
        codexArchivedDir: null,
        antigravityBrainDir: agyBrain
      },
      homeDir: path.join(tmp, 'home'),
      includeDsh: false
    });
    assert.equal(discovered.length, 1);
    assert.equal(discovered[0].project, 'RocketApi');
    assert.deepEqual(discovered[0].git_roots, [path.resolve(projDir)]);

    const res = await runSetupWizard({
      vaultPath,
      dataPath,
      configPath,
      yes: true,
      homeDir: path.join(tmp, 'home'),
      sourceRoots: {
        codexHome,
        codexArchivedDir: null,
        antigravityBrainDir: agyBrain,
        dshHome: path.join(tmp, 'empty-dsh')
      }
    });

    assert.equal(res.ok, true);
    assert.equal(res.initStatus, 'initialized');
    assert.ok(fs.existsSync(path.join(dataPath, 'runtime', 'state.sqlite')));
    assert.ok(fs.existsSync(path.join(dataPath, 'cli', 'cli', 'mem.mjs')));
    assert.ok(fs.existsSync(path.join(dataPath, 'manifests', 'install-config.json')));
    assert.ok(fs.existsSync(configPath));

    const pmap = JSON.parse(fs.readFileSync(path.join(dataPath, 'manifests', 'project-map.json'), 'utf8'));
    assert.ok(pmap.projects.some((p) => p.project === 'RocketApi'));

    assert.equal(res.plugin.deployed, true);
    assert.ok(fs.existsSync(path.join(vaultPath, '.obsidian', 'plugins', 'mindloom', 'main.js')));
    assert.ok(fs.existsSync(path.join(vaultPath, '.obsidian', 'plugins', 'mindloom', 'manifest.json')));
    assert.ok(fs.existsSync(path.join(vaultPath, '.obsidian', 'plugins', 'mindloom', 'styles.css')));
    const enabled = JSON.parse(fs.readFileSync(path.join(vaultPath, '.obsidian', 'community-plugins.json'), 'utf8'));
    assert.deepEqual(enabled, ['mindloom']);
  });

  await t.test('2. setup preserves existing third-party plugins in community-plugins.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-setup-merge-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultPath = path.join(tmp, 'Vault');
    const dataPath = path.join(tmp, 'Vault-Data');
    const configPath = path.join(tmp, 'config.json');

    // First setup
    await runSetupWizard({
      vaultPath,
      dataPath,
      configPath,
      yes: true,
      sourceRoots: {
        codexHome: path.join(tmp, 'no-cdx'),
        codexArchivedDir: null,
        antigravityBrainDir: path.join(tmp, 'no-agy'),
        dshHome: path.join(tmp, 'no-dsh')
      }
    });

    // Simulate user installing third-party plugins before re-running setup
    const cpPath = path.join(vaultPath, '.obsidian', 'community-plugins.json');
    fs.writeFileSync(cpPath, JSON.stringify(['dataview', 'templater-obsidian'], null, 2) + '\n', 'utf8');

    const res2 = await runSetupWizard({
      vaultPath,
      dataPath,
      configPath,
      yes: true,
      sourceRoots: {
        codexHome: path.join(tmp, 'no-cdx'),
        codexArchivedDir: null,
        antigravityBrainDir: path.join(tmp, 'no-agy'),
        dshHome: path.join(tmp, 'no-dsh')
      }
    });

    assert.equal(res2.initStatus, 'already_initialized');
    const merged = JSON.parse(fs.readFileSync(cpPath, 'utf8'));
    assert.deepEqual(merged, ['dataview', 'templater-obsidian', 'mindloom']);
  });

  await t.test('3. CLI setup --authorize-autosync and install.ps1 reject ANTIGRAVITY_AGENT=1 with EXIT 43', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-setup-43-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultPath = path.join(tmp, 'Vault');
    const dataPath = path.join(tmp, 'Vault-Data');

    const cliRes = spawnSync(
      process.execPath,
      [CLI_PATH, 'setup', '--vault', vaultPath, '--data', dataPath, '--yes', '--authorize-autosync'],
      {
        encoding: 'utf8',
        env: { ...process.env, ANTIGRAVITY_AGENT: '1', MINDLOOM_CONFIG: path.join(tmp, 'cfg.json') }
      }
    );
    assert.equal(cliRes.status, 43, `Expected EXIT 43 from mem setup, got ${cliRes.status}: ${cliRes.stderr}`);
    assert.match(`${cliRes.stderr}\n${cliRes.stdout}`, /EXIT 43/);
    // Fail-fast guarantee: EXIT 43 must not create Vault or Data directories
    assert.equal(fs.existsSync(vaultPath), false);
    assert.equal(fs.existsSync(dataPath), false);

    if (process.platform === 'win32') {
      const astOut = execFileSync(
        'pwsh',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('${INSTALL_PS1.replace(/'/g, "''")}', [ref]$null, [ref]$e); if($e.Count -gt 0){throw ($e|Out-String)}; 'AST_OK'`
        ],
        { encoding: 'utf8' }
      );
      assert.match(astOut, /AST_OK/);

      const psRes = spawnSync(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-File', INSTALL_PS1, '-AuthorizeAutoSync', '-VaultDir', vaultPath, '-DataDir', dataPath],
        {
          encoding: 'utf8',
          env: { ...process.env, ANTIGRAVITY_AGENT: '1' }
        }
      );
      assert.equal(psRes.status, 43, `Expected EXIT 43 from install.ps1, got ${psRes.status}: ${psRes.stderr}`);
    }

    assert.ok(fs.existsSync(INSTALL_SH));
    const shText = fs.readFileSync(INSTALL_SH, 'utf8');
    assert.match(shText, /exit 43/);
    assert.match(shText, /ANTIGRAVITY_AGENT/);
  });

  await t.test('4. Antigravity discovery decodes JSON \\n escapes, and re-running setup refreshes plugin data.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-setup-agy-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const agyBrain = path.join(tmp, 'home', '.gemini', 'antigravity', 'brain');
    const sessDir = path.join(agyBrain, '33333333-3333-4333-8333-333333333333', '.system_generated', 'logs');
    const pkgProj = path.join(tmp, 'pkg-only-proj');
    const gitProj = path.join(tmp, 'git-sub-proj');
    const gitSub = path.join(gitProj, 'packages', 'web');
    fs.mkdirSync(sessDir, { recursive: true });
    fs.mkdirSync(pkgProj, { recursive: true });
    fs.mkdirSync(path.join(gitProj, '.git'), { recursive: true });
    fs.mkdirSync(gitSub, { recursive: true });
    fs.writeFileSync(path.join(pkgProj, 'package.json'), '{"name":"pkg-only-proj"}\n', 'utf8');

    const transcript1 = path.join(sessDir, 'transcript.jsonl');
    fs.writeFileSync(
      transcript1,
      JSON.stringify({
        type: 'user',
        content: `Active Workspaces:\n- ${pkgProj}\nCommand Working Directory: ${pkgProj}\nFiles relating to the user request`
      }) + '\n',
      'utf8'
    );
    // Must decode JSON \\ and stop cleanly before \n so non-git paths match exact directory
    assert.equal(extractAntigravityCwdHint(transcript1), pkgProj);

    // Overwrite transcript to point to gitSub for full discoverCandidateWorkspaces + runSetupWizard check
    fs.writeFileSync(
      transcript1,
      JSON.stringify({
        type: 'user',
        content: `Active Workspaces:\n- ${gitSub}\nCommand Working Directory: ${gitSub}\nFiles relating to the user request`
      }) + '\n',
      'utf8'
    );

    const discovered = discoverCandidateWorkspaces({
      sourceRoots: {
        codexHome: path.join(tmp, 'no-codex'),
        codexArchivedDir: null,
        antigravityBrainDir: agyBrain,
        dshHome: path.join(tmp, 'no-dsh')
      },
      homeDir: path.join(tmp, 'home'),
      includeDsh: false
    });
    assert.equal(discovered.length, 1);
    assert.equal(discovered[0].project, 'GitSubProj');

    const vaultPath = path.join(tmp, 'Vault');
    const dataPath1 = path.join(tmp, 'Vault-Data-1');
    const vaultPath2 = path.join(tmp, 'Vault2');
    const dataPath2 = path.join(tmp, 'Vault-Data-2');
    const cfgPath = path.join(tmp, 'cfg.json');

    await runSetupWizard({
      vaultPath,
      dataPath: dataPath1,
      configPath: cfgPath,
      yes: true,
      homeDir: path.join(tmp, 'home'),
      sourceRoots: { codexHome: path.join(tmp, 'no-codex'), codexArchivedDir: null, antigravityBrainDir: agyBrain, dshHome: path.join(tmp, 'no-dsh') }
    });

    // Simulate stale data.json paths in Vault plugin config, then re-run setup on the same pair
    const pluginDataFile = path.join(vaultPath, '.obsidian', 'plugins', 'mindloom', 'data.json');
    const stale = JSON.parse(fs.readFileSync(pluginDataFile, 'utf8'));
    stale.dataPath = path.join(tmp, 'Stale-Data');
    stale.cliPath = path.join(tmp, 'Stale-Data', 'cli', 'mem.mjs');
    fs.writeFileSync(pluginDataFile, JSON.stringify(stale, null, 2), 'utf8');

    await runSetupWizard({
      vaultPath,
      dataPath: dataPath1,
      configPath: cfgPath,
      yes: true,
      homeDir: path.join(tmp, 'home'),
      sourceRoots: { codexHome: path.join(tmp, 'no-codex'), codexArchivedDir: null, antigravityBrainDir: agyBrain, dshHome: path.join(tmp, 'no-dsh') }
    });

    const refreshed = JSON.parse(fs.readFileSync(pluginDataFile, 'utf8'));
    assert.equal(refreshed.dataPath, path.resolve(dataPath1));
    assert.equal(refreshed.cliPath, path.join(path.resolve(dataPath1), 'cli', 'mem.mjs'));

    // Also verify interactive promptFn declining discovered workspaces leaves project-map empty
    await runSetupWizard({
      vaultPath: vaultPath2,
      dataPath: dataPath2,
      configPath: cfgPath,
      yes: false,
      isTty: true,
      promptFn: async () => 'n',
      homeDir: path.join(tmp, 'home'),
      sourceRoots: { codexHome: path.join(tmp, 'no-codex'), codexArchivedDir: null, antigravityBrainDir: agyBrain, dshHome: path.join(tmp, 'no-dsh') }
    });
    const pmap2 = JSON.parse(fs.readFileSync(path.join(dataPath2, 'manifests', 'project-map.json'), 'utf8'));
    assert.equal(pmap2.projects.length, 0);
  });

  await t.test('5. [Bug B] Setup rejects same-dir, nested (both ways), symlink/junction aliases, and empty-vault mismatch with zero writes', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-setup-iso-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
    const noSources = {
      codexHome: path.join(tmp, 'no-cdx'),
      codexArchivedDir: null,
      antigravityBrainDir: path.join(tmp, 'no-agy'),
      dshHome: path.join(tmp, 'no-dsh')
    };
    const cfgSentinel = path.join(tmp, 'sentinel-cfg.json');
    fs.writeFileSync(cfgSentinel, '{"keep":"original"}\n', 'utf8');

    // (a) Same path
    const sameDir = path.join(tmp, 'SameDir');
    await assert.rejects(
      () => runSetupWizard({ vaultPath: sameDir, dataPath: sameDir, configPath: cfgSentinel, yes: true, sourceRoots: noSources }),
      /ERR_VAULT_DATA_NESTED/
    );
    assert.equal(fs.existsSync(sameDir), false);
    assert.equal(fs.readFileSync(cfgSentinel, 'utf8'), '{"keep":"original"}\n');

    // (b) Data inside Vault
    const vaultA = path.join(tmp, 'VaultA');
    const nestedData = path.join(vaultA, 'MindLoom-Data');
    await assert.rejects(
      () => runSetupWizard({ vaultPath: vaultA, dataPath: nestedData, configPath: cfgSentinel, yes: true, sourceRoots: noSources }),
      /ERR_VAULT_DATA_NESTED/
    );
    assert.equal(fs.existsSync(vaultA), false);

    // (c) Vault inside Data
    const dataB = path.join(tmp, 'DataB');
    const nestedVault = path.join(dataB, 'Vault');
    await assert.rejects(
      () => runSetupWizard({ vaultPath: nestedVault, dataPath: dataB, configPath: cfgSentinel, yes: true, sourceRoots: noSources }),
      /ERR_VAULT_DATA_NESTED/
    );
    assert.equal(fs.existsSync(dataB), false);

    // (d) Directory alias (junction on Windows, symlink on POSIX)
    const realParent = path.join(tmp, 'RealParent');
    const aliasParent = path.join(tmp, 'AliasParent');
    fs.mkdirSync(realParent, { recursive: true });
    let aliasCreated = false;
    try {
      fs.symlinkSync(realParent, aliasParent, process.platform === 'win32' ? 'junction' : 'dir');
      aliasCreated = true;
    } catch {
      aliasCreated = false;
    }
    if (aliasCreated) {
      await assert.rejects(
        () =>
          runSetupWizard({
            vaultPath: realParent,
            dataPath: path.join(aliasParent, 'nested-data'),
            configPath: cfgSentinel,
            yes: true,
            sourceRoots: noSources
          }),
        /ERR_VAULT_DATA_NESTED/
      );
      assert.equal(fs.existsSync(path.join(realParent, 'nested-data')), false);
    }

    // (e) Existing Data paired with a brand-new empty Vault -> rejected before any write or git init
    const validVault = path.join(tmp, 'ValidVault');
    const validData = path.join(tmp, 'ValidData');
    const validCfg = path.join(tmp, 'valid-cfg.json');
    await runSetupWizard({ vaultPath: validVault, dataPath: validData, configPath: validCfg, yes: true, sourceRoots: noSources });
    const emptyForeignVault = path.join(tmp, 'EmptyForeignVault');
    fs.mkdirSync(emptyForeignVault, { recursive: true });

    await assert.rejects(
      () =>
        runSetupWizard({
          vaultPath: emptyForeignVault,
          dataPath: validData,
          configPath: cfgSentinel,
          yes: true,
          sourceRoots: noSources
        }),
      /ERR_VAULT_DATA_MISMATCH/
    );
    assert.deepEqual(fs.readdirSync(emptyForeignVault), []);
    assert.equal(fs.readFileSync(cfgSentinel, 'utf8'), '{"keep":"original"}\n');

    // (f) Validly paired empty Vault + Data can still re-run setup idempotently
    const rerunRes = await runSetupWizard({
      vaultPath: validVault,
      dataPath: validData,
      configPath: validCfg,
      yes: true,
      sourceRoots: noSources
    });
    assert.equal(rerunRes.ok, true);
    assert.equal(rerunRes.initStatus, 'already_initialized');
  });

  await t.test('6. [Bug C] deployCompanionPlugin handles UTF-8 BOM and aborts cleanly without mutating corrupted configs', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-plugin-cfg-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    // (a) UTF-8 BOM community-plugins.json preserves existing plugins and order
    const vaultBom = path.join(tmp, 'VaultBom');
    const dataBom = path.join(tmp, 'VaultBom-Data');
    const obsDir = path.join(vaultBom, '.obsidian');
    fs.mkdirSync(obsDir, { recursive: true });
    const cpBom = path.join(obsDir, 'community-plugins.json');
    fs.writeFileSync(cpBom, '\uFEFF' + JSON.stringify(['dataview', 'templater-obsidian'], null, 2) + '\n', 'utf8');

    const resBom = deployCompanionPlugin({ vaultPath: vaultBom, dataPath: dataBom });
    assert.equal(resBom.deployed, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(cpBom, 'utf8')), ['dataview', 'templater-obsidian', 'mindloom']);

    // (b) Invalid JSON in community-plugins.json preserves original bytes and does not copy plugin files
    const vaultBad = path.join(tmp, 'VaultBad');
    const dataBad = path.join(tmp, 'VaultBad-Data');
    fs.mkdirSync(path.join(vaultBad, '.obsidian'), { recursive: true });
    const cpBad = path.join(vaultBad, '.obsidian', 'community-plugins.json');
    fs.writeFileSync(cpBad, '{corrupted json', 'utf8');
    assert.throws(
      () => deployCompanionPlugin({ vaultPath: vaultBad, dataPath: dataBad }),
      /INVALID_COMMUNITY_PLUGINS_JSON/
    );
    assert.equal(fs.readFileSync(cpBad, 'utf8'), '{corrupted json');
    assert.equal(fs.existsSync(path.join(vaultBad, '.obsidian', 'plugins', 'mindloom', 'main.js')), false);

    // (c) Object instead of array in community-plugins.json preserves original bytes
    const vaultObj = path.join(tmp, 'VaultObj');
    fs.mkdirSync(path.join(vaultObj, '.obsidian'), { recursive: true });
    const cpObj = path.join(vaultObj, '.obsidian', 'community-plugins.json');
    fs.writeFileSync(cpObj, '{"plugins":["dataview"]}\n', 'utf8');
    assert.throws(
      () => deployCompanionPlugin({ vaultPath: vaultObj, dataPath: dataBad }),
      /INVALID_COMMUNITY_PLUGINS_FORMAT/
    );
    assert.equal(fs.readFileSync(cpObj, 'utf8'), '{"plugins":["dataview"]}\n');

    // (d) Corrupted plugin data.json preserves original bytes
    const vaultBadData = path.join(tmp, 'VaultBadData');
    const pDir = path.join(vaultBadData, '.obsidian', 'plugins', 'mindloom');
    fs.mkdirSync(pDir, { recursive: true });
    const pDataPath = path.join(pDir, 'data.json');
    fs.writeFileSync(pDataPath, '{broken-data', 'utf8');
    assert.throws(
      () => deployCompanionPlugin({ vaultPath: vaultBadData, dataPath: dataBad }),
      /INVALID_PLUGIN_DATA_JSON/
    );
    assert.equal(fs.readFileSync(pDataPath, 'utf8'), '{broken-data');
  });

  await t.test('7. [Bug D] Antigravity CWD extraction is shared between Setup & auto-sync and requires real rule match', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-agy-parity-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const homeDir = path.join(tmp, 'home');
    const agyBrain = path.join(homeDir, '.gemini', 'antigravity', 'brain');
    const projDir = path.join(tmp, 'repos', 'alpha-loom');
    fs.mkdirSync(path.join(projDir, '.git'), { recursive: true });

    const sessGoodDir = path.join(agyBrain, 'aaaa1111-1111-4111-8111-111111111111', '.system_generated', 'logs');
    fs.mkdirSync(sessGoodDir, { recursive: true });
    fs.writeFileSync(
      path.join(sessGoodDir, 'transcript.jsonl'),
      [
        JSON.stringify({
          type: 'USER_INPUT',
          content: `Active Workspaces:\n- ${projDir}\nCommand Working Directory: ${projDir}\nFiles relating to the user request`
        }),
        JSON.stringify({ type: 'PLANNER_RESPONSE', content: 'done' })
      ].join('\n') + '\n',
      'utf8'
    );

    const sessUnrecognizedDir = path.join(agyBrain, 'bbbb2222-2222-4222-8222-222222222222', '.system_generated', 'logs');
    fs.mkdirSync(sessUnrecognizedDir, { recursive: true });
    fs.writeFileSync(
      path.join(sessUnrecognizedDir, 'transcript.jsonl'),
      [
        JSON.stringify({
          type: 'USER_INPUT',
          content: 'No working directory metadata here, just chatting'
        }),
        JSON.stringify({ type: 'PLANNER_RESPONSE', content: 'ok' })
      ].join('\n') + '\n',
      'utf8'
    );

    const vaultPath = path.join(tmp, 'Vault');
    const dataPath = path.join(tmp, 'Vault-Data');
    const cfgPath = path.join(tmp, 'cfg.json');

    const setupRes = await runSetupWizard({
      vaultPath,
      dataPath,
      configPath: cfgPath,
      yes: true,
      skipPlugin: true,
      homeDir,
      sourceRoots: {
        codexHome: path.join(tmp, 'no-cdx'),
        codexArchivedDir: null,
        antigravityBrainDir: agyBrain,
        dshHome: path.join(tmp, 'no-dsh')
      }
    });
    assert.deepEqual(setupRes.workspacesAdded, ['AlphaLoom']);

    // Custom non-'unmapped' default_unmapped_project must NOT grant whitelist sync eligibility!
    const pmapPath = path.join(dataPath, 'manifests', 'project-map.json');
    const pmap = JSON.parse(fs.readFileSync(pmapPath, 'utf8'));
    pmap.default_unmapped_project = 'GeneralDisplayOnly';
    fs.writeFileSync(pmapPath, JSON.stringify(pmap, null, 2) + '\n', 'utf8');

    const db = openExistingDatabase(path.join(dataPath, 'runtime', 'state.sqlite'), { readOnly: true });
    try {
      const dryRes = runWhitelistAutoSync({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourceTool: 'antigravity',
        codexHome: path.join(tmp, 'no-cdx'),
        codexArchivedDir: null,
        antigravityBrainDir: agyBrain,
        dshHome: path.join(tmp, 'no-dsh'),
        dryRun: true
      });
      assert.equal(dryRes.dryRunCandidatesCount, 1);
      assert.equal(dryRes.dryRunCandidates[0].project, 'AlphaLoom');
      assert.equal(dryRes.dryRunCandidates[0].sessionId, 'aaaa1111-1111-4111-8111-111111111111');
      assert.equal(dryRes.skippedUnmappedCount, 1);
      assert.equal(dryRes.skippedUnmapped[0].sessionId, 'bbbb2222-2222-4222-8222-222222222222');
    } finally {
      db.close();
    }
  });

  await t.test('8. [Round-2 B & D] Full CLI setup aborts with ZERO side effects on corrupt community-plugins/data.json or missing plugin dist files, and aligns scheduler task name', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-setup-atomic-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
    const noSources = {
      codexHome: path.join(tmp, 'no-cdx'),
      codexArchivedDir: null,
      antigravityBrainDir: path.join(tmp, 'no-agy'),
      dshHome: path.join(tmp, 'no-dsh')
    };

    const vaultPath = path.join(tmp, 'Vault');
    const dataPath = path.join(tmp, 'Vault-Data');
    const cfgPath = path.join(tmp, 'mindloom-config.json');

    await runSetupWizard({
      vaultPath,
      dataPath,
      configPath: cfgPath,
      yes: true,
      sourceRoots: noSources
    });

    // Remove one template, place a sentinel in default config & deployed cli to detect any premature write
    const tplPath = path.join(vaultPath, '90_Templates', 'Template_Session.md');
    fs.unlinkSync(tplPath);
    fs.writeFileSync(cfgPath, '{"sentinel":"preserve-me"}\n', 'utf8');
    const deployedCli = path.join(dataPath, 'cli', 'cli', 'mem.mjs');
    fs.writeFileSync(deployedCli, '// sentinel-cli\n', 'utf8');

    // (a) Corrupt community-plugins.json via full CLI `mem setup`
    const cpPath = path.join(vaultPath, '.obsidian', 'community-plugins.json');
    fs.writeFileSync(cpPath, '{corrupt-plugins', 'utf8');
    const cliFailPlugins = spawnSync(
      process.execPath,
      [CLI_PATH, 'setup', '--vault', vaultPath, '--data', dataPath, '--yes'],
      {
        encoding: 'utf8',
        env: { ...process.env, MINDLOOM_CONFIG: cfgPath }
      }
    );
    assert.notEqual(cliFailPlugins.status, 0);
    assert.match(`${cliFailPlugins.stderr}\n${cliFailPlugins.stdout}`, /INVALID_COMMUNITY_PLUGINS_JSON/);
    assert.equal(fs.readFileSync(cpPath, 'utf8'), '{corrupt-plugins');
    assert.equal(fs.readFileSync(cfgPath, 'utf8'), '{"sentinel":"preserve-me"}\n');
    assert.equal(fs.existsSync(tplPath), false);
    assert.equal(fs.readFileSync(deployedCli, 'utf8'), '// sentinel-cli\n');

    // Fix community-plugins.json, corrupt plugin data.json
    fs.writeFileSync(cpPath, '["mindloom"]\n', 'utf8');
    const pluginDataPath = path.join(vaultPath, '.obsidian', 'plugins', 'mindloom', 'data.json');
    fs.writeFileSync(pluginDataPath, '{corrupt-data', 'utf8');
    const cliFailData = spawnSync(
      process.execPath,
      [CLI_PATH, 'setup', '--vault', vaultPath, '--data', dataPath, '--yes'],
      {
        encoding: 'utf8',
        env: { ...process.env, MINDLOOM_CONFIG: cfgPath }
      }
    );
    assert.notEqual(cliFailData.status, 0);
    assert.match(`${cliFailData.stderr}\n${cliFailData.stdout}`, /INVALID_PLUGIN_DATA_JSON/);
    assert.equal(fs.readFileSync(pluginDataPath, 'utf8'), '{corrupt-data');
    assert.equal(fs.readFileSync(cfgPath, 'utf8'), '{"sentinel":"preserve-me"}\n');
    assert.equal(fs.existsSync(tplPath), false);
    assert.equal(fs.readFileSync(deployedCli, 'utf8'), '// sentinel-cli\n');

    // (b) Incomplete plugin dist (main.js only, missing manifest.json & styles.css) -> rejected with zero writes
    fs.writeFileSync(pluginDataPath, '{}\n', 'utf8');
    const partialDist = path.join(tmp, 'partial-dist');
    fs.mkdirSync(partialDist, { recursive: true });
    fs.writeFileSync(path.join(partialDist, 'main.js'), 'module.exports = {};\n', 'utf8');
    await assert.rejects(
      () =>
        runSetupWizard({
          vaultPath,
          dataPath,
          configPath: cfgPath,
          pluginDistDir: partialDist,
          yes: true,
          sourceRoots: noSources
        }),
      /PLUGIN_DIST_INCOMPLETE/
    );
    assert.equal(fs.readFileSync(cfgPath, 'utf8'), '{"sentinel":"preserve-me"}\n');
    assert.equal(fs.existsSync(tplPath), false);
    assert.equal(fs.readFileSync(deployedCli, 'utf8'), '// sentinel-cli\n');

    // (c) Verify authorizeAutosync scheduler name matches detectScheduleStatus
    const { detectScheduleStatus } = await import('../src/schedule/scheduler.mjs');
    const authRes = await runSetupWizard({
      vaultPath,
      dataPath,
      configPath: cfgPath,
      yes: true,
      authorizeAutosync: true,
      isTty: true,
      env: {},
      confirmAuthorizeFn: async () => 'YES',
      platform: 'win32',
      dryRunScheduler: true,
      sourceRoots: noSources
    });
    assert.equal(authRes.ok, true);
    assert.equal(fs.existsSync(tplPath), true);
    const det = detectScheduleStatus({
      platform: 'win32',
      vaultDir: vaultPath,
      dataDir: dataPath,
      runner: () => ''
    });
    assert.equal(authRes.scheduler.plan.taskName, det.target);
  });

  await t.test('11. [Round 3 Panel C] Malformed project-map.json field types abort BEFORE any template/CLI/config write', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-pmap-schema-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultPath = path.join(tmp, 'Vault');
    const dataPath = path.join(tmp, 'Vault-Data');
    const cfgPath = path.join(tmp, 'cfg.json');
    const noSources = {
      codexHome: path.join(tmp, 'no-cdx'),
      codexArchivedDir: null,
      antigravityBrainDir: path.join(tmp, 'no-agy'),
      dshHome: path.join(tmp, 'no-dsh')
    };

    await runSetupWizard({
      vaultPath,
      dataPath,
      configPath: cfgPath,
      yes: true,
      skipPlugin: true,
      sourceRoots: noSources
    });

    const pmapPath = path.join(dataPath, 'manifests', 'project-map.json');
    const badPmap = JSON.stringify(
      {
        schema_version: 1,
        default_unmapped_project: 'unmapped',
        projects: [{ project: 'Alpha', paths: 123 }]
      },
      null,
      2
    );
    fs.writeFileSync(pmapPath, badPmap, 'utf8');

    const tplPath = path.join(vaultPath, '90_Templates', 'Session_Template.md');
    if (fs.existsSync(tplPath)) fs.unlinkSync(tplPath);
    const deployedCli = path.join(dataPath, 'cli', 'mem.mjs');
    fs.writeFileSync(deployedCli, '// sentinel-cli\n', 'utf8');
    fs.writeFileSync(cfgPath, '{"sentinel":"keep-intact"}\n', 'utf8');

    await assert.rejects(
      () =>
        runSetupWizard({
          vaultPath,
          dataPath,
          configPath: cfgPath,
          yes: true,
          skipPlugin: true,
          sourceRoots: noSources
        }),
      (err) => err?.code === 'INVALID_PROJECT_MAP_SCHEMA' && /projects\[0\]\.paths/.test(err.message)
    );

    assert.equal(fs.existsSync(tplPath), false);
    assert.equal(fs.readFileSync(deployedCli, 'utf8'), '// sentinel-cli\n');
    assert.equal(fs.readFileSync(cfgPath, 'utf8'), '{"sentinel":"keep-intact"}\n');
    assert.equal(fs.readFileSync(pmapPath, 'utf8'), badPmap);

    // Non-string element inside git_roots array also aborts cleanly with exact field pinpointed
    fs.writeFileSync(
      pmapPath,
      JSON.stringify({ schema_version: 1, projects: [{ project: 'Alpha', git_roots: ['ok', 42] }] }),
      'utf8'
    );
    await assert.rejects(
      () =>
        runSetupWizard({
          vaultPath,
          dataPath,
          configPath: cfgPath,
          yes: true,
          skipPlugin: true,
          sourceRoots: noSources
        }),
      (err) => err?.code === 'INVALID_PROJECT_MAP_SCHEMA' && /projects\[0\]\.git_roots\[1\]/.test(err.message)
    );
    assert.equal(fs.existsSync(tplPath), false);
  });
});
