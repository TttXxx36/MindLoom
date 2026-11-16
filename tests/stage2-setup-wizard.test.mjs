import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { runSetupWizard, discoverCandidateWorkspaces, extractAntigravityCwdHint } from '../src/setup/wizard.mjs';

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
});
