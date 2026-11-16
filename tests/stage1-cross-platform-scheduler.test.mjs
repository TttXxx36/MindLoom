import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  getDefaultVaultPath,
  getDefaultDataPath,
  getDefaultOperatorRoot,
  resolveConfiguredPaths,
  writeInstallConfig,
  getConfiguredSourceRoots
} from '../src/config/paths.mjs';
import { getPlanB01SixSurfaces } from '../src/security/isolation-sentinel.mjs';
import {
  validateScheduleTimes,
  generateSchedulePlan,
  applySchedulePlan
} from '../src/schedule/scheduler.mjs';
import { linkFileAtomically, stageCandidate } from '../src/storage/atomic-publisher.mjs';

test('Stage 1: Cross-platform paths, scheduler dry-run, and atomic publisher', async (t) => {
  await t.test('1. Dynamic paths and B01 surfaces contain zero hardcoded personal paths', () => {
    const fakeHome = process.platform === 'win32' ? 'C:\\Users\\alice' : '/home/alice';
    assert.equal(
      getDefaultVaultPath(fakeHome),
      path.join(fakeHome, 'Documents', 'Obsidian', 'MindLoom')
    );
    assert.equal(
      getDefaultDataPath(fakeHome),
      path.join(fakeHome, 'Documents', 'Obsidian', 'MindLoom-Data')
    );
    assert.ok(getDefaultOperatorRoot('darwin', {}, fakeHome).includes('.mindloom-operator'));
    assert.ok(getDefaultOperatorRoot('linux', {}, fakeHome).includes('.mindloom-operator'));

    const surfaces = getPlanB01SixSurfaces({ homeDir: fakeHome });
    const serialized = JSON.stringify(surfaces);
    assert.equal(serialized.includes('XT'), false);
    assert.equal(serialized.includes('D:\\Document'), false);
    assert.ok(surfaces[0].paths[0].includes('.codex'));

    const roots = getConfiguredSourceRoots({ homeDir: fakeHome, env: {} });
    assert.equal(roots.codexRoot, path.join(fakeHome, '.codex', 'sessions'));
    assert.equal(roots.agyRoot, path.join(fakeHome, '.gemini', 'antigravity', 'brain'));
    assert.equal(roots.dshRoot, path.join(fakeHome, '.dsh', 'sessions'));
  });

  await t.test('2. writeInstallConfig and resolveConfiguredPaths honor config and env overrides', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-cfg-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const cfgPath = path.join(tmp, 'config.json');
    const vaultPath = path.join(tmp, 'MyVault');
    const dataPath = path.join(tmp, 'MyVault-Data');
    writeInstallConfig({ vaultPath, dataPath, configPath: cfgPath });

    const fromCfg = resolveConfiguredPaths({ configPath: cfgPath, env: {} });
    assert.equal(fromCfg.vaultPath, path.resolve(vaultPath));
    assert.equal(fromCfg.dataPath, path.resolve(dataPath));
    assert.equal(fromCfg.deployDir, path.join(path.resolve(dataPath), 'cli'));

    const envVault = path.join(tmp, 'EnvVault');
    const fromEnv = resolveConfiguredPaths({
      configPath: cfgPath,
      env: { MINDLOOM_VAULT: envVault }
    });
    assert.equal(fromEnv.vaultPath, path.resolve(envVault));
  });

  await t.test('3. Scheduler dry-run generates valid Windows, macOS launchd, and Linux systemd/crontab plans', () => {
    const baseOpts = {
      times: ['12:20', '21:20'],
      memCliPath: '/opt/mindloom/cli/mem.mjs',
      vaultDir: '/home/alice/Obsidian/MindLoom',
      dataDir: '/home/alice/Obsidian/MindLoom-Data',
      homeDir: '/home/alice'
    };

    const winPlan = generateSchedulePlan({ platform: 'win32', ...baseOpts });
    assert.equal(winPlan.backend, 'windows_task_scheduler');
    assert.match(winPlan.scriptContent, /Register-ScheduledTask/);
    assert.match(winPlan.scriptContent, /12:20/);
    assert.match(winPlan.scriptContent, /21:20/);
    const winDry = applySchedulePlan(winPlan, { dryRun: true });
    assert.equal(winDry.dryRun, true);

    const macPlan = generateSchedulePlan({ platform: 'darwin', ...baseOpts });
    assert.equal(macPlan.backend, 'launchd');
    assert.match(macPlan.plistContent, /<key>Label<\/key>/);
    assert.match(macPlan.plistContent, /<integer>12<\/integer>/);
    assert.match(macPlan.plistContent, /<integer>20<\/integer>/);
    assert.ok(macPlan.plistPath.endsWith('com.mindloom.autosync.plist'));

    const systemdPlan = generateSchedulePlan({ platform: 'linux', linuxBackend: 'systemd', ...baseOpts });
    assert.equal(systemdPlan.backend, 'systemd_user');
    assert.match(systemdPlan.serviceContent, /ExecStart=/);
    assert.match(systemdPlan.timerContent, /OnCalendar=\*-\*-\* 12:20:00/);
    assert.match(systemdPlan.timerContent, /OnCalendar=\*-\*-\* 21:20:00/);

    const existingCron = '0 5 * * * /usr/bin/echo hi\n# BEGIN MINDLOOM AUTOSYNC\nold line\n# END MINDLOOM AUTOSYNC\n';
    const cronPlan = generateSchedulePlan({
      platform: 'linux',
      linuxBackend: 'crontab',
      existingCrontab: existingCron,
      ...baseOpts
    });
    assert.equal(cronPlan.backend, 'crontab');
    assert.equal(cronPlan.mergedCrontab.includes('old line'), false);
    assert.ok(cronPlan.mergedCrontab.includes('0 5 * * * /usr/bin/echo hi'));
    assert.match(cronPlan.mergedCrontab, /20 12 \* \* \*/);
    assert.match(cronPlan.mergedCrontab, /20 21 \* \* \*/);
  });

  await t.test('4. Scheduler rejects malformed times and injection characters', () => {
    assert.throws(() => validateScheduleTimes(['25:99']), /INVALID_SCHEDULER_TIME/);
    assert.throws(() => validateScheduleTimes([]), /INVALID_SCHEDULER_TIMES/);
    assert.throws(
      () =>
        generateSchedulePlan({
          platform: 'win32',
          taskName: 'Bad;Remove-Item',
          memCliPath: 'cli/mem.mjs',
          vaultDir: 'V',
          dataDir: 'D'
        }),
      /INVALID_SCHEDULER_INPUT/
    );
    assert.throws(
      () =>
        generateSchedulePlan({
          platform: 'darwin',
          label: 'bad/label\nnewline',
          memCliPath: 'cli/mem.mjs',
          vaultDir: 'V',
          dataDir: 'D'
        }),
      /INVALID_SCHEDULER_INPUT/
    );
  });

  await t.test('5. stageCandidate + linkFileAtomically create writable target files without overwriting', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-pub-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
    const stagingDir = path.join(tmp, 'staging');
    const targetDir = path.join(tmp, 'vault');
    fs.mkdirSync(targetDir, { recursive: true });

    const { stagingPath } = stageCandidate({
      stagingDir,
      outputUuid: 'KN-019316a8-0001-7000-8000-000000000001',
      content: '---\nid: "KN-019316a8-0001-7000-8000-000000000001"\n---\nhello\n'
    });
    const destPath = path.join(targetDir, 'note.md');
    const linkRes = linkFileAtomically(stagingPath, destPath);
    assert.equal(linkRes.crossVolumeFallback, false);
    assert.ok(fs.existsSync(destPath));
    // Must refuse overwrite if target already exists
    assert.throws(() => linkFileAtomically(stagingPath, destPath));
    // Target must remain writable
    fs.appendFileSync(destPath, 'appended\n', 'utf8');
    assert.ok(fs.readFileSync(destPath, 'utf8').includes('appended'));
  });
});
