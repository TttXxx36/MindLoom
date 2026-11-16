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
  getConfiguredSourceRoots,
  isNodeVersionSupported
} from '../src/config/paths.mjs';
import { getPlanB01SixSurfaces } from '../src/security/isolation-sentinel.mjs';
import {
  validateScheduleTimes,
  generateSchedulePlan,
  applySchedulePlan,
  deriveSchedulerInstanceTag,
  resolveSchedulerNames,
  inspectLegacyScheduleTarget,
  migrateLegacyScheduleIfSameInstance,
  detectScheduleStatus
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

  await t.test('3. Scheduler dry-run generates instance-scoped Windows, macOS launchd, and Linux systemd/crontab plans without cross-vault overwrite', () => {
    const baseOpts = {
      times: ['12:20', '21:20'],
      memCliPath: '/opt/mindloom/cli/mem.mjs',
      vaultDir: '/home/alice/Obsidian/MindLoom',
      dataDir: '/home/alice/Obsidian/MindLoom-Data',
      homeDir: '/home/alice'
    };
    const tagA = deriveSchedulerInstanceTag({ vaultDir: baseOpts.vaultDir, dataDir: baseOpts.dataDir });
    const otherOpts = {
      ...baseOpts,
      vaultDir: '/home/alice/Obsidian/SecondVault',
      dataDir: '/home/alice/Obsidian/SecondVault-Data'
    };
    const tagB = deriveSchedulerInstanceTag({ vaultDir: otherOpts.vaultDir, dataDir: otherOpts.dataDir });
    assert.notEqual(tagA, tagB);

    const winPlan = generateSchedulePlan({ platform: 'win32', ...baseOpts });
    const winPlanB = generateSchedulePlan({ platform: 'win32', ...otherOpts });
    assert.equal(winPlan.backend, 'windows_task_scheduler');
    assert.equal(winPlan.taskName, `MindLoom AutoSync-${tagA}`);
    assert.notEqual(winPlan.taskName, winPlanB.taskName);
    assert.match(winPlan.scriptContent, /Register-ScheduledTask/);
    assert.match(winPlan.scriptContent, /12:20/);
    assert.match(winPlan.scriptContent, /21:20/);
    const winDry = applySchedulePlan(winPlan, { dryRun: true });
    assert.equal(winDry.dryRun, true);

    const macPlan = generateSchedulePlan({ platform: 'darwin', ...baseOpts });
    const macPlanB = generateSchedulePlan({ platform: 'darwin', ...otherOpts });
    assert.equal(macPlan.backend, 'launchd');
    assert.match(macPlan.plistContent, /<key>Label<\/key>/);
    assert.match(macPlan.plistContent, /<integer>12<\/integer>/);
    assert.match(macPlan.plistContent, /<integer>20<\/integer>/);
    assert.ok(macPlan.plistPath.endsWith(`com.mindloom.autosync.${tagA}.plist`));
    assert.notEqual(macPlan.plistPath, macPlanB.plistPath);

    const systemdPlan = generateSchedulePlan({ platform: 'linux', linuxBackend: 'systemd', ...baseOpts });
    const systemdPlanB = generateSchedulePlan({ platform: 'linux', linuxBackend: 'systemd', ...otherOpts });
    assert.equal(systemdPlan.backend, 'systemd_user');
    assert.equal(systemdPlan.unitName, `mindloom-autosync-${tagA}`);
    assert.notEqual(systemdPlan.unitName, systemdPlanB.unitName);
    assert.match(systemdPlan.serviceContent, /ExecStart=/);
    assert.match(systemdPlan.timerContent, /OnCalendar=\*-\*-\* 12:20:00/);
    assert.match(systemdPlan.timerContent, /OnCalendar=\*-\*-\* 21:20:00/);

    const existingCron = `0 5 * * * /usr/bin/echo hi\n# BEGIN MINDLOOM AUTOSYNC [${tagA}]\nold line\n# END MINDLOOM AUTOSYNC [${tagA}]\n`;
    const cronPlanA = generateSchedulePlan({
      platform: 'linux',
      linuxBackend: 'crontab',
      existingCrontab: existingCron,
      ...baseOpts
    });
    assert.equal(cronPlanA.backend, 'crontab');
    assert.equal(cronPlanA.mergedCrontab.includes('old line'), false);
    assert.ok(cronPlanA.mergedCrontab.includes('0 5 * * * /usr/bin/echo hi'));
    assert.match(cronPlanA.mergedCrontab, /20 12 \* \* \*/);
    assert.match(cronPlanA.mergedCrontab, /20 21 \* \* \*/);

    // Applying second instance crontab must preserve first instance block
    const cronPlanB = generateSchedulePlan({
      platform: 'linux',
      linuxBackend: 'crontab',
      existingCrontab: cronPlanA.mergedCrontab,
      ...otherOpts
    });
    assert.ok(cronPlanB.mergedCrontab.includes(`# BEGIN MINDLOOM AUTOSYNC [${tagA}]`));
    assert.ok(cronPlanB.mergedCrontab.includes(`# BEGIN MINDLOOM AUTOSYNC [${tagB}]`));

    const statusCheck = detectScheduleStatus({
      platform: 'win32',
      vaultDir: baseOpts.vaultDir,
      dataDir: baseOpts.dataDir,
      runner: () => ''
    });
    assert.equal(statusCheck.target, `MindLoom AutoSync-${tagA}`);
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

  await t.test('6. Scheduler runner -ConfigPath, Windows pwsh->powershell.exe fallback, and Linux auto backend fallback', () => {
    const winPlanWithRunner = generateSchedulePlan({
      platform: 'win32',
      memCliPath: 'C:\\MindLoom-Data\\cli\\mem.mjs',
      vaultDir: 'C:\\MindLoom',
      dataDir: 'C:\\MindLoom-Data',
      configPath: 'C:\\MindLoom-Data\\manifests\\auto-sync-config.json',
      runnerScriptPath: 'C:\\MindLoom\\scripts\\auto-sync-memory.ps1'
    });
    assert.match(winPlanWithRunner.scriptContent, /-ConfigPath/);
    assert.match(winPlanWithRunner.scriptContent, /auto-sync-config\.json/);

    const calls = [];
    const fallbackApply = applySchedulePlan(winPlanWithRunner, {
      dryRun: false,
      migrateLegacy: false,
      runner: (exe) => {
        calls.push(exe);
        if (exe === 'pwsh') {
          const e = new Error('pwsh not found');
          e.code = 'ENOENT';
          throw e;
        }
        return '';
      }
    });
    assert.equal(fallbackApply.applied, true);
    assert.deepEqual(calls, ['pwsh', 'powershell.exe']);

    const autoLinuxPlan = generateSchedulePlan({
      platform: 'linux',
      linuxBackend: 'auto',
      memCliPath: '/opt/mindloom/cli/mem.mjs',
      vaultDir: '/home/alice/MindLoom',
      dataDir: '/home/alice/MindLoom-Data',
      homeDir: '/home/alice',
      runner: (exe) => {
        if (exe === 'systemctl') throw new Error('no systemd bus');
        if (exe === 'crontab') return '0 4 * * * /bin/true\n';
        return '';
      }
    });
    assert.equal(autoLinuxPlan.backend, 'crontab');
    assert.ok(autoLinuxPlan.mergedCrontab.includes('0 4 * * * /bin/true'));
  });

  await t.test('7. Crontab read errors abort without writing; confirmed empty crontab is allowed', () => {
    const baseOpts = {
      platform: 'linux',
      linuxBackend: 'crontab',
      memCliPath: '/opt/mindloom/cli/mem.mjs',
      vaultDir: '/home/alice/Obsidian/MindLoom',
      dataDir: '/home/alice/Obsidian/MindLoom-Data'
    };

    // Confirmed no crontab yet -> allowed
    const emptyPlan = generateSchedulePlan({
      ...baseOpts,
      runner: () => {
        const err = new Error('Command failed');
        err.status = 1;
        err.stderr = 'no crontab for alice\n';
        throw err;
      }
    });
    assert.equal(emptyPlan.backend, 'crontab');
    assert.match(emptyPlan.mergedCrontab, /BEGIN MINDLOOM AUTOSYNC/);

    // Read error (permission denied / ENOENT) -> must abort and NEVER call write
    let writeCalled = false;
    assert.throws(() => {
      const plan = generateSchedulePlan({
        ...baseOpts,
        runner: (exe, args) => {
          if (exe === 'crontab' && args[0] === '-') {
            writeCalled = true;
          }
          const err = new Error('permission denied');
          err.status = 1;
          err.stderr = 'crontab: cannot access /var/spool/cron: Permission denied\n';
          throw err;
        }
      });
      applySchedulePlan(plan, {
        runner: (exe, args) => {
          if (exe === 'crontab' && args[0] === '-') writeCalled = true;
          return '';
        }
      });
    }, /CRONTAB_READ_FAILED/);
    assert.equal(writeCalled, false);
  });

  await t.test('8. Minimum Node.js version threshold enforces 22.15+ / 23.8+ / 24+ consistently', () => {
    assert.equal(isNodeVersionSupported('22.14.9'), false);
    assert.equal(isNodeVersionSupported('22.0.0'), false);
    assert.equal(isNodeVersionSupported('21.7.3'), false);
    assert.equal(isNodeVersionSupported('23.0.0'), false);
    assert.equal(isNodeVersionSupported('23.7.0'), false);
    assert.equal(isNodeVersionSupported('22.15.0'), true);
    assert.equal(isNodeVersionSupported('22.16.1'), true);
    assert.equal(isNodeVersionSupported('23.8.0'), true);
    assert.equal(isNodeVersionSupported('24.0.0'), true);
    const pkg = JSON.parse(fs.readFileSync(path.resolve('package.json'), 'utf8'));
    assert.equal(pkg.engines.node, '^22.15.0 || ^23.8.0 || >=24.0.0');
  });

  await t.test('9. [Round-2 D] Registration & detectScheduleStatus match names, and legacy fixed task migrates ONLY for same instance', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-sched-mig-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const vaultA = path.join(tmp, 'VaultA');
    const dataA = path.join(tmp, 'VaultA-Data');
    const vaultB = path.join(tmp, 'VaultB');
    const dataB = path.join(tmp, 'VaultB-Data');
    const homeDir = path.join(tmp, 'home');
    fs.mkdirSync(path.join(dataA, 'runtime'), { recursive: true });
    fs.mkdirSync(path.join(dataB, 'runtime'), { recursive: true });
    fs.writeFileSync(
      path.join(dataA, 'runtime', 'instance-identity.json'),
      JSON.stringify({ schema_version: 1, vault_id: 'VLT-AAA', data_id: 'DAT-AAA' }),
      'utf8'
    );

    // Even if instanceId is passed alongside vaultDir+dataDir, names must match detectScheduleStatus
    const names = resolveSchedulerNames({ vaultDir: vaultA, dataDir: dataA });
    const winPlan = generateSchedulePlan({
      platform: 'win32',
      memCliPath: path.join(dataA, 'cli', 'mem.mjs'),
      vaultDir: vaultA,
      dataDir: dataA,
      instanceId: 'VLT-AAA'
    });
    assert.equal(winPlan.taskName, names.taskName);

    const statusA = detectScheduleStatus({
      platform: 'win32',
      vaultDir: vaultA,
      dataDir: dataA,
      runner: (_exe, args) => {
        if (args[0] === '/Query' && args[2] === names.taskName) return 'OK';
        throw new Error('not found');
      }
    });
    assert.equal(statusA.installed, true);
    assert.equal(statusA.target, names.taskName);

    // Legacy macOS plist belonging to VaultA -> migrated cleanly; belonging to VaultB -> preserved untouched
    const launchAgents = path.join(homeDir, 'Library', 'LaunchAgents');
    fs.mkdirSync(launchAgents, { recursive: true });
    const legacyPlist = path.join(launchAgents, 'com.mindloom.autosync.plist');
    const makeLegacyPlist = (v, d) =>
      `<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/node</string><string>/x/mem.mjs</string><string>auto-sync</string><string>--vault</string><string>${v}</string><string>--data</string><string>${d}</string></array></dict></plist>`;
    fs.writeFileSync(legacyPlist, makeLegacyPlist(vaultB, dataB), 'utf8');

    const otherCheck = inspectLegacyScheduleTarget({ platform: 'darwin', vaultDir: vaultA, dataDir: dataA, homeDir });
    assert.equal(otherCheck.found, true);
    assert.equal(otherCheck.sameInstance, false);

    const otherMig = migrateLegacyScheduleIfSameInstance({
      platform: 'darwin',
      vaultDir: vaultA,
      dataDir: dataA,
      homeDir,
      runner: () => ''
    });
    assert.equal(otherMig.migrated, false);
    assert.equal(fs.existsSync(legacyPlist), true);

    fs.writeFileSync(legacyPlist, makeLegacyPlist(vaultA, dataA), 'utf8');
    const sameMig = migrateLegacyScheduleIfSameInstance({
      platform: 'darwin',
      vaultDir: vaultA,
      dataDir: dataA,
      homeDir,
      runner: () => ''
    });
    assert.equal(sameMig.sameInstance, true);
    assert.equal(sameMig.migrated, true);
    assert.equal(fs.existsSync(legacyPlist), false);

    // Windows legacy XML check via mock runner: deletes legacy only when XML references same vault/data
    const winCalls = [];
    const winMigOther = migrateLegacyScheduleIfSameInstance({
      platform: 'win32',
      vaultDir: vaultA,
      dataDir: dataA,
      runner: (exe, args) => {
        winCalls.push([exe, ...args]);
        if (args.includes('/XML')) return `<Task><Arguments>-VaultDir "${vaultB}" -DataDir "${dataB}"</Arguments></Task>`;
        return '';
      }
    });
    assert.equal(winMigOther.migrated, false);
    assert.equal(winCalls.some((c) => c.includes('/Delete')), false);

    winCalls.length = 0;
    const winMigSame = migrateLegacyScheduleIfSameInstance({
      platform: 'win32',
      vaultDir: vaultA,
      dataDir: dataA,
      runner: (exe, args) => {
        winCalls.push([exe, ...args]);
        if (args.includes('/XML')) {
          return `<Task><Description>Other</Description><Actions><Exec><Command>pwsh.exe</Command><Arguments>-NoProfile -File "C:\\repo\\scripts\\auto-sync-memory.ps1" -VaultDir "${vaultA}" -DataDir "${dataA}"</Arguments></Exec></Actions></Task>`;
        }
        return '';
      }
    });
    assert.equal(winMigSame.sameInstance, true);
    assert.equal(winMigSame.migrated, true);
    assert.equal(winCalls.some((c) => c.includes('/Delete') && c.includes('MindLoom AutoSync')), true);

    // Round 3 Panel B: Decoy Description/Comment + partial (only Vault or only Data) + multi-line crontab mismatch MUST preserve legacy schedule
    winCalls.length = 0;
    const winDecoyMismatch = migrateLegacyScheduleIfSameInstance({
      platform: 'win32',
      vaultDir: vaultA,
      dataDir: dataA,
      runner: (exe, args) => {
        winCalls.push([exe, ...args]);
        if (args.includes('/XML')) {
          return `<Task><Description>Owned by ${vaultA} and ${dataA}</Description><Actions><Exec><Command>pwsh.exe</Command><Arguments>-NoProfile -File "C:\\repo\\scripts\\auto-sync-memory.ps1" -VaultDir "${vaultA}" -DataDir "${dataB}"</Arguments></Exec></Actions></Task>`;
        }
        return '';
      }
    });
    assert.equal(winDecoyMismatch.sameInstance, false);
    assert.equal(winDecoyMismatch.migrated, false);
    assert.equal(winCalls.some((c) => c.includes('/Delete')), false);

    // Windows XML with missing DataDir must NOT match
    winCalls.length = 0;
    const winMissingData = migrateLegacyScheduleIfSameInstance({
      platform: 'win32',
      vaultDir: vaultA,
      dataDir: dataA,
      runner: (exe, args) => {
        winCalls.push([exe, ...args]);
        if (args.includes('/XML')) {
          return `<Task><Actions><Exec><Command>pwsh.exe</Command><Arguments>-File "C:\\repo\\scripts\\auto-sync-memory.ps1" -VaultDir "${vaultA}"</Arguments></Exec></Actions></Task>`;
        }
        return '';
      }
    });
    assert.equal(winMissingData.sameInstance, false);
    assert.equal(winCalls.some((c) => c.includes('/Delete')), false);

    // macOS plist with matching comment decoy vs mismatched ProgramArguments MUST preserve legacy plist
    fs.mkdirSync(path.dirname(legacyPlist), { recursive: true });
    fs.writeFileSync(
      legacyPlist,
      `<plist><dict><key>Comment</key><string>${vaultA} ${dataA}</string><key>ProgramArguments</key><array><string>/usr/bin/node</string><string>/x/mem.mjs</string><string>auto-sync</string><string>--vault</string><string>${vaultA}</string><string>--data</string><string>${dataB}</string></array></dict></plist>`,
      'utf8'
    );
    const macDecoy = migrateLegacyScheduleIfSameInstance({
      platform: 'darwin',
      vaultDir: vaultA,
      dataDir: dataA,
      homeDir,
      runner: () => ''
    });
    assert.equal(macDecoy.sameInstance, false);
    assert.equal(macDecoy.migrated, false);
    assert.equal(fs.existsSync(legacyPlist), true);

    // Linux systemd with Description decoy vs mismatched ExecStart MUST preserve legacy unit
    const sysDir = path.join(homeDir, '.config', 'systemd', 'user');
    fs.mkdirSync(sysDir, { recursive: true });
    const legSvc = path.join(sysDir, 'mindloom-autosync.service');
    const legTmr = path.join(sysDir, 'mindloom-autosync.timer');
    fs.writeFileSync(
      legSvc,
      `[Unit]\nDescription=Runs for ${vaultA} ${dataA}\n[Service]\nExecStart="/usr/bin/node" "/x/mem.mjs" "auto-sync" "--vault" "${vaultA}" "--data" "${dataB}"\n`,
      'utf8'
    );
    fs.writeFileSync(legTmr, '[Timer]\nOnCalendar=12:20\n', 'utf8');
    const sysMismatch = inspectLegacyScheduleTarget({
      platform: 'linux',
      backend: 'systemd',
      vaultDir: vaultA,
      dataDir: dataA,
      homeDir
    });
    assert.equal(sysMismatch.found, true);
    assert.equal(sysMismatch.sameInstance, false);

    fs.writeFileSync(
      legSvc,
      `[Unit]\nDescription=Sync\n[Service]\nExecStart="/usr/bin/node" "/x/mem.mjs" "auto-sync" "--vault" "${vaultA}" "--data" "${dataA}"\n`,
      'utf8'
    );
    const sysMatch = inspectLegacyScheduleTarget({
      platform: 'linux',
      backend: 'systemd',
      vaultDir: vaultA,
      dataDir: dataA,
      homeDir
    });
    assert.equal(sysMatch.sameInstance, true);

    // Linux crontab: multi-line block where line 1 matches but line 2 belongs to another Data dir -> MUST NOT match
    const multiCronMixed = [
      '# BEGIN MINDLOOM AUTOSYNC',
      `20 12 * * * '/usr/bin/node' '/x/mem.mjs' 'auto-sync' '--vault' '${vaultA}' '--data' '${dataA}' >> '/tmp/a.log' 2>&1`,
      `20 21 * * * '/usr/bin/node' '/x/mem.mjs' 'auto-sync' '--vault' '${vaultA}' '--data' '${dataB}' >> '${dataA}/cron.log' 2>&1`,
      '# END MINDLOOM AUTOSYNC'
    ].join('\n');
    const cronMixed = inspectLegacyScheduleTarget({
      platform: 'linux',
      backend: 'crontab',
      vaultDir: vaultA,
      dataDir: dataA,
      existingCrontab: multiCronMixed
    });
    assert.equal(cronMixed.found, true);
    assert.equal(cronMixed.sameInstance, false);

    const multiCronSame = [
      '# BEGIN MINDLOOM AUTOSYNC',
      `20 12 * * * '/usr/bin/node' '/x/mem.mjs' 'auto-sync' '--vault' '${vaultA}' '--data' '${dataA}' >> '${dataA}/cron.log' 2>&1`,
      `20 21 * * * '/usr/bin/node' '/x/mem.mjs' 'auto-sync' '--vault' '${vaultA}' '--data' '${dataA}' >> '${dataA}/cron.log' 2>&1`,
      '# END MINDLOOM AUTOSYNC'
    ].join('\n');
    const cronSame = inspectLegacyScheduleTarget({
      platform: 'linux',
      backend: 'crontab',
      vaultDir: vaultA,
      dataDir: dataA,
      existingCrontab: multiCronSame
    });
    assert.equal(cronSame.sameInstance, true);
  });
});
