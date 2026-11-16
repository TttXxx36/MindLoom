import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const CRONTAB_BEGIN_MARKER = '# BEGIN MINDLOOM AUTOSYNC';
const CRONTAB_END_MARKER = '# END MINDLOOM AUTOSYNC';

function assertSafeString(value, fieldName) {
  const str = String(value ?? '');
  if (!str || /[\r\n\0]/.test(str)) {
    throw new Error(`INVALID_SCHEDULER_INPUT: ${fieldName} contains forbidden control characters or is empty`);
  }
  return str;
}

export function validateScheduleTimes(times) {
  if (!Array.isArray(times) || times.length === 0) {
    throw new Error('INVALID_SCHEDULER_TIMES: at least one HH:MM time must be provided');
  }
  return times.map((t) => {
    const clean = String(t || '').trim();
    const m = clean.match(/^([01]\d|2[0-3]):([0-5]\d)$/);
    if (!m) {
      throw new Error(`INVALID_SCHEDULER_TIME: "${clean}" must match HH:MM (24-hour)`);
    }
    return { raw: clean, hour: Number(m[1]), minute: Number(m[2]) };
  });
}

function escapeXml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function quotePosixShellArg(arg) {
  return `'${String(arg).replace(/'/g, `'\\''`)}'`;
}

function quotePowerShellArg(arg) {
  return `'${String(arg).replace(/'/g, "''")}'`;
}

export function buildAutoSyncCommandArgs({
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null
}) {
  const safeNode = assertSafeString(path.resolve(nodeExe), 'nodeExe');
  const safeCli = assertSafeString(path.resolve(memCliPath), 'memCliPath');
  const safeVault = assertSafeString(path.resolve(vaultDir), 'vaultDir');
  const safeData = assertSafeString(path.resolve(dataDir), 'dataDir');
  const args = [safeCli, 'auto-sync', '--vault', safeVault, '--data', safeData, '--json'];
  if (configPath) {
    args.push('--config', assertSafeString(path.resolve(configPath), 'configPath'));
  }
  return { executable: safeNode, args };
}

export function buildWindowsScheduledTaskPlan({
  taskName = 'MindLoom AutoSync',
  times = ['12:20', '21:20'],
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null,
  runnerScriptPath = null
}) {
  const safeTaskName = assertSafeString(taskName, 'taskName');
  if (/[`$"';&|<>]/.test(safeTaskName)) {
    throw new Error('INVALID_SCHEDULER_INPUT: taskName contains unsafe shell characters');
  }
  const parsedTimes = validateScheduleTimes(times);
  const { executable, args } = buildAutoSyncCommandArgs({
    nodeExe,
    memCliPath,
    vaultDir,
    dataDir,
    configPath
  });

  const useRunner = Boolean(runnerScriptPath);
  const safeRunner = useRunner ? assertSafeString(path.resolve(runnerScriptPath), 'runnerScriptPath') : null;
  const triggerExpr = parsedTimes.map((t) => `(New-ScheduledTaskTrigger -Daily -At ${quotePowerShellArg(t.raw)})`).join(', ');
  const scriptLines = [
    '$ErrorActionPreference = "Stop"',
    useRunner
      ? `$argLine = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File " + '"' + ${quotePowerShellArg(safeRunner)} + '"' + " -VaultDir " + '"' + ${quotePowerShellArg(path.resolve(vaultDir))} + '"' + " -DataDir " + '"' + ${quotePowerShellArg(path.resolve(dataDir))} + '"'`
      : `$argLine = ${quotePowerShellArg(args.map((a) => `"${a.replace(/"/g, '\\"')}"`).join(' '))}`,
    useRunner
      ? `$exe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { (Get-Command pwsh).Source } else { 'powershell.exe' }`
      : `$exe = ${quotePowerShellArg(executable)}`,
    '$action = New-ScheduledTaskAction -Execute $exe -Argument $argLine',
    `$triggers = @(${triggerExpr})`,
    '$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries',
    `Register-ScheduledTask -TaskName ${quotePowerShellArg(safeTaskName)} -Action $action -Trigger $triggers -Settings $settings -Description 'MindLoom whitelist low-sensitivity auto-sync' -Force | Out-Null`
  ];

  return {
    platform: 'win32',
    backend: 'windows_task_scheduler',
    taskName: safeTaskName,
    times: parsedTimes.map((t) => t.raw),
    scriptContent: scriptLines.join('\n') + '\n',
    detectCommand: ['schtasks', '/Query', '/TN', safeTaskName]
  };
}

export function buildMacOsLaunchdPlan({
  label = 'com.mindloom.autosync',
  times = ['12:20', '21:20'],
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null,
  homeDir = os.homedir()
}) {
  const safeLabel = assertSafeString(label, 'label');
  if (!/^[A-Za-z0-9._-]+$/.test(safeLabel)) {
    throw new Error('INVALID_SCHEDULER_INPUT: launchd label must match [A-Za-z0-9._-]+');
  }
  const parsedTimes = validateScheduleTimes(times);
  const { executable, args } = buildAutoSyncCommandArgs({
    nodeExe,
    memCliPath,
    vaultDir,
    dataDir,
    configPath
  });

  const plistPath = path.join(homeDir, 'Library', 'LaunchAgents', `${safeLabel}.plist`);
  const logDir = path.join(path.resolve(dataDir), 'runtime', 'logs');
  const stdoutLog = path.join(logDir, 'launchd-autosync.out.log');
  const stderrLog = path.join(logDir, 'launchd-autosync.err.log');

  const programArgsXml = [executable, ...args]
    .map((item) => `    <string>${escapeXml(item)}</string>`)
    .join('\n');

  const calendarIntervalsXml = parsedTimes
    .map(
      (t) => `    <dict>
      <key>Hour</key>
      <integer>${t.hour}</integer>
      <key>Minute</key>
      <integer>${t.minute}</integer>
    </dict>`
    )
    .join('\n');

  const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${escapeXml(safeLabel)}</string>
  <key>ProgramArguments</key>
  <array>
${programArgsXml}
  </array>
  <key>StartCalendarInterval</key>
  <array>
${calendarIntervalsXml}
  </array>
  <key>RunAtLoad</key>
  <false/>
  <key>StandardOutPath</key>
  <string>${escapeXml(stdoutLog)}</string>
  <key>StandardErrorPath</key>
  <string>${escapeXml(stderrLog)}</string>
</dict>
</plist>
`;

  return {
    platform: 'darwin',
    backend: 'launchd',
    label: safeLabel,
    times: parsedTimes.map((t) => t.raw),
    plistPath,
    plistContent,
    installCommands: [
      ['launchctl', 'unload', plistPath],
      ['launchctl', 'load', '-w', plistPath]
    ]
  };
}

export function buildLinuxSchedulerPlan({
  backend = 'systemd',
  unitName = 'mindloom-autosync',
  times = ['12:20', '21:20'],
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null,
  homeDir = os.homedir(),
  existingCrontab = ''
}) {
  const safeUnit = assertSafeString(unitName, 'unitName');
  if (!/^[A-Za-z0-9._-]+$/.test(safeUnit)) {
    throw new Error('INVALID_SCHEDULER_INPUT: systemd unitName must match [A-Za-z0-9._-]+');
  }
  const parsedTimes = validateScheduleTimes(times);
  const { executable, args } = buildAutoSyncCommandArgs({
    nodeExe,
    memCliPath,
    vaultDir,
    dataDir,
    configPath
  });

  const quotedCmd = [executable, ...args].map(quotePosixShellArg).join(' ');
  const logFile = path.join(path.resolve(dataDir), 'runtime', 'logs', 'autosync-cron.log');

  if (backend === 'crontab') {
    const cronLines = parsedTimes.map(
      (t) => `${t.minute} ${t.hour} * * * ${quotedCmd} >> ${quotePosixShellArg(logFile)} 2>&1`
    );
    const block = [CRONTAB_BEGIN_MARKER, ...cronLines, CRONTAB_END_MARKER].join('\n');
    const cleanedExisting = String(existingCrontab || '')
      .replace(new RegExp(`${CRONTAB_BEGIN_MARKER}[\\s\\S]*?${CRONTAB_END_MARKER}\\r?\\n?`, 'g'), '')
      .trimEnd();
    const mergedCrontab = (cleanedExisting ? `${cleanedExisting}\n${block}` : block) + '\n';

    return {
      platform: 'linux',
      backend: 'crontab',
      times: parsedTimes.map((t) => t.raw),
      cronBlock: block + '\n',
      mergedCrontab
    };
  }

  const systemdDir = path.join(homeDir, '.config', 'systemd', 'user');
  const servicePath = path.join(systemdDir, `${safeUnit}.service`);
  const timerPath = path.join(systemdDir, `${safeUnit}.timer`);

  const serviceContent = `[Unit]
Description=MindLoom Whitelist Low-Sensitivity Auto-Sync

[Service]
Type=oneshot
ExecStart=${[executable, ...args].map((a) => `"${a.replace(/"/g, '\\"')}"`).join(' ')}

[Install]
WantedBy=default.target
`;

  const onCalendarLines = parsedTimes.map((t) => `OnCalendar=*-*-* ${t.raw}:00`).join('\n');
  const timerContent = `[Unit]
Description=MindLoom Auto-Sync Schedule Timer

[Timer]
${onCalendarLines}
Persistent=true

[Install]
WantedBy=timers.target
`;

  return {
    platform: 'linux',
    backend: 'systemd_user',
    unitName: safeUnit,
    times: parsedTimes.map((t) => t.raw),
    servicePath,
    timerPath,
    serviceContent,
    timerContent,
    installCommands: [
      ['systemctl', '--user', 'daemon-reload'],
      ['systemctl', '--user', 'enable', '--now', `${safeUnit}.timer`]
    ]
  };
}

export function generateSchedulePlan({
  platform = process.platform,
  linuxBackend = 'systemd',
  ...opts
}) {
  if (platform === 'win32') {
    return buildWindowsScheduledTaskPlan(opts);
  }
  if (platform === 'darwin') {
    return buildMacOsLaunchdPlan(opts);
  }
  if (platform === 'linux') {
    return buildLinuxSchedulerPlan({ backend: linuxBackend, ...opts });
  }
  throw new Error(`UNSUPPORTED_PLATFORM: scheduler does not support platform "${platform}"`);
}

export function applySchedulePlan(plan, { dryRun = false, runner = execFileSync } = {}) {
  if (dryRun) {
    return { applied: false, dryRun: true, plan };
  }

  if (plan.platform === 'win32') {
    runner('pwsh', ['-NoProfile', '-NonInteractive', '-Command', plan.scriptContent], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return { applied: true, dryRun: false, backend: plan.backend, taskName: plan.taskName };
  }

  if (plan.platform === 'darwin') {
    fs.mkdirSync(path.dirname(plan.plistPath), { recursive: true });
    fs.writeFileSync(plan.plistPath, plan.plistContent, 'utf8');
    try {
      runner('launchctl', ['unload', plan.plistPath], { stdio: 'ignore' });
    } catch {
      // ignore if not loaded yet
    }
    runner('launchctl', ['load', '-w', plan.plistPath], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return { applied: true, dryRun: false, backend: plan.backend, plistPath: plan.plistPath };
  }

  if (plan.platform === 'linux') {
    if (plan.backend === 'crontab') {
      runner('crontab', ['-'], { input: plan.mergedCrontab, encoding: 'utf8' });
      return { applied: true, dryRun: false, backend: plan.backend };
    }
    fs.mkdirSync(path.dirname(plan.servicePath), { recursive: true });
    fs.writeFileSync(plan.servicePath, plan.serviceContent, 'utf8');
    fs.writeFileSync(plan.timerPath, plan.timerContent, 'utf8');
    runner('systemctl', ['--user', 'daemon-reload'], { encoding: 'utf8' });
    runner('systemctl', ['--user', 'enable', '--now', `${plan.unitName}.timer`], { encoding: 'utf8' });
    return {
      applied: true,
      dryRun: false,
      backend: plan.backend,
      servicePath: plan.servicePath,
      timerPath: plan.timerPath
    };
  }

  throw new Error(`UNSUPPORTED_PLATFORM: ${plan.platform}`);
}

export function detectScheduleStatus({
  platform = process.platform,
  taskName = 'MindLoom AutoSync',
  label = 'com.mindloom.autosync',
  unitName = 'mindloom-autosync',
  homeDir = os.homedir(),
  runner = execFileSync
} = {}) {
  if (platform === 'win32') {
    try {
      runner('schtasks', ['/Query', '/TN', taskName], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      return { platform, backend: 'windows_task_scheduler', installed: true, target: taskName };
    } catch {
      return { platform, backend: 'windows_task_scheduler', installed: false, target: taskName };
    }
  }
  if (platform === 'darwin') {
    const plistPath = path.join(homeDir, 'Library', 'LaunchAgents', `${label}.plist`);
    return { platform, backend: 'launchd', installed: fs.existsSync(plistPath), target: plistPath };
  }
  if (platform === 'linux') {
    const timerPath = path.join(homeDir, '.config', 'systemd', 'user', `${unitName}.timer`);
    return { platform, backend: 'systemd_user', installed: fs.existsSync(timerPath), target: timerPath };
  }
  return { platform, backend: 'unknown', installed: false, target: null };
}
