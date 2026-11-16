import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { isSameCanonicalPath, resolveCanonicalPath } from '../config/paths.mjs';
import { readInstanceIdentity } from '../storage/instance-identity.mjs';

const CRONTAB_BEGIN_PREFIX = '# BEGIN MINDLOOM AUTOSYNC';
const CRONTAB_END_PREFIX = '# END MINDLOOM AUTOSYNC';

export function deriveSchedulerInstanceTag({ instanceId = null, vaultDir = null, dataDir = null } = {}) {
  if (vaultDir && dataDir) {
    const identity = readInstanceIdentity({ vaultPath: vaultDir, dataPath: dataDir });
    if (identity.persisted) {
      return crypto
        .createHash('sha256')
        .update(`${identity.vaultId}:${identity.dataId}`, 'utf8')
        .digest('hex')
        .slice(0, 10);
    }
    return crypto
      .createHash('sha256')
      .update(`${resolveCanonicalPath(vaultDir)}\0${resolveCanonicalPath(dataDir)}`, 'utf8')
      .digest('hex')
      .slice(0, 10);
  }
  if (instanceId) {
    return crypto.createHash('sha256').update(String(instanceId), 'utf8').digest('hex').slice(0, 10);
  }
  if (dataDir || vaultDir) {
    return crypto
      .createHash('sha256')
      .update(resolveCanonicalPath(dataDir || vaultDir), 'utf8')
      .digest('hex')
      .slice(0, 10);
  }
  return null;
}

export function resolveSchedulerNames({
  instanceId = null,
  vaultDir = null,
  dataDir = null,
  taskName = null,
  label = null,
  unitName = null
} = {}) {
  const instanceTag = deriveSchedulerInstanceTag({ instanceId, vaultDir, dataDir });
  return {
    instanceTag,
    taskName: taskName || (instanceTag ? `MindLoom AutoSync-${instanceTag}` : 'MindLoom AutoSync'),
    label: label || (instanceTag ? `com.mindloom.autosync.${instanceTag}` : 'com.mindloom.autosync'),
    unitName: unitName || (instanceTag ? `mindloom-autosync-${instanceTag}` : 'mindloom-autosync'),
    cronBeginMarker: instanceTag ? `${CRONTAB_BEGIN_PREFIX} [${instanceTag}]` : CRONTAB_BEGIN_PREFIX,
    cronEndMarker: instanceTag ? `${CRONTAB_END_PREFIX} [${instanceTag}]` : CRONTAB_END_PREFIX
  };
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function decodeXmlEntities(text) {
  return String(text || '')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function tokenizeCommandArgs(commandLine, { posixEscapes = true } = {}) {
  const tokens = [];
  let current = '';
  let inToken = false;
  let quote = null;
  const src = String(commandLine || '');

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quote === "'") {
      if (ch === "'") {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = null;
        continue;
      }
      if (ch === '\\') {
        const next = src[i + 1];
        if (posixEscapes) {
          if (next === '"' || next === '\\' || next === '$' || next === '`') {
            current += next;
            i++;
            continue;
          }
        } else if (next === '"') {
          current += '"';
          i++;
          continue;
        }
      }
      current += ch;
      continue;
    }

    if (/\s/.test(ch)) {
      if (inToken) {
        tokens.push(current);
        current = '';
        inToken = false;
      }
      continue;
    }

    inToken = true;
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (posixEscapes && ch === '\\' && i + 1 < src.length) {
      current += src[i + 1];
      i++;
      continue;
    }
    current += ch;
  }

  if (quote !== null) {
    return null; // Unclosed quote -> unparseable
  }
  if (inToken) {
    tokens.push(current);
  }
  return tokens;
}

function verifyTokensMatchInstance(tokens, { vaultDir, dataDir }) {
  if (!Array.isArray(tokens) || tokens.length === 0 || !vaultDir || !dataDir) {
    return false;
  }

  let hasAutoSyncTarget = false;
  const vaultArgs = [];
  const dataArgs = [];

  for (let i = 0; i < tokens.length; i++) {
    const tok = String(tokens[i] || '');
    const lower = tok.toLowerCase();
    const base = path.win32.basename(tok).toLowerCase();

    if (
      tok === 'auto-sync' ||
      base === 'auto-sync-memory.ps1' ||
      base === 'register-auto-sync-task.ps1'
    ) {
      hasAutoSyncTarget = true;
    }

    const eqIdx = tok.search(/[=:]/);
    const maybeFlag = eqIdx > 0 ? lower.slice(0, eqIdx) : lower;
    const inlineVal = eqIdx > 0 ? tok.slice(eqIdx + 1) : null;

    if (maybeFlag === '--vault' || maybeFlag === '--vault-dir' || maybeFlag === '-vaultdir') {
      const val = inlineVal !== null ? inlineVal : i + 1 < tokens.length ? String(tokens[++i] || '') : '';
      if (!val) return false;
      vaultArgs.push(val);
    } else if (maybeFlag === '--data' || maybeFlag === '--data-dir' || maybeFlag === '-datadir') {
      const val = inlineVal !== null ? inlineVal : i + 1 < tokens.length ? String(tokens[++i] || '') : '';
      if (!val) return false;
      dataArgs.push(val);
    }
  }

  if (!hasAutoSyncTarget || vaultArgs.length === 0 || dataArgs.length === 0) {
    return false;
  }

  return (
    vaultArgs.every((v) => isSameCanonicalPath(v, vaultDir)) &&
    dataArgs.every((d) => isSameCanonicalPath(d, dataDir))
  );
}

function inspectWindowsLegacyXml(xmlOut, { vaultDir, dataDir }) {
  const actionsMatch = /<Actions\b[^>]*>([\s\S]*?)<\/Actions>/i.exec(String(xmlOut || ''));
  if (!actionsMatch) return false;
  const execMatches = [...actionsMatch[1].matchAll(/<Exec\b[^>]*>([\s\S]*?)<\/Exec>/gi)];
  if (execMatches.length === 0) return false;

  for (const m of execMatches) {
    const cmdMatch = /<Command\b[^>]*>([\s\S]*?)<\/Command>/i.exec(m[1]);
    if (!cmdMatch) return false;
    const cmd = decodeXmlEntities(cmdMatch[1]).trim();
    const argsMatch = /<Arguments\b[^>]*>([\s\S]*?)<\/Arguments>/i.exec(m[1]);
    const argStr = argsMatch ? decodeXmlEntities(argsMatch[1]).trim() : '';
    const argTokens = tokenizeCommandArgs(argStr, { posixEscapes: false });
    if (!argTokens) return false;
    const cmdTokens = cmd.startsWith('"') ? tokenizeCommandArgs(cmd, { posixEscapes: false }) : [cmd];
    if (!cmdTokens || !verifyTokensMatchInstance([...cmdTokens, ...argTokens], { vaultDir, dataDir })) {
      return false;
    }
  }
  return true;
}

function inspectDarwinLegacyPlist(plistContent, { vaultDir, dataDir }) {
  const progArgsMatch = /<key>\s*ProgramArguments\s*<\/key>\s*<array>([\s\S]*?)<\/array>/i.exec(
    String(plistContent || '')
  );
  if (!progArgsMatch) return false;
  const tokens = [...progArgsMatch[1].matchAll(/<string>([\s\S]*?)<\/string>/gi)].map((m) =>
    decodeXmlEntities(m[1]).trim()
  );
  return verifyTokensMatchInstance(tokens, { vaultDir, dataDir });
}

function inspectSystemdLegacyService(serviceContent, { vaultDir, dataDir }) {
  const normalized = String(serviceContent || '').replace(/\\\r?\n/g, ' ');
  const execLines = [];
  let inServiceSection = false;
  for (const rawLine of normalized.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    if (/^\[[^\]]+\]$/.test(line)) {
      inServiceSection = line.toLowerCase() === '[service]';
      continue;
    }
    if (inServiceSection && /^ExecStart\s*=/i.test(line)) {
      const rhs = line.replace(/^ExecStart\s*=/i, '').trim().replace(/^[-@!+]+/, '');
      execLines.push(rhs);
    }
  }
  if (execLines.length === 0) return false;
  for (const cmdLine of execLines) {
    const tokens = tokenizeCommandArgs(cmdLine, { posixEscapes: true });
    if (!tokens || !verifyTokensMatchInstance(tokens, { vaultDir, dataDir })) {
      return false;
    }
  }
  return true;
}

function inspectLegacyCrontabBlock(blockBody, { vaultDir, dataDir }) {
  const taskLines = String(blockBody || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  if (taskLines.length === 0) return false;

  for (const line of taskLines) {
    let cmdRest = null;
    if (line.startsWith('@')) {
      const m = /^@[a-z]+\s+(.+)$/i.exec(line);
      cmdRest = m ? m[1] : null;
    } else {
      const m = /^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
      cmdRest = m ? m[1] : null;
    }
    if (!cmdRest) return false;
    const tokens = tokenizeCommandArgs(cmdRest, { posixEscapes: true });
    if (!tokens || !verifyTokensMatchInstance(tokens, { vaultDir, dataDir })) {
      return false;
    }
  }
  return true;
}

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
  taskName = null,
  instanceId = null,
  times = ['12:20', '21:20'],
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null,
  runnerScriptPath = null
}) {
  const names = resolveSchedulerNames({ instanceId, vaultDir, dataDir, taskName });
  const safeTaskName = assertSafeString(names.taskName, 'taskName');
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
  const safeCfgPart =
    useRunner && configPath
      ? ` + " -ConfigPath " + '"' + ${quotePowerShellArg(assertSafeString(path.resolve(configPath), 'configPath'))} + '"'`
      : '';
  const triggerExpr = parsedTimes.map((t) => `(New-ScheduledTaskTrigger -Daily -At ${quotePowerShellArg(t.raw)})`).join(', ');
  const scriptLines = [
    '$ErrorActionPreference = "Stop"',
    useRunner
      ? `$argLine = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File " + '"' + ${quotePowerShellArg(safeRunner)} + '"' + " -VaultDir " + '"' + ${quotePowerShellArg(path.resolve(vaultDir))} + '"' + " -DataDir " + '"' + ${quotePowerShellArg(path.resolve(dataDir))} + '"'${safeCfgPart}`
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
    instanceTag: names.instanceTag,
    taskName: safeTaskName,
    vaultDir,
    dataDir,
    times: parsedTimes.map((t) => t.raw),
    scriptContent: scriptLines.join('\n') + '\n',
    detectCommand: ['schtasks', '/Query', '/TN', safeTaskName]
  };
}

export function buildMacOsLaunchdPlan({
  label = null,
  instanceId = null,
  times = ['12:20', '21:20'],
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null,
  homeDir = os.homedir()
}) {
  const names = resolveSchedulerNames({ instanceId, vaultDir, dataDir, label });
  const safeLabel = assertSafeString(names.label, 'label');
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
    instanceTag: names.instanceTag,
    label: safeLabel,
    vaultDir,
    dataDir,
    homeDir,
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
  unitName = null,
  instanceId = null,
  times = ['12:20', '21:20'],
  nodeExe = process.execPath,
  memCliPath,
  vaultDir,
  dataDir,
  configPath = null,
  homeDir = os.homedir(),
  existingCrontab = ''
}) {
  const names = resolveSchedulerNames({ instanceId, vaultDir, dataDir, unitName });
  const instanceTag = names.instanceTag;
  const safeUnit = assertSafeString(names.unitName, 'unitName');
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
    const beginMarker = names.cronBeginMarker;
    const endMarker = names.cronEndMarker;
    const cronLines = parsedTimes.map(
      (t) => `${t.minute} ${t.hour} * * * ${quotedCmd} >> ${quotePosixShellArg(logFile)} 2>&1`
    );
    const block = [beginMarker, ...cronLines, endMarker].join('\n');
    const cleanedExisting = String(existingCrontab || '')
      .replace(new RegExp(`${escapeRegExp(beginMarker)}[\\s\\S]*?${escapeRegExp(endMarker)}\\r?\\n?`, 'g'), '')
      .trimEnd();
    const mergedCrontab = (cleanedExisting ? `${cleanedExisting}\n${block}` : block) + '\n';

    return {
      platform: 'linux',
      backend: 'crontab',
      instanceTag,
      beginMarker,
      endMarker,
      vaultDir,
      dataDir,
      homeDir,
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
    instanceTag,
    unitName: safeUnit,
    vaultDir,
    dataDir,
    homeDir,
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

function detectLinuxBackend({ runner = execFileSync } = {}) {
  try {
    runner('systemctl', ['--user', 'show-environment'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    return 'systemd';
  } catch {
    return 'crontab';
  }
}

function readExistingCrontab(runner = execFileSync) {
  try {
    return runner('crontab', ['-l'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (err) {
    const stderr = String(err?.stderr ?? '');
    const stdout = String(err?.stdout ?? '');
    const msg = String(err?.message ?? '');
    const combined = `${stderr}\n${stdout}\n${msg}`;
    const isConfirmedNoCrontab =
      err?.code !== 'ENOENT' &&
      (err?.status === undefined || err?.status === 1) &&
      /\bno crontab for\b/i.test(combined);
    if (isConfirmedNoCrontab) {
      return '';
    }
    const readErr = new Error(
      `CRONTAB_READ_FAILED: 无法安全读取现有 crontab (${combined.trim() || err?.code || 'unknown error'})，已中止以免覆盖现有定时任务`
    );
    readErr.code = 'CRONTAB_READ_FAILED';
    throw readErr;
  }
}

export function generateSchedulePlan({
  platform = process.platform,
  linuxBackend = 'systemd',
  runner = execFileSync,
  ...opts
}) {
  if (platform === 'win32') {
    return buildWindowsScheduledTaskPlan(opts);
  }
  if (platform === 'darwin') {
    return buildMacOsLaunchdPlan(opts);
  }
  if (platform === 'linux') {
    let effectiveBackend = linuxBackend;
    let existingCrontab = opts.existingCrontab;
    if (linuxBackend === 'auto') {
      effectiveBackend = detectLinuxBackend({ runner });
    }
    if (effectiveBackend === 'crontab' && existingCrontab === undefined) {
      existingCrontab = readExistingCrontab(runner);
    }
    return buildLinuxSchedulerPlan({ backend: effectiveBackend, ...opts, existingCrontab });
  }
  throw new Error(`UNSUPPORTED_PLATFORM: scheduler does not support platform "${platform}"`);
}

const LEGACY_CRONTAB_BLOCK_RE = new RegExp(
  `^${escapeRegExp(CRONTAB_BEGIN_PREFIX)}\\r?\\n([\\s\\S]*?)^${escapeRegExp(CRONTAB_END_PREFIX)}(?:\\r?\\n|$)`,
  'gm'
);

export function inspectLegacyScheduleTarget({
  platform = process.platform,
  backend = null,
  vaultDir = null,
  dataDir = null,
  homeDir = os.homedir(),
  runner = execFileSync,
  existingCrontab = null
} = {}) {
  if (platform === 'win32') {
    const legacyName = 'MindLoom AutoSync';
    try {
      const xmlOut = String(
        runner('schtasks', ['/Query', '/TN', legacyName, '/XML'], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        }) || ''
      );
      return {
        found: true,
        target: legacyName,
        sameInstance: inspectWindowsLegacyXml(xmlOut, { vaultDir, dataDir })
      };
    } catch {
      return { found: false, target: legacyName, sameInstance: false };
    }
  }

  if (platform === 'darwin') {
    const legacyPlist = path.join(homeDir, 'Library', 'LaunchAgents', 'com.mindloom.autosync.plist');
    if (!fs.existsSync(legacyPlist)) {
      return { found: false, target: legacyPlist, sameInstance: false };
    }
    const content = fs.readFileSync(legacyPlist, 'utf8');
    return {
      found: true,
      target: legacyPlist,
      sameInstance: inspectDarwinLegacyPlist(content, { vaultDir, dataDir })
    };
  }

  if (platform === 'linux') {
    if (backend === 'crontab') {
      let cronText = existingCrontab;
      if (cronText === null || cronText === undefined) {
        try {
          cronText = readExistingCrontab(runner);
        } catch {
          return { found: false, target: 'crontab', sameInstance: false };
        }
      }
      LEGACY_CRONTAB_BLOCK_RE.lastIndex = 0;
      const m = LEGACY_CRONTAB_BLOCK_RE.exec(String(cronText || ''));
      if (!m) {
        return { found: false, target: 'crontab', sameInstance: false };
      }
      return {
        found: true,
        target: 'crontab',
        sameInstance: inspectLegacyCrontabBlock(m[1], { vaultDir, dataDir })
      };
    }

    const legacyService = path.join(homeDir, '.config', 'systemd', 'user', 'mindloom-autosync.service');
    const legacyTimer = path.join(homeDir, '.config', 'systemd', 'user', 'mindloom-autosync.timer');
    if (!fs.existsSync(legacyService) && !fs.existsSync(legacyTimer)) {
      return { found: false, target: legacyTimer, sameInstance: false };
    }
    const content = fs.existsSync(legacyService) ? fs.readFileSync(legacyService, 'utf8') : '';
    return {
      found: true,
      target: legacyTimer,
      legacyService,
      sameInstance: inspectSystemdLegacyService(content, { vaultDir, dataDir })
    };
  }

  return { found: false, target: null, sameInstance: false };
}

export function migrateLegacyScheduleIfSameInstance({
  platform = process.platform,
  backend = null,
  vaultDir = null,
  dataDir = null,
  homeDir = os.homedir(),
  runner = execFileSync,
  dryRun = false,
  existingCrontab = null
} = {}) {
  const info = inspectLegacyScheduleTarget({
    platform,
    backend,
    vaultDir,
    dataDir,
    homeDir,
    runner,
    existingCrontab
  });
  if (!info.found) {
    return { found: false, sameInstance: false, migrated: false, target: info.target };
  }
  if (!info.sameInstance) {
    return {
      found: true,
      sameInstance: false,
      migrated: false,
      target: info.target,
      warning: `Legacy fixed-name schedule (${info.target}) belongs to a different or unverified vault; preserved untouched.`
    };
  }

  if (!dryRun) {
    if (platform === 'win32') {
      runner('schtasks', ['/Delete', '/TN', info.target, '/F'], {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } else if (platform === 'darwin') {
      try {
        runner('launchctl', ['unload', info.target], { stdio: 'ignore' });
      } catch {
        // ignore if already unloaded
      }
      if (fs.existsSync(info.target)) fs.unlinkSync(info.target);
    } else if (platform === 'linux') {
      if (backend === 'crontab') {
        const current = existingCrontab !== null && existingCrontab !== undefined ? existingCrontab : readExistingCrontab(runner);
        const stripped = String(current || '').replace(LEGACY_CRONTAB_BLOCK_RE, '').trimEnd();
        runner('crontab', ['-'], { input: stripped ? `${stripped}\n` : '', encoding: 'utf8' });
      } else {
        try {
          runner('systemctl', ['--user', 'disable', '--now', 'mindloom-autosync.timer'], { stdio: 'ignore' });
        } catch {
          // ignore if inactive
        }
        if (info.legacyService && fs.existsSync(info.legacyService)) fs.unlinkSync(info.legacyService);
        if (fs.existsSync(info.target)) fs.unlinkSync(info.target);
      }
    }
  }

  return { found: true, sameInstance: true, migrated: !dryRun, target: info.target };
}

export function applySchedulePlan(plan, { dryRun = false, runner = execFileSync, migrateLegacy = true } = {}) {
  if (dryRun) {
    return { applied: false, dryRun: true, plan };
  }

  const runLegacyMigration = (extra = {}) => {
    if (!migrateLegacy || !plan.vaultDir || !plan.dataDir) return null;
    return migrateLegacyScheduleIfSameInstance({
      platform: plan.platform,
      backend: plan.backend,
      vaultDir: plan.vaultDir,
      dataDir: plan.dataDir,
      homeDir: plan.homeDir || os.homedir(),
      runner,
      dryRun: false,
      ...extra
    });
  };

  if (plan.platform === 'win32') {
    try {
      runner('pwsh', ['-NoProfile', '-NonInteractive', '-Command', plan.scriptContent], {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        runner('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', plan.scriptContent], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } else {
        throw err;
      }
    }
    const legacyMigration = runLegacyMigration();
    return { applied: true, dryRun: false, backend: plan.backend, taskName: plan.taskName, legacyMigration };
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
    const legacyMigration = runLegacyMigration();
    return { applied: true, dryRun: false, backend: plan.backend, plistPath: plan.plistPath, legacyMigration };
  }

  if (plan.platform === 'linux') {
    if (plan.backend === 'crontab') {
      const legacyCheck = migrateLegacy && plan.vaultDir && plan.dataDir
        ? inspectLegacyScheduleTarget({
            platform: 'linux',
            backend: 'crontab',
            vaultDir: plan.vaultDir,
            dataDir: plan.dataDir,
            runner,
            existingCrontab: plan.mergedCrontab
          })
        : { found: false, sameInstance: false };
      const finalCrontab = legacyCheck.found && legacyCheck.sameInstance
        ? plan.mergedCrontab.replace(LEGACY_CRONTAB_BLOCK_RE, '')
        : plan.mergedCrontab;
      runner('crontab', ['-'], { input: finalCrontab, encoding: 'utf8' });
      const legacyMigration = legacyCheck.found
        ? {
            found: true,
            sameInstance: legacyCheck.sameInstance,
            migrated: legacyCheck.sameInstance,
            target: legacyCheck.target,
            ...(legacyCheck.sameInstance ? {} : { warning: 'Legacy fixed-name crontab block belongs to another vault; preserved untouched.' })
          }
        : { found: false, sameInstance: false, migrated: false, target: 'crontab' };
      return { applied: true, dryRun: false, backend: plan.backend, legacyMigration };
    }
    fs.mkdirSync(path.dirname(plan.servicePath), { recursive: true });
    fs.writeFileSync(plan.servicePath, plan.serviceContent, 'utf8');
    fs.writeFileSync(plan.timerPath, plan.timerContent, 'utf8');
    runner('systemctl', ['--user', 'daemon-reload'], { encoding: 'utf8' });
    runner('systemctl', ['--user', 'enable', '--now', `${plan.unitName}.timer`], { encoding: 'utf8' });
    const legacyMigration = runLegacyMigration();
    return {
      applied: true,
      dryRun: false,
      backend: plan.backend,
      servicePath: plan.servicePath,
      timerPath: plan.timerPath,
      legacyMigration
    };
  }

  throw new Error(`UNSUPPORTED_PLATFORM: ${plan.platform}`);
}

export function detectScheduleStatus({
  platform = process.platform,
  taskName = null,
  label = null,
  unitName = null,
  instanceId = null,
  vaultDir = null,
  dataDir = null,
  homeDir = os.homedir(),
  runner = execFileSync
} = {}) {
  const names = resolveSchedulerNames({ instanceId, vaultDir, dataDir, taskName, label, unitName });
  const effTaskName = names.taskName;
  const effLabel = names.label;
  const effUnitName = names.unitName;

  if (platform === 'win32') {
    let installed = false;
    try {
      runner('schtasks', ['/Query', '/TN', effTaskName], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      installed = true;
    } catch {
      installed = false;
    }
    const legacy = !installed && vaultDir && dataDir
      ? inspectLegacyScheduleTarget({ platform, vaultDir, dataDir, homeDir, runner })
      : { found: false, sameInstance: false };
    return {
      platform,
      backend: 'windows_task_scheduler',
      installed,
      target: effTaskName,
      legacyDetectedForInstance: Boolean(legacy.found && legacy.sameInstance)
    };
  }
  if (platform === 'darwin') {
    const plistPath = path.join(homeDir, 'Library', 'LaunchAgents', `${effLabel}.plist`);
    const installed = fs.existsSync(plistPath);
    const legacy = !installed && vaultDir && dataDir
      ? inspectLegacyScheduleTarget({ platform, vaultDir, dataDir, homeDir, runner })
      : { found: false, sameInstance: false };
    return {
      platform,
      backend: 'launchd',
      installed,
      target: plistPath,
      legacyDetectedForInstance: Boolean(legacy.found && legacy.sameInstance)
    };
  }
  if (platform === 'linux') {
    const timerPath = path.join(homeDir, '.config', 'systemd', 'user', `${effUnitName}.timer`);
    const installed = fs.existsSync(timerPath);
    const legacy = !installed && vaultDir && dataDir
      ? inspectLegacyScheduleTarget({ platform, vaultDir, dataDir, homeDir, runner })
      : { found: false, sameInstance: false };
    return {
      platform,
      backend: 'systemd_user',
      installed,
      target: timerPath,
      legacyDetectedForInstance: Boolean(legacy.found && legacy.sameInstance)
    };
  }
  return { platform, backend: 'unknown', installed: false, target: null, legacyDetectedForInstance: false };
}
