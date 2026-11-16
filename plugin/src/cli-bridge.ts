import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import type { CliResult, MindLoomSettings } from './types';

export type ExecFileFn = (
  file: string,
  args: string[],
  options: { timeout: number; maxBuffer: number; windowsHide: boolean },
  cb: (err: Error | null, stdout: string, stderr: string) => void
) => void;

export function parseJsonOutput<T>(rawStdout: string): T {
  const trimmed = String(rawStdout || '').trim();
  if (!trimmed) {
    throw new Error('CLI returned empty output');
  }
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    const lines = trimmed.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const lineTrim = lines[i].trimStart();
      if (!lineTrim.startsWith('{') && !lineTrim.startsWith('[')) continue;
      try {
        return JSON.parse(lines.slice(i).join('\n')) as T;
      } catch {
        // try next candidate line
      }
    }
    throw new Error(`Invalid JSON from CLI: ${trimmed.slice(0, 160)}`);
  }
}

export function resolveNodeExecutable(configuredNodePath = ''): string {
  const candidates: string[] = [];
  if (configuredNodePath && configuredNodePath.trim()) {
    candidates.push(configuredNodePath.trim());
  }
  if (process.platform === 'win32') {
    candidates.push(
      'C:\\Program Files\\nodejs\\node.exe',
      path.join(process.env.LOCALAPPDATA || '', 'Programs', 'nodejs', 'node.exe'),
      'node'
    );
  } else {
    candidates.push('/opt/homebrew/bin/node', '/usr/local/bin/node', '/usr/bin/node', 'node');
  }

  for (const cand of candidates) {
    if (!cand) continue;
    if (cand === 'node' || fs.existsSync(cand)) {
      return cand;
    }
  }
  return 'node';
}

export function resolveDefaultCliPath(dataPath: string, configuredCliPath = ''): string {
  if (configuredCliPath && configuredCliPath.trim()) {
    return configuredCliPath.trim();
  }
  if (dataPath && dataPath.trim()) {
    const candidate = path.join(path.resolve(dataPath), 'cli', 'mem.mjs');
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  const configPath = path.join(os.homedir(), '.mindloom', 'config.json');
  if (fs.existsSync(configPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8')) as { dataPath?: string };
      if (cfg.dataPath) {
        const cand = path.join(path.resolve(cfg.dataPath), 'cli', 'mem.mjs');
        if (fs.existsSync(cand)) return cand;
      }
    } catch {
      // ignore invalid config
    }
  }
  return dataPath ? path.join(path.resolve(dataPath), 'cli', 'mem.mjs') : '';
}

export function resolveDefaultDataPath(vaultPath: string, configuredDataPath = ''): string {
  if (configuredDataPath && configuredDataPath.trim()) {
    return path.resolve(configuredDataPath.trim());
  }
  if (vaultPath && vaultPath.trim()) {
    const resolvedVault = path.resolve(vaultPath);
    const sibling = `${resolvedVault}-Data`;
    if (fs.existsSync(path.join(sibling, 'runtime', 'state.sqlite'))) {
      return sibling;
    }
  }
  const configPath = path.join(os.homedir(), '.mindloom', 'config.json');
  if (fs.existsSync(configPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8')) as { dataPath?: string };
      if (cfg.dataPath) return path.resolve(cfg.dataPath);
    } catch {
      // ignore
    }
  }
  return vaultPath ? `${path.resolve(vaultPath)}-Data` : path.join(os.homedir(), 'Documents', 'Obsidian', 'MindLoom-Data');
}

export class CliBridge {
  private getSettings: () => MindLoomSettings;
  private getVaultPath: () => string;
  private execFn: ExecFileFn;

  constructor(
    getSettings: () => MindLoomSettings,
    getVaultPath: () => string,
    execFn: ExecFileFn = execFile as unknown as ExecFileFn
  ) {
    this.getSettings = getSettings;
    this.getVaultPath = getVaultPath;
    this.execFn = execFn;
  }

  resolvePaths(): { vaultPath: string; dataPath: string; cliPath: string; nodePath: string; timeoutMs: number } {
    const settings = this.getSettings();
    const vaultPath = settings.vaultPath?.trim() || this.getVaultPath();
    const dataPath = resolveDefaultDataPath(vaultPath, settings.dataPath);
    const cliPath = resolveDefaultCliPath(dataPath, settings.cliPath);
    const nodePath = resolveNodeExecutable(settings.nodePath);
    const timeoutMs = Number(settings.timeoutMs) > 0 ? Number(settings.timeoutMs) : 25000;
    return { vaultPath, dataPath, cliPath, nodePath, timeoutMs };
  }

  async runRaw(args: string[], options: { timeoutMs?: number; includeVaultData?: boolean } = {}): Promise<CliResult<string>> {
    const { vaultPath, dataPath, cliPath, nodePath, timeoutMs } = this.resolvePaths();
    if (!cliPath || !fs.existsSync(cliPath)) {
      return {
        ok: false,
        stdout: '',
        stderr: '',
        exitCode: 1,
        error: `MindLoom CLI not found at "${cliPath || '<unset>'}". Run "mem setup" or configure CLI path in Settings.`
      };
    }

    const fullArgs = [cliPath, ...args];
    if (options.includeVaultData !== false) {
      if (vaultPath && !args.includes('--vault')) {
        fullArgs.push('--vault', vaultPath);
      }
      if (dataPath && !args.includes('--data')) {
        fullArgs.push('--data', dataPath);
      }
    }

    const effectiveTimeout = options.timeoutMs ?? timeoutMs;

    return await new Promise<CliResult<string>>((resolve) => {
      this.execFn(
        nodePath,
        fullArgs,
        {
          timeout: effectiveTimeout,
          maxBuffer: 8 * 1024 * 1024,
          windowsHide: true
        },
        (err, stdout, stderr) => {
          const outText = String(stdout || '');
          const errText = String(stderr || '');
          if (err) {
            const anyErr = err as Error & { code?: number | string; killed?: boolean };
            const timedOut = Boolean(anyErr.killed);
            const code = typeof anyErr.code === 'number' ? anyErr.code : 1;
            const msg = timedOut
              ? `CLI timed out after ${effectiveTimeout}ms`
              : errText.trim() || anyErr.message || 'CLI command failed';
            resolve({
              ok: false,
              stdout: outText,
              stderr: errText,
              exitCode: code,
              error: msg
            });
            return;
          }
          resolve({
            ok: true,
            data: outText,
            stdout: outText,
            stderr: errText,
            exitCode: 0
          });
        }
      );
    });
  }

  async runJson<T>(args: string[], options: { timeoutMs?: number; includeVaultData?: boolean } = {}): Promise<CliResult<T>> {
    const finalArgs = args.includes('--json') ? args : [...args, '--json'];
    const raw = await this.runRaw(finalArgs, options);
    if (!raw.ok) {
      return {
        ok: false,
        stdout: raw.stdout,
        stderr: raw.stderr,
        exitCode: raw.exitCode,
        error: raw.error
      };
    }
    try {
      const parsed = parseJsonOutput<T>(raw.stdout);
      return {
        ok: true,
        data: parsed,
        stdout: raw.stdout,
        stderr: raw.stderr,
        exitCode: 0
      };
    } catch (parseErr) {
      return {
        ok: false,
        stdout: raw.stdout,
        stderr: raw.stderr,
        exitCode: 1,
        error: parseErr instanceof Error ? parseErr.message : String(parseErr)
      };
    }
  }

  readLastAutoSyncTime(): string | null {
    const { dataPath } = this.resolvePaths();
    if (!dataPath) return null;
    const candidates: number[] = [];

    const latestJsonPath = path.join(dataPath, 'runtime', 'logs', 'auto-sync-latest.json');
    if (fs.existsSync(latestJsonPath)) {
      try {
        const latest = JSON.parse(fs.readFileSync(latestJsonPath, 'utf8')) as { executedAt?: string };
        const ts = latest.executedAt ? Date.parse(latest.executedAt) : NaN;
        if (Number.isFinite(ts)) candidates.push(ts);
      } catch {
        // ignore invalid json
      }
    }

    const logPath = path.join(dataPath, 'runtime', 'logs', 'auto-sync-runner.log');
    if (fs.existsSync(logPath)) {
      try {
        const st = fs.statSync(logPath);
        if (Number.isFinite(st.mtimeMs)) candidates.push(st.mtimeMs);
      } catch {
        // ignore stat error
      }
    }

    if (candidates.length > 0) {
      return new Date(Math.max(...candidates)).toISOString();
    }

    const cfgPath = path.join(dataPath, 'manifests', 'auto-sync-config.json');
    if (fs.existsSync(cfgPath)) {
      try {
        const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as { issuedAt?: string };
        return cfg.issuedAt || null;
      } catch {
        return null;
      }
    }
    return null;
  }
}
