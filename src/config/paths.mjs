import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const MIN_NODE_VERSION = Object.freeze({ major: 22, minor: 15, patch: 0, label: '22.15.0' });

export function isNodeVersionSupported(versionStr = process.versions.node) {
  const parts = String(versionStr || '')
    .replace(/^v/i, '')
    .split('.')
    .map((n) => Number.parseInt(n, 10));
  const major = Number.isFinite(parts[0]) ? parts[0] : 0;
  const minor = Number.isFinite(parts[1]) ? parts[1] : 0;
  if (major >= 24) return true;
  if (major === 23) return minor >= 8;
  if (major === 22) return minor >= 15;
  return false;
}

export function resolveCanonicalPath(targetPath, { preserveCase = false } = {}) {
  const resolved = path.resolve(String(targetPath || ''));
  const segments = [];
  let cur = resolved;
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) break;
    segments.unshift(path.basename(cur));
    cur = parent;
  }
  let base = cur;
  if (fs.existsSync(cur)) {
    try {
      base = fs.realpathSync(cur);
    } catch {
      base = cur;
    }
  }
  const joined = path.resolve(segments.length > 0 ? path.join(base, ...segments) : base);
  if (process.platform === 'win32' && !preserveCase) {
    return joined.toLowerCase();
  }
  return joined;
}

export function isSubPathOrSame(parentDir, candidatePath) {
  const normParent = resolveCanonicalPath(parentDir);
  const normCand = resolveCanonicalPath(candidatePath);
  const rel = path.relative(normParent, normCand);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function isSameCanonicalPath(pathA, pathB) {
  return resolveCanonicalPath(pathA) === resolveCanonicalPath(pathB);
}

export function getDefaultVaultPath(homeDir = os.homedir()) {
  return path.join(homeDir, 'Documents', 'Obsidian', 'MindLoom');
}

export function getDefaultDataPath(homeDir = os.homedir()) {
  return path.join(homeDir, 'Documents', 'Obsidian', 'MindLoom-Data');
}

export function getDefaultOperatorRoot(platform = process.platform, env = process.env, homeDir = os.homedir()) {
  if (platform === 'win32') {
    return path.join(env.ProgramData || 'C:\\ProgramData', 'MindLoom');
  }
  return path.join(homeDir, '.mindloom-operator');
}

export function getDefaultConfigPath(env = process.env, homeDir = os.homedir()) {
  return env.MINDLOOM_CONFIG || env.AGENT_MEMORY_CONFIG || path.join(homeDir, '.mindloom', 'config.json');
}

export function getConfiguredSourceRoots(options = {}) {
  const env = options.env || process.env;
  const homeDir = options.homeDir || env.USERPROFILE || env.HOME || os.homedir();
  const hasCustomCodex = Boolean(options.codexHome || env.AGENT_MEMORY_CODEX_HOME || env.MINDLOOM_CODEX_HOME);
  const codexRoot =
    options.codexHome ||
    env.AGENT_MEMORY_CODEX_HOME ||
    env.MINDLOOM_CODEX_HOME ||
    path.join(homeDir, '.codex', 'sessions');
  const codexArchivedRoot =
    options.codexArchivedDir !== undefined
      ? options.codexArchivedDir
      : hasCustomCodex
        ? null
        : path.join(homeDir, '.codex', 'archived_sessions');
  const agyRoot =
    options.antigravityBrainDir ||
    env.AGENT_MEMORY_ANTIGRAVITY_BRAIN_DIR ||
    env.MINDLOOM_ANTIGRAVITY_BRAIN_DIR ||
    path.join(homeDir, '.gemini', 'antigravity', 'brain');
  const dshRoot =
    options.dshHome ||
    env.AGENT_MEMORY_DSH_HOME ||
    env.MINDLOOM_DSH_HOME ||
    path.join(homeDir, '.dsh', 'sessions');
  return { codexRoot, codexArchivedRoot, agyRoot, dshRoot };
}

export function readInstallConfig(configPath = getDefaultConfigPath()) {
  if (!configPath || !fs.existsSync(configPath)) return {};
  try {
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

export function resolveConfiguredPaths(options = {}) {
  const env = options.env || process.env;
  const homeDir = options.homeDir || os.homedir();
  const configPath = options.configPath || getDefaultConfigPath(env, homeDir);
  const cfg = readInstallConfig(configPath);

  const vaultPath = path.resolve(
    options.vaultPath ||
      env.MINDLOOM_VAULT ||
      env.AGENT_MEMORY_VAULT ||
      cfg.vaultPath ||
      getDefaultVaultPath(homeDir)
  );

  const dataPath = path.resolve(
    options.dataPath ||
      env.MINDLOOM_DATA ||
      env.AGENT_MEMORY_DATA ||
      cfg.dataPath ||
      getDefaultDataPath(homeDir)
  );

  const operatorRoot = path.resolve(
    options.operatorRoot ||
      env.MINDLOOM_OPERATOR_ROOT ||
      cfg.operatorRoot ||
      getDefaultOperatorRoot(options.platform || process.platform, env, homeDir)
  );

  return {
    configPath,
    vaultPath,
    dataPath,
    deployDir: path.join(dataPath, 'cli'),
    operatorRoot
  };
}

export function writeInstallConfig({
  vaultPath,
  dataPath,
  operatorRoot = null,
  configPath = getDefaultConfigPath(),
  extra = {}
}) {
  const payload = {
    schema_version: 1,
    vaultPath: path.resolve(vaultPath),
    dataPath: path.resolve(dataPath),
    ...(operatorRoot ? { operatorRoot: path.resolve(operatorRoot) } : {}),
    updatedAt: new Date().toISOString(),
    ...extra
  };
  const serialized = JSON.stringify(payload, null, 2) + '\n';

  if (configPath) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, serialized, 'utf8');
  }

  const manifestPath = path.join(path.resolve(dataPath), 'manifests', 'install-config.json');
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, serialized, 'utf8');

  return { configPath, manifestPath, config: payload };
}
