import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import readline from 'node:readline/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { initRepository, ensureMissingTemplates } from '../init.mjs';
import { openExistingDatabase } from '../db/sqlite.mjs';
import { initGitRepo } from '../git/repo-manager.mjs';
import { listDiscoverableSessions } from '../ingest/session-ingestor.mjs';
import { extractAntigravityCwdHint } from '../ingest/adapters/antigravity-adapter.mjs';
import { issueTrustedLowSensitivityApproval } from '../security/trusted-approvals.mjs';
import { withWriteLock } from '../storage/write-lock.mjs';
import {
  assertVaultDataIsolation,
  ensureInstanceIdentity,
  readInstanceIdentity,
  validateVaultDataPairing
} from '../storage/instance-identity.mjs';
import {
  getConfiguredSourceRoots,
  isNodeVersionSupported,
  resolveConfiguredPaths,
  writeInstallConfig
} from '../config/paths.mjs';
import { generateSchedulePlan, applySchedulePlan } from '../schedule/scheduler.mjs';
import { runDeploy } from '../../cli/deploy.mjs';

export { extractAntigravityCwdHint };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const DEFAULT_REPO_ROOT = path.resolve(__dirname, '../..');

export const AGENT_ENV_VARS = Object.freeze([
  'ANTIGRAVITY_AGENT',
  'CODEX_SANDBOX',
  'CODEX_CI',
  'CODEX_THREAD_ID',
  'CLAUDECODE',
  'GEMINI_CLI',
  'CURSOR_AGENT',
  'CI'
]);

export function checkTrustedHumanTerminal({ env = process.env, isTty = Boolean(process.stdin?.isTTY) } = {}) {
  for (const key of AGENT_ENV_VARS) {
    if (env[key]) {
      return {
        ok: false,
        exitCode: 43,
        reason: `ACCESS_DENIED (EXIT 43): automated agent environment (${key}) cannot authorize auto-sync tickets.`
      };
    }
  }
  if (!isTty) {
    return {
      ok: false,
      exitCode: 43,
      reason: 'ACCESS_DENIED (EXIT 43): interactive human TTY is required to authorize auto-sync tickets.'
    };
  }
  return { ok: true, exitCode: 0, reason: null };
}

export async function runPreflightChecks({ vaultPath, dataPath }) {
  const nodeOk = isNodeVersionSupported(process.versions.node);

  let sqliteOk = false;
  try {
    const { DatabaseSync } = await import('node:sqlite');
    const memDb = new DatabaseSync(':memory:');
    const row = memDb.prepare('SELECT 1 as ok').get();
    memDb.close();
    sqliteOk = Boolean(row && row.ok === 1);
  } catch {
    sqliteOk = false;
  }

  let zstdOk = false;
  try {
    if (typeof zlib.zstdCompressSync === 'function' && typeof zlib.zstdDecompressSync === 'function') {
      const roundtrip = zlib
        .zstdDecompressSync(zlib.zstdCompressSync(Buffer.from('mindloom-setup', 'utf8')))
        .toString('utf8');
      zstdOk = roundtrip === 'mindloom-setup';
    }
  } catch {
    zstdOk = false;
  }

  let gitOk = false;
  let gitVersion = null;
  try {
    gitVersion = execFileSync('git', ['--version'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
    gitOk = Boolean(gitVersion);
  } catch {
    gitOk = false;
  }

  const resolvedVault = path.resolve(vaultPath);
  const resolvedData = path.resolve(dataPath);
  const vaultRoot = path.parse(resolvedVault).root.toLowerCase();
  const dataRoot = path.parse(resolvedData).root.toLowerCase();
  const sameVolume = vaultRoot === dataRoot;

  return {
    ok: nodeOk && sqliteOk && zstdOk && gitOk,
    nodeVersion: process.version,
    nodeOk,
    sqliteOk,
    zstdOk,
    gitOk,
    gitVersion,
    sameVolume,
    vaultRoot,
    dataRoot
  };
}

function normalizeDirPath(p) {
  const resolved = path.resolve(String(p || ''));
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isGenericContainerPath(dirPath, homeDir = os.homedir(), { hasGit = false } = {}) {
  const norm = normalizeDirPath(dirPath).replace(/[\\/]+$/, '');
  const homeNorm = normalizeDirPath(homeDir).replace(/[\\/]+$/, '');
  const tmpNorm = normalizeDirPath(os.tmpdir()).replace(/[\\/]+$/, '');
  const rootNorm = normalizeDirPath(path.parse(dirPath).root).replace(/[\\/]+$/, '');
  if (!norm || norm === rootNorm || norm === homeNorm || norm === tmpNorm) return true;
  if (!hasGit && (norm.startsWith(tmpNorm + path.sep) || norm.includes(`${path.sep}appdata${path.sep}`))) return true;
  if (norm.includes(`${path.sep}.codex`) || norm.includes(`${path.sep}.gemini`) || norm.includes(`${path.sep}.dsh`)) return true;
  const genericNames = new Set([
    'documents',
    'desktop',
    'downloads',
    'projects',
    'work',
    'workspace',
    'workspaces',
    'src',
    'tmp',
    'temp',
    'codex',
    'antigravity',
    'deepseek',
    '.codex',
    '.gemini',
    '.dsh'
  ]);
  const base = path.basename(norm).toLowerCase();
  if (genericNames.has(base)) return true;
  if (norm.toLowerCase() === path.join(homeNorm, '.gemini', 'antigravity').toLowerCase()) return true;
  return false;
}

function isProjectMarkerDir(dirPath) {
  for (const marker of ['.git', 'package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'pom.xml', '.obsidian']) {
    if (fs.existsSync(path.join(dirPath, marker))) return true;
  }
  return false;
}

function findGitRoot(startDir) {
  let current = path.resolve(startDir);
  const root = path.parse(current).root;
  while (current && current !== root) {
    if (fs.existsSync(path.join(current, '.git'))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function sanitizeProjectName(rawName) {
  const cleaned = String(rawName || '')
    .replace(/[^A-Za-z0-9._-]+/g, ' ')
    .trim();
  if (!cleaned) return 'Workspace';
  return cleaned
    .split(/[\s._-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

export function discoverCandidateWorkspaces({
  sourceRoots = {},
  homeDir = os.homedir(),
  includeDsh = true
} = {}) {
  const roots = getConfiguredSourceRoots({ ...sourceRoots, homeDir });
  const sessions = listDiscoverableSessions({
    sourceTool: 'all',
    codexHome: roots.codexRoot,
    codexArchivedDir: roots.codexArchivedRoot,
    antigravityBrainDir: roots.agyRoot,
    dshHome: includeDsh ? roots.dshRoot : path.join(os.tmpdir(), '__mindloom_no_dsh__')
  });

  const byRootKey = new Map();
  for (const s of sessions) {
    let cwd = s.cwd || null;
    if (!cwd && s.source_tool === 'antigravity' && s._internal_source_path) {
      cwd = extractAntigravityCwdHint(s._internal_source_path);
    }
    if (!cwd) continue;

    const baseDir = fs.existsSync(cwd) && !fs.statSync(cwd).isDirectory() ? path.dirname(cwd) : cwd;
    const gitRoot = findGitRoot(baseDir);
    const candidateRoot = gitRoot || baseDir;

    if (!fs.existsSync(candidateRoot) || !fs.statSync(candidateRoot).isDirectory()) {
      continue;
    }
    if (isGenericContainerPath(candidateRoot, homeDir, { hasGit: Boolean(gitRoot) })) {
      continue;
    }
    if (!gitRoot && !isProjectMarkerDir(candidateRoot)) {
      continue;
    }

    const key = normalizeDirPath(candidateRoot).replace(/[\\/]+$/, '');
    if (!byRootKey.has(key)) {
      const base = path.basename(candidateRoot) || 'Project';
      const hasGit = fs.existsSync(path.join(candidateRoot, '.git'));
      byRootKey.set(key, {
        project: sanitizeProjectName(base),
        paths: [path.resolve(candidateRoot)],
        git_roots: hasGit ? [path.resolve(candidateRoot)] : [],
        workspace_slugs: s.workspace_slug ? [s.workspace_slug] : [base.toLowerCase()],
        discoveredFrom: [s.source_tool],
        sessionCount: 1
      });
    } else {
      const entry = byRootKey.get(key);
      entry.sessionCount += 1;
      if (!entry.discoveredFrom.includes(s.source_tool)) {
        entry.discoveredFrom.push(s.source_tool);
      }
      if (s.workspace_slug && !entry.workspace_slugs.includes(s.workspace_slug)) {
        entry.workspace_slugs.push(s.workspace_slug);
      }
    }
  }

  // Disambiguate colliding project names while keeping deterministic order
  const usedNames = new Set();
  const candidates = [...byRootKey.values()].sort((a, b) => b.sessionCount - a.sessionCount);
  for (const item of candidates) {
    let name = item.project;
    let suffix = 2;
    while (usedNames.has(name.toLowerCase())) {
      name = `${item.project}${suffix}`;
      suffix++;
    }
    usedNames.add(name.toLowerCase());
    item.project = name;
  }

  return candidates;
}

export function validateProjectMapObject(parsedMap, mapPath = 'project-map.json') {
  if (!parsedMap || typeof parsedMap !== 'object' || Array.isArray(parsedMap)) {
    const err = new Error(`project-map.json 根对象必须是 JSON object (${mapPath})`);
    err.code = 'INVALID_PROJECT_MAP_SCHEMA';
    throw err;
  }

  if (
    parsedMap.schema_version !== undefined &&
    (typeof parsedMap.schema_version !== 'number' || !Number.isInteger(parsedMap.schema_version))
  ) {
    const err = new Error(`INVALID_PROJECT_MAP_SCHEMA: 字段 schema_version 必须是整数 (${mapPath})`);
    err.code = 'INVALID_PROJECT_MAP_SCHEMA';
    throw err;
  }

  if (parsedMap.default_unmapped_project !== undefined && typeof parsedMap.default_unmapped_project !== 'string') {
    const err = new Error(`INVALID_PROJECT_MAP_SCHEMA: 字段 default_unmapped_project 必须是字符串 (${mapPath})`);
    err.code = 'INVALID_PROJECT_MAP_SCHEMA';
    throw err;
  }

  if (parsedMap.projects !== undefined) {
    if (!Array.isArray(parsedMap.projects)) {
      const err = new Error(`INVALID_PROJECT_MAP_SCHEMA: 字段 projects 必须是数组 (${mapPath})`);
      err.code = 'INVALID_PROJECT_MAP_SCHEMA';
      throw err;
    }

    const stringArrayFields = ['paths', 'git_roots', 'workspace_slugs', 'aliases'];
    for (let idx = 0; idx < parsedMap.projects.length; idx++) {
      const entry = parsedMap.projects[idx];
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        const err = new Error(`INVALID_PROJECT_MAP_SCHEMA: 字段 projects[${idx}] 必须是对象 (${mapPath})`);
        err.code = 'INVALID_PROJECT_MAP_SCHEMA';
        throw err;
      }
      if (typeof entry.project !== 'string' || !entry.project.trim()) {
        const err = new Error(`INVALID_PROJECT_MAP_SCHEMA: 字段 projects[${idx}].project 必须是非空字符串 (${mapPath})`);
        err.code = 'INVALID_PROJECT_MAP_SCHEMA';
        throw err;
      }
      for (const field of stringArrayFields) {
        if (entry[field] === undefined) continue;
        if (!Array.isArray(entry[field])) {
          const err = new Error(`INVALID_PROJECT_MAP_SCHEMA: 字段 projects[${idx}].${field} 必须是字符串数组 (${mapPath})`);
          err.code = 'INVALID_PROJECT_MAP_SCHEMA';
          throw err;
        }
        for (let j = 0; j < entry[field].length; j++) {
          if (typeof entry[field][j] !== 'string') {
            const err = new Error(
              `INVALID_PROJECT_MAP_SCHEMA: 字段 projects[${idx}].${field}[${j}] 必须是字符串 (${mapPath})`
            );
            err.code = 'INVALID_PROJECT_MAP_SCHEMA';
            throw err;
          }
        }
      }
    }
  }

  return parsedMap;
}

export function mergeProjectMapEntries(existingMap, newEntries) {
  const base =
    existingMap && typeof existingMap === 'object'
      ? {
          schema_version: existingMap.schema_version || 1,
          default_unmapped_project: existingMap.default_unmapped_project || 'unmapped',
          projects: Array.isArray(existingMap.projects)
            ? existingMap.projects.map((p) => ({
                ...p,
                paths: Array.isArray(p.paths) ? [...p.paths] : [],
                git_roots: Array.isArray(p.git_roots) ? [...p.git_roots] : [],
                workspace_slugs: Array.isArray(p.workspace_slugs) ? [...p.workspace_slugs] : []
              }))
            : []
        }
      : {
          schema_version: 1,
          default_unmapped_project: 'unmapped',
          projects: []
        };

  const existingByName = new Map(base.projects.map((p) => [String(p.project || '').toLowerCase(), p]));
  const existingNormPaths = new Set(
    base.projects.flatMap((p) => [...(p.paths || []), ...(p.git_roots || [])]).map((p) => normalizeDirPath(p))
  );

  const addedProjects = [];
  for (const entry of newEntries) {
    const cleanEntry = {
      project: entry.project,
      paths: [...new Set(entry.paths || [])],
      git_roots: [...new Set(entry.git_roots || [])],
      workspace_slugs: [...new Set(entry.workspace_slugs || [])]
    };
    const pathOverlap = [...cleanEntry.paths, ...cleanEntry.git_roots].some((p) =>
      existingNormPaths.has(normalizeDirPath(p))
    );
    if (pathOverlap) continue;

    let finalName = cleanEntry.project;
    let idx = 2;
    while (existingByName.has(finalName.toLowerCase())) {
      finalName = `${cleanEntry.project}${idx++}`;
    }
    cleanEntry.project = finalName;
    base.projects.push(cleanEntry);
    existingByName.set(finalName.toLowerCase(), cleanEntry);
    for (const p of [...cleanEntry.paths, ...cleanEntry.git_roots]) {
      existingNormPaths.add(normalizeDirPath(p));
    }
    addedProjects.push(finalName);
  }

  return { projectMap: base, addedProjects };
}

function stripUtf8Bom(text) {
  return String(text || '').replace(/^\uFEFF/, '');
}

function writeFileAtomicSameDir(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(dir, `.${path.basename(targetPath)}.tmp-${process.pid}-${crypto.randomUUID()}`);
  try {
    fs.writeFileSync(tmpPath, content, 'utf8');
    fs.renameSync(tmpPath, targetPath);
  } finally {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // ignore cleanup error
    }
  }
}

const REQUIRED_PLUGIN_ASSETS = Object.freeze(['manifest.json', 'main.js', 'styles.css']);

export function prepareCompanionPluginPlan({
  vaultPath,
  dataPath,
  pluginDistDir = path.join(DEFAULT_REPO_ROOT, 'plugin', 'dist'),
  pluginId = 'mindloom',
  nodePath = process.execPath
} = {}) {
  const resolvedVault = path.resolve(vaultPath);
  const resolvedData = path.resolve(dataPath);
  const obsidianDir = path.join(resolvedVault, '.obsidian');
  const pluginsDir = path.join(obsidianDir, 'plugins');
  const targetPluginDir = path.join(pluginsDir, pluginId);
  const communityPluginsPath = path.join(obsidianDir, 'community-plugins.json');
  const pluginDataPath = path.join(targetPluginDir, 'data.json');

  if (!fs.existsSync(pluginDistDir)) {
    const err = new Error(`PLUGIN_DIST_INCOMPLETE: 插件构建目录不存在 (${pluginDistDir})，请先构建插件或传入 --skip-plugin`);
    err.code = 'PLUGIN_DIST_INCOMPLETE';
    throw err;
  }

  const missingAssets = [];
  for (const fileName of REQUIRED_PLUGIN_ASSETS) {
    const src = path.join(pluginDistDir, fileName);
    if (!fs.existsSync(src) || !fs.statSync(src).isFile() || fs.statSync(src).size === 0) {
      missingAssets.push(fileName);
    }
  }
  if (missingAssets.length > 0) {
    const err = new Error(
      `PLUGIN_DIST_INCOMPLETE: 缺少必需插件构建产物 (${missingAssets.join(', ')}) in ${pluginDistDir}，请先构建插件或传入 --skip-plugin`
    );
    err.code = 'PLUGIN_DIST_INCOMPLETE';
    throw err;
  }

  try {
    const manifestObj = JSON.parse(stripUtf8Bom(fs.readFileSync(path.join(pluginDistDir, 'manifest.json'), 'utf8')));
    if (!manifestObj || typeof manifestObj !== 'object' || typeof manifestObj.id !== 'string' || !manifestObj.id.trim() || typeof manifestObj.version !== 'string' || !manifestObj.version.trim()) {
      throw new Error('manifest.json missing id or version');
    }
  } catch (err) {
    const manifestErr = new Error(
      `INVALID_PLUGIN_MANIFEST: 无法解析插件 manifest.json (${err.message})，已中止安装`
    );
    manifestErr.code = 'INVALID_PLUGIN_MANIFEST';
    throw manifestErr;
  }

  // Validate existing community-plugins.json & plugin data.json BEFORE copying or modifying any files
  let existingPlugins = [];
  if (fs.existsSync(communityPluginsPath)) {
    const rawPlugins = stripUtf8Bom(fs.readFileSync(communityPluginsPath, 'utf8'));
    let parsedPlugins;
    try {
      parsedPlugins = JSON.parse(rawPlugins);
    } catch (err) {
      const parseErr = new Error(
        `INVALID_COMMUNITY_PLUGINS_JSON: 无法解析 ${communityPluginsPath} (${err.message})，已保留原文件未作修改`
      );
      parseErr.code = 'INVALID_COMMUNITY_PLUGINS_JSON';
      throw parseErr;
    }
    if (!Array.isArray(parsedPlugins) || parsedPlugins.some((x) => typeof x !== 'string' || x.trim().length === 0)) {
      const fmtErr = new Error(
        `INVALID_COMMUNITY_PLUGINS_FORMAT: ${communityPluginsPath} 必须为非空字符串数组，已保留原文件未作修改`
      );
      fmtErr.code = 'INVALID_COMMUNITY_PLUGINS_FORMAT';
      throw fmtErr;
    }
    existingPlugins = [...parsedPlugins];
  }

  let existingData = {};
  if (fs.existsSync(pluginDataPath)) {
    const rawData = stripUtf8Bom(fs.readFileSync(pluginDataPath, 'utf8'));
    let parsedData;
    try {
      parsedData = JSON.parse(rawData);
    } catch (err) {
      const parseErr = new Error(
        `INVALID_PLUGIN_DATA_JSON: 无法解析 ${pluginDataPath} (${err.message})，已保留原文件未作修改`
      );
      parseErr.code = 'INVALID_PLUGIN_DATA_JSON';
      throw parseErr;
    }
    if (!parsedData || typeof parsedData !== 'object' || Array.isArray(parsedData)) {
      const fmtErr = new Error(
        `INVALID_PLUGIN_DATA_FORMAT: ${pluginDataPath} 必须为 JSON 对象，已保留原文件未作修改`
      );
      fmtErr.code = 'INVALID_PLUGIN_DATA_FORMAT';
      throw fmtErr;
    }
    existingData = parsedData;
  }

  return {
    resolvedVault,
    resolvedData,
    pluginDistDir,
    pluginId,
    targetPluginDir,
    communityPluginsPath,
    pluginDataPath,
    existingPlugins,
    existingData,
    nodePath
  };
}

export function applyCompanionPluginPlan(plan) {
  fs.mkdirSync(plan.targetPluginDir, { recursive: true });
  const copiedFiles = [];
  for (const fileName of REQUIRED_PLUGIN_ASSETS) {
    const src = path.join(plan.pluginDistDir, fileName);
    fs.copyFileSync(src, path.join(plan.targetPluginDir, fileName));
    copiedFiles.push(fileName);
  }

  const mergedData = {
    ...plan.existingData,
    vaultPath: plan.resolvedVault,
    dataPath: plan.resolvedData,
    cliPath: path.join(plan.resolvedData, 'cli', 'mem.mjs'),
    nodePath: plan.nodePath || plan.existingData.nodePath || process.execPath
  };
  writeFileAtomicSameDir(plan.pluginDataPath, JSON.stringify(mergedData, null, 2) + '\n');

  const enabledPlugins = [...plan.existingPlugins];
  if (!enabledPlugins.includes(plan.pluginId)) {
    enabledPlugins.push(plan.pluginId);
  }
  writeFileAtomicSameDir(plan.communityPluginsPath, JSON.stringify(enabledPlugins, null, 2) + '\n');

  return {
    deployed: true,
    status: 'deployed',
    pluginId: plan.pluginId,
    targetPluginDir: plan.targetPluginDir,
    copiedFiles,
    communityPluginsPath: plan.communityPluginsPath,
    enabledPlugins
  };
}

export function deployCompanionPlugin(options = {}) {
  const plan = prepareCompanionPluginPlan(options);
  return applyCompanionPluginPlan(plan);
}

export async function runSetupWizard(options = {}) {
  const repoRoot = path.resolve(options.repoRoot || DEFAULT_REPO_ROOT);
  const env = options.env || process.env;
  const isTty = options.isTty !== undefined ? Boolean(options.isTty) : Boolean(process.stdin?.isTTY);

  // Fail fast before mutating any filesystem state if --authorize-autosync is called from untrusted context
  if (options.authorizeAutosync) {
    const gate = checkTrustedHumanTerminal({ env, isTty });
    if (!gate.ok) {
      const err = new Error(gate.reason);
      err.exitCode = gate.exitCode;
      err.code = 'ERR_UNTRUSTED_AUTO_SYNC_AUTH';
      throw err;
    }
  }

  const resolved = resolveConfiguredPaths({
    vaultPath: options.vaultPath,
    dataPath: options.dataPath,
    operatorRoot: options.operatorRoot,
    configPath: options.configPath,
    env
  });

  const isInteractive = !options.yes && !options.nonInteractive && (typeof options.promptFn === 'function' || isTty);
  const askUser = async (questionText) => {
    if (typeof options.promptFn === 'function') {
      return await options.promptFn(questionText);
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      return await rl.question(questionText);
    } finally {
      rl.close();
    }
  };

  let vaultPath = resolved.vaultPath;
  let dataPath = resolved.dataPath;
  if (isInteractive && !options.vaultPath) {
    const ans = String(await askUser(`Obsidian Vault directory [${vaultPath}]: `) || '').trim();
    if (ans) vaultPath = path.resolve(ans);
  }
  if (isInteractive && !options.dataPath) {
    const defaultData = options.vaultPath || vaultPath !== resolved.vaultPath ? `${vaultPath}-Data` : dataPath;
    const ans = String(await askUser(`MindLoom Data directory [${defaultData}]: `) || '').trim();
    dataPath = ans ? path.resolve(ans) : path.resolve(defaultData);
  }

  // 1. Preflight, isolation/pairing, plugin dist/config validation & prompts (ZERO filesystem writes before all pass)
  const preflight = await runPreflightChecks({ vaultPath, dataPath });
  if (!preflight.ok) {
    throw new Error(
      `SETUP_PREFLIGHT_FAILED: nodeOk=${preflight.nodeOk}, sqliteOk=${preflight.sqliteOk}, zstdOk=${preflight.zstdOk}, gitOk=${preflight.gitOk}`
    );
  }

  assertVaultDataIsolation({ vaultPath, dataPath });

  const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');
  let initStatus = 'already_initialized';
  let needsIdentityMigration = false;
  if (fs.existsSync(dbPath)) {
    const checkDb = openExistingDatabase(dbPath, { readOnly: true });
    try {
      const pairing = validateVaultDataPairing({ db: checkDb, vaultPath, dataPath });
      if (!pairing.ok) {
        const err = new Error(`[${pairing.code}] ${pairing.message}`);
        err.code = pairing.code;
        throw err;
      }
      needsIdentityMigration = !pairing.identityPersisted;
    } finally {
      checkDb.close();
    }
  }

  const projectMapPath = path.join(dataPath, 'manifests', 'project-map.json');
  let prevalidatedExistingMap = null;
  if (fs.existsSync(projectMapPath)) {
    try {
      const parsedMap = JSON.parse(stripUtf8Bom(fs.readFileSync(projectMapPath, 'utf8')));
      prevalidatedExistingMap = validateProjectMapObject(parsedMap, projectMapPath);
    } catch (err) {
      const errCode = err.code === 'INVALID_PROJECT_MAP_SCHEMA' ? 'INVALID_PROJECT_MAP_SCHEMA' : 'INVALID_PROJECT_MAP_JSON';
      const mapErr = new Error(
        `${errCode}: 无法校验 ${projectMapPath} (${err.message})，已中止安装未修改任何文件`
      );
      mapErr.code = errCode;
      throw mapErr;
    }
  }

  const pluginPlan = options.skipPlugin
    ? null
    : prepareCompanionPluginPlan({
        vaultPath,
        dataPath,
        pluginDistDir: options.pluginDistDir || path.join(repoRoot, 'plugin', 'dist')
      });

  const discovered = discoverCandidateWorkspaces({
    sourceRoots: options.sourceRoots || {},
    homeDir: options.homeDir || os.homedir()
  });

  let selectedWorkspaces = discovered;
  if (isInteractive && discovered.length > 0) {
    const answer = await askUser(
      `Discovered ${discovered.length} workspace(s): ${discovered.map((d) => d.project).join(', ')}. Include all in project-map.json? [Y/n] `
    );
    if (/^n(o)?$/i.test(String(answer || '').trim())) {
      selectedWorkspaces = [];
    }
  }

  if (options.authorizeAutosync) {
    let confirmed = false;
    if (typeof options.confirmAuthorizeFn === 'function') {
      confirmed = (await options.confirmAuthorizeFn()) === 'YES';
    } else {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      try {
        const reply = await rl.question(
          'Type YES to authorize 30-day low-sensitivity auto-sync (Codex + Antigravity, DSH excluded) and register scheduler: '
        );
        confirmed = reply.trim() === 'YES';
      } finally {
        rl.close();
      }
    }

    if (!confirmed) {
      const err = new Error('ACCESS_DENIED (EXIT 43): Interactive confirmation not granted.');
      err.exitCode = 43;
      throw err;
    }
  }

  // Pre-compute merged project map BEFORE any filesystem writes so schema/merge errors abort cleanly.
  mergeProjectMapEntries(prevalidatedExistingMap, selectedWorkspaces);

  // 2. Mutating phases (install_config written LAST after all vault/data/plugin writes succeed)
  const completedSteps = [];
  let deployResult;
  let addedProjects = [];
  let pluginResult = { deployed: false, status: 'skipped' };
  let configWrite;
  let authorization = { authorized: false, status: 'skipped' };
  let scheduler = { applied: false, status: 'skipped' };

  try {
    if (!fs.existsSync(dbPath)) {
      initRepository({ vaultPath, dataPath });
      initStatus = 'initialized';
    } else {
      if (needsIdentityMigration) {
        ensureInstanceIdentity({ vaultPath, dataPath });
      }
      ensureMissingTemplates({ vaultPath });
    }
    initGitRepo(vaultPath);
    completedSteps.push('vault_and_data_init');

    deployResult = runDeploy({
      repoRoot,
      targetDir: path.join(dataPath, 'cli'),
      apply: true
    });
    completedSteps.push('cli_deploy');

    ({ addedProjects } = withWriteLock({ dataPath, command: 'setup-project-map' }, () => {
      let existingMap = null;
      if (fs.existsSync(projectMapPath)) {
        existingMap = validateProjectMapObject(
          JSON.parse(stripUtf8Bom(fs.readFileSync(projectMapPath, 'utf8'))),
          projectMapPath
        );
      }
      const merged = mergeProjectMapEntries(existingMap, selectedWorkspaces);
      writeFileAtomicSameDir(projectMapPath, JSON.stringify(merged.projectMap, null, 2) + '\n');
      return merged;
    }));
    completedSteps.push('project_map');

    if (pluginPlan) {
      pluginResult = applyCompanionPluginPlan(pluginPlan);
      completedSteps.push('companion_plugin');
    }

    configWrite = writeInstallConfig({
      vaultPath,
      dataPath,
      operatorRoot: resolved.operatorRoot,
      configPath: resolved.configPath,
      extra: { repoRoot }
    });
    completedSteps.push('install_config');

    if (options.authorizeAutosync) {
      const ttlHours = Number(options.ttlHours || 720);
      const issued = withWriteLock({ dataPath, command: 'setup-authorize' }, () => {
        const db = openExistingDatabase(dbPath);
        try {
          const codexAp = issueTrustedLowSensitivityApproval({
            db,
            sourceTool: 'codex',
            sessionId: '*',
            approvedBy: 'human-setup-tty',
            ttlHours,
            trustedHumanContext: true
          });
          const agyAp = issueTrustedLowSensitivityApproval({
            db,
            sourceTool: 'antigravity',
            sessionId: '*',
            approvedBy: 'human-setup-tty',
            ttlHours,
            trustedHumanContext: true
          });
          return {
            codexApprovalId: codexAp.ingestApprovalId,
            antigravityApprovalId: agyAp.ingestApprovalId
          };
        } finally {
          db.close();
        }
      });

      const autoSyncConfigPath = path.join(dataPath, 'manifests', 'auto-sync-config.json');
      const autoSyncCfg = {
        version: 1,
        sourceTool: 'all',
        lookbackDays: 30,
        maxSessionsPerRun: 10,
        codexApprovalId: issued.codexApprovalId,
        antigravityApprovalId: issued.antigravityApprovalId,
        dshApprovalId: null,
        vaultDir: vaultPath,
        dataDir: dataPath,
        ttlHours,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + ttlHours * 3_600_000).toISOString()
      };
      writeFileAtomicSameDir(autoSyncConfigPath, JSON.stringify(autoSyncCfg, null, 2) + '\n');
      authorization = { authorized: true, status: 'issued', autoSyncConfigPath, ...issued };
      completedSteps.push('auto_sync_authorization');

      if (!options.skipScheduler) {
        const effPlatform = options.platform || process.platform;
        const winRunnerCand = path.join(repoRoot, 'scripts', 'auto-sync-memory.ps1');
        const useWinRunner =
          effPlatform === 'win32' &&
          fs.existsSync(winRunnerCand) &&
          !winRunnerCand.replace(/\\/g, '/').includes('/_npx/');
        const plan = generateSchedulePlan({
          platform: effPlatform,
          linuxBackend: options.linuxBackend || 'auto',
          times: options.times || ['12:20', '21:20'],
          memCliPath: path.join(dataPath, 'cli', 'mem.mjs'),
          vaultDir: vaultPath,
          dataDir: dataPath,
          configPath: autoSyncConfigPath,
          runnerScriptPath: useWinRunner ? winRunnerCand : null
        });
        scheduler = applySchedulePlan(plan, { dryRun: Boolean(options.dryRunScheduler) });
        completedSteps.push('scheduler');
      }
    }
  } catch (err) {
    err.completedSteps = [...completedSteps];
    if (!String(err.message || '').includes('completedSteps=')) {
      err.message = `${err.message} [completedSteps=${completedSteps.join(',') || 'none'}]`;
    }
    throw err;
  }

  return {
    ok: true,
    completedSteps,
    preflight,
    initStatus,
    vaultPath,
    dataPath,
    dbPath,
    deploy: {
      targetDir: deployResult.targetDir,
      counts: deployResult.counts
    },
    workspacesDiscovered: discovered.length,
    workspacesAdded: addedProjects,
    projectMapPath,
    installConfig: configWrite,
    plugin: pluginResult,
    authorization,
    scheduler
  };
}
