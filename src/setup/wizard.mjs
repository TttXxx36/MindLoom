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
import { issueTrustedLowSensitivityApproval } from '../security/trusted-approvals.mjs';
import { withWriteLock } from '../storage/write-lock.mjs';
import {
  getConfiguredSourceRoots,
  resolveConfiguredPaths,
  writeInstallConfig
} from '../config/paths.mjs';
import { generateSchedulePlan, applySchedulePlan } from '../schedule/scheduler.mjs';
import { runDeploy } from '../../cli/deploy.mjs';

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
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  const nodeOk = nodeMajor >= 22;

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

function extractStringsFromJsonValue(val, out = []) {
  if (typeof val === 'string') {
    out.push(val);
  } else if (Array.isArray(val)) {
    for (const item of val) extractStringsFromJsonValue(item, out);
  } else if (val && typeof val === 'object') {
    for (const v of Object.values(val)) extractStringsFromJsonValue(v, out);
  }
  return out;
}

function matchWorkingDirectoryHint(text) {
  const m = String(text || '').match(
    /Command Working Directory:\s*([A-Za-z]:[\\/][^\r\n<>"|*?\x00]{1,220}|\/[^\r\n<>"|*?\x00]{1,220})/i
  );
  return m && m[1] ? m[1].trim() : null;
}

export function extractAntigravityCwdHint(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  try {
    const fd = fs.openSync(filePath, 'r');
    try {
      const buf = Buffer.allocUnsafe(65536);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      if (n <= 0) return null;
      const head = buf.subarray(0, n).toString('utf8');

      // 1. Prefer proper JSON line parsing so escaped \\ and \n are decoded cleanly
      for (const line of head.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) continue;
        try {
          const parsed = JSON.parse(trimmed);
          const strings = extractStringsFromJsonValue(parsed);
          for (const s of strings) {
            const hit = matchWorkingDirectoryHint(s);
            if (hit) return hit;
          }
        } catch {
          // ignore partial/malformed JSON line
        }
      }

      // 2. Fallback for truncated/raw text: stop before unescaped JSON \n, \r, \t, \"
      const rawMatch = head.match(
        /Command Working Directory:\s*([A-Za-z]:(?:\\\\|[\\/])(?:(?!(?<!\\)\\[nrt"]).){1,220}|\/(?:(?!(?<!\\)\\[nrt"]).){1,220})/i
      );
      if (rawMatch && rawMatch[1]) {
        return rawMatch[1].replace(/\\\\/g, '\\').trim();
      }
      return matchWorkingDirectoryHint(head);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
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

export function mergeProjectMapEntries(existingMap, newEntries) {
  const base =
    existingMap && typeof existingMap === 'object'
      ? {
          schema_version: existingMap.schema_version || 1,
          default_unmapped_project: existingMap.default_unmapped_project || 'unmapped',
          projects: Array.isArray(existingMap.projects) ? existingMap.projects.map((p) => ({ ...p })) : []
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

export function deployCompanionPlugin({
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

  if (!fs.existsSync(pluginDistDir) || !fs.existsSync(path.join(pluginDistDir, 'main.js'))) {
    return {
      deployed: false,
      status: 'plugin_dist_missing',
      pluginDistDir,
      targetPluginDir
    };
  }

  fs.mkdirSync(targetPluginDir, { recursive: true });
  const copiedFiles = [];
  for (const fileName of ['manifest.json', 'main.js', 'styles.css']) {
    const src = path.join(pluginDistDir, fileName);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(targetPluginDir, fileName));
      copiedFiles.push(fileName);
    }
  }

  // Write non-secret plugin data.json defaults if missing, or refresh detected paths cleanly
  const pluginDataPath = path.join(targetPluginDir, 'data.json');
  let existingData = {};
  if (fs.existsSync(pluginDataPath)) {
    try {
      existingData = JSON.parse(fs.readFileSync(pluginDataPath, 'utf8')) || {};
    } catch {
      existingData = {};
    }
  }
  const mergedData = {
    ...existingData,
    vaultPath: resolvedVault,
    dataPath: resolvedData,
    cliPath: path.join(resolvedData, 'cli', 'mem.mjs'),
    nodePath: nodePath || existingData.nodePath || process.execPath
  };
  fs.writeFileSync(pluginDataPath, JSON.stringify(mergedData, null, 2) + '\n', 'utf8');

  // Safely merge .obsidian/community-plugins.json (preserve all user plugins!)
  let existingPlugins = [];
  if (fs.existsSync(communityPluginsPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(communityPluginsPath, 'utf8'));
      if (Array.isArray(parsed)) {
        existingPlugins = parsed.filter((x) => typeof x === 'string' && x.trim().length > 0);
      }
    } catch {
      existingPlugins = [];
    }
  }
  if (!existingPlugins.includes(pluginId)) {
    existingPlugins.push(pluginId);
  }
  fs.writeFileSync(communityPluginsPath, JSON.stringify(existingPlugins, null, 2) + '\n', 'utf8');

  return {
    deployed: true,
    status: 'deployed',
    pluginId,
    targetPluginDir,
    copiedFiles,
    communityPluginsPath,
    enabledPlugins: existingPlugins
  };
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

  // 1. Preflight checks
  const preflight = await runPreflightChecks({ vaultPath, dataPath });
  if (!preflight.ok) {
    throw new Error(
      `SETUP_PREFLIGHT_FAILED: nodeOk=${preflight.nodeOk}, sqliteOk=${preflight.sqliteOk}, zstdOk=${preflight.zstdOk}, gitOk=${preflight.gitOk}`
    );
  }

  // 2. Initialize or verify dual directories
  const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');
  let initStatus = 'already_initialized';
  if (!fs.existsSync(dbPath)) {
    initRepository({ vaultPath, dataPath });
    initStatus = 'initialized';
  } else {
    ensureMissingTemplates({ vaultPath });
  }
  initGitRepo(vaultPath);

  // Deploy CLI runtime into <DataDir>/cli/
  const deployResult = runDeploy({
    repoRoot,
    targetDir: path.join(dataPath, 'cli'),
    apply: true
  });

  // 3. Discover workspaces and update project-map.json
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

  const projectMapPath = path.join(dataPath, 'manifests', 'project-map.json');
  const { addedProjects } = withWriteLock({ dataPath, command: 'setup-project-map' }, () => {
    let existingMap = null;
    if (fs.existsSync(projectMapPath)) {
      try {
        existingMap = JSON.parse(fs.readFileSync(projectMapPath, 'utf8'));
      } catch {
        existingMap = null;
      }
    }
    const merged = mergeProjectMapEntries(existingMap, selectedWorkspaces);
    fs.writeFileSync(projectMapPath, JSON.stringify(merged.projectMap, null, 2) + '\n', 'utf8');
    return merged;
  });

  // 4. Write install config (including repoRoot for copy-ready admin scripts)
  const configWrite = writeInstallConfig({
    vaultPath,
    dataPath,
    operatorRoot: resolved.operatorRoot,
    configPath: resolved.configPath,
    extra: { repoRoot }
  });

  // 5. Deploy companion Obsidian plugin
  const pluginResult = options.skipPlugin
    ? { deployed: false, status: 'skipped' }
    : deployCompanionPlugin({
        vaultPath,
        dataPath,
        pluginDistDir: options.pluginDistDir || path.join(repoRoot, 'plugin', 'dist')
      });

  // 6. Optional interactive human-only auto-sync authorization & scheduler registration
  let authorization = { authorized: false, status: 'skipped' };
  let scheduler = { applied: false, status: 'skipped' };

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
    fs.writeFileSync(autoSyncConfigPath, JSON.stringify(autoSyncCfg, null, 2) + '\n', 'utf8');
    authorization = { authorized: true, status: 'issued', autoSyncConfigPath, ...issued };

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
    }
  }

  return {
    ok: true,
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
