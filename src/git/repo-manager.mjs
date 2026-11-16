import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';

function sha256Text(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

const ALLOWED_FOLDER_PREFIXES = [
  '00_MOC',
  '10_Readable_Sessions',
  '20_Evidence_Cards',
  '30_Knowledge_Notes',
  '40_Review_Queue',
  '50_Bases_Views',
  '90_Templates',
  '.obsidian'
];

const ALLOWED_ROOT_FILES = new Set([
  '首页.md',
  '.gitignore',
  'README.md'
]);

/**
 * 门禁类别 1：工程代码远程仓库白名单 (§1.1, §5.3)
 * 明确允许工程源码与必要根配置文件（package.json, .gitignore, .env.example 及依赖锁文件等），
 * 严禁混入 Vault / Data 运行态实例数据（raw/, staging/, egress/, runtime/ 等）。
 */
export const ENGINEERING_ALLOWED_FOLDER_PREFIXES = [
  'src',
  'cli',
  'tests',
  'docs',
  'scripts',
  'plugin',
  '.github'
];

export const ENGINEERING_ALLOWED_ROOT_FILES = new Set([
  'README.md',
  'README.zh-CN.md',
  'CONTEXT.md',
  'LICENSE',
  'CONTRIBUTING.md',
  'SECURITY.md',
  'CHANGELOG.md',
  'package.json',
  '.gitignore',
  '.gitattributes',
  '.env.example',
  'package-lock.json',
  'pnpm-lock.yaml',
  'npm-shrinkwrap.json'
]);

const FORBIDDEN_ANYWHERE_SEGMENTS = new Set([
  'agentmemory',
  'agentmemory-data',
  'mindloom-data',
  '.answer-me-with-html',
  '.tmp'
]);

const FORBIDDEN_RUNTIME_DATA_SEGMENTS = new Set([
  'raw',
  'staging',
  'egress',
  'manifests',
  'attachments',
  'runtime'
]);

/**
 * 初始化 Vault 本地 Git 仓库并配置 CJK 路径支持
 * @param {string} vaultDir
 */
export function initGitRepo(vaultDir) {
  if (!fs.existsSync(path.join(vaultDir, '.git'))) {
    execFileSync('git', ['init'], { cwd: vaultDir });
  }
  execFileSync('git', ['config', 'core.quotepath', 'false'], { cwd: vaultDir });
}

/**
 * 门禁类别 2 铁律：核验 Vault 本地 .git 仓库零远端 (git remote 必须为空)
 * @param {string} vaultDir
 * @param {(args: string[], cwd: string) => string} [gitRunner]
 */
export function assertVaultGitNoRemote(vaultDir, gitRunner) {
  if (!vaultDir || !fs.existsSync(path.join(vaultDir, '.git'))) {
    return { ok: true, remotes: [] };
  }
  const defaultRunner = (args, cwd) => {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  };
  const runner = gitRunner || defaultRunner;
  const out = String(runner(['remote'], path.resolve(vaultDir)) || '').trim();
  const remotes = out ? out.split(/\r?\n/).map(s => s.trim()).filter(Boolean) : [];
  if (remotes.length > 0) {
    const err = new Error(
      `VAULT_GIT_REMOTE_FORBIDDEN: 检测到 Vault 本地 .git 配置了远端 (${remotes.join(', ')})！为保护 local_only 笔记本地历史，Vault .git 严禁配置任何 git remote`
    );
    err.code = 'VAULT_GIT_REMOTE_FORBIDDEN';
    throw err;
  }
  return { ok: true, remotes: [] };
}

/**
 * 判断指定文件是否在 AgentMemory Vault 本地 Git 白名单内 (门禁类别 2)
 * @param {string} vaultDir
 * @param {string} filePath
 * @returns {boolean}
 */
export function isWhitelistedVaultPath(vaultDir, filePath) {
  if (!vaultDir || !filePath) return false;

  const normalizedVault = path.resolve(vaultDir);
  const normalizedFile = path.resolve(filePath);

  const rel = path.relative(normalizedVault, normalizedFile).replace(/\\/g, '/');

  // 必须严格在 vaultDir 之内
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    return false;
  }

  // 排除运行态缓存、回收站与第三方插件目录/凭据（避免 Vault .git 误纳入 credentials.json 等文件）
  if (
    rel === '.obsidian/workspace.json' ||
    rel === '.obsidian/workspace-mobile.json' ||
    rel === '.obsidian/cache' ||
    rel.startsWith('.obsidian/cache/') ||
    rel === '.obsidian/plugins' ||
    rel.startsWith('.obsidian/plugins/') ||
    rel === '.trash' ||
    rel.startsWith('.trash/')
  ) {
    return false;
  }

  // 检查根目录允许的文件
  if (ALLOWED_ROOT_FILES.has(rel)) {
    return true;
  }

  // 检查允许的前缀目录
  for (const prefix of ALLOWED_FOLDER_PREFIXES) {
    if (rel === prefix || rel.startsWith(`${prefix}/`)) {
      return true;
    }
  }

  return false;
}

/**
 * 判断指定文件是否在工程代码仓库白名单内 (门禁类别 1)
 * @param {string} repoRoot
 * @param {string} filePath
 * @returns {boolean}
 */
export function isWhitelistedEngineeringPath(repoRoot, filePath) {
  if (!repoRoot || !filePath) return false;

  const normalizedRoot = path.resolve(repoRoot);
  const normalizedFile = path.resolve(filePath);
  const rel = path.relative(normalizedRoot, normalizedFile).replace(/\\/g, '/');

  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    return false;
  }

  const segments = rel.split('/');
  const isCodeFileInSrc = segments[0] === 'src' && /\.(mjs|js|ts)$/i.test(rel);
  for (let i = 0; i < segments.length; i++) {
    const segLower = segments[i].toLowerCase();
    if (FORBIDDEN_ANYWHERE_SEGMENTS.has(segLower)) {
      return false;
    }
    if (FORBIDDEN_RUNTIME_DATA_SEGMENTS.has(segLower)) {
      // 允许 src/egress/*.mjs 等源码模块目录，但严禁任何根目录或非源码数据目录 (raw/, egress/, runtime/ 等)
      if (!(isCodeFileInSrc && i === 1 && segLower === 'egress')) {
        return false;
      }
    }
  }
  const isSyntheticFixture = rel === 'tests/fixtures' || rel.startsWith('tests/fixtures/');
  if (/\.(sqlite|sqlite-wal|sqlite-shm|lock)$/i.test(rel)) {
    return false;
  }
  if (!isSyntheticFixture && /\.(zst|zstd|jsonl)$/i.test(rel)) {
    return false;
  }

  if (ENGINEERING_ALLOWED_ROOT_FILES.has(rel)) {
    return true;
  }

  for (const prefix of ENGINEERING_ALLOWED_FOLDER_PREFIXES) {
    if (rel === prefix || rel.startsWith(`${prefix}/`)) {
      return true;
    }
  }

  return false;
}

/**
 * 门禁类别 1：校验待提交至工程远程仓库的文件列表
 * - 放行 src/, cli/, tests/, docs/ 及 package.json, .gitignore, .env.example, lockfiles 等必要工程文件（无需笔记 privacy YAML）
 * - 严格拦截任何不在工程白名单内的运行态路径，以及任何带有 privacy: local_only 的 Markdown 笔记
 *
 * @param {{ repoRoot: string, filePaths: string[] }} params
 */
export function validateEngineeringCommitPaths({ repoRoot, filePaths = [] }) {
  const blocked = [];
  const allowed = [];

  for (const fp of filePaths) {
    const resolved = path.resolve(repoRoot, fp);
    if (!isWhitelistedEngineeringPath(repoRoot, resolved)) {
      blocked.push({ filePath: fp, reason: 'not_in_engineering_whitelist' });
      continue;
    }

    if (resolved.toLowerCase().endsWith('.md') && fs.existsSync(resolved)) {
      const raw = fs.readFileSync(resolved, 'utf8');
      const { frontmatter, hasFrontmatter } = parseMarkdownFrontmatter(raw);
      if (hasFrontmatter && frontmatter.privacy === 'local_only') {
        blocked.push({ filePath: fp, reason: 'local_only_markdown_forbidden_in_engineering_repo' });
        continue;
      }
    }

    allowed.push(fp);
  }

  return {
    valid: blocked.length === 0,
    allowed,
    blocked
  };
}

/**
 * 门禁类别 3：外部知识同步/导出门禁（严格要求笔记 Schema privacy == 'sanitized' 且与 SQLite 台账一致）
 * - 拒绝任何 privacy == 'local_only'（即使文件名普通、或曾以 sanitized 追踪后降级为 local_only）
 * - 拒绝非标准笔记文件进入外部知识同步
 *
 * @param {{ db?: any, filePaths: string[] }} params
 */
export function validateExternalExportNotes({ db = null, filePaths = [] }) {
  const blocked = [];
  const allowed = [];

  for (const fp of filePaths) {
    if (!fp || !fs.existsSync(fp)) {
      blocked.push({ filePath: fp, reason: 'file_not_found' });
      continue;
    }
    const raw = fs.readFileSync(fp, 'utf8');
    const { frontmatter, hasFrontmatter } = parseMarkdownFrontmatter(raw);
    if (!hasFrontmatter || !frontmatter.id) {
      blocked.push({ filePath: fp, reason: 'missing_note_frontmatter' });
      continue;
    }
    if (frontmatter.privacy !== 'sanitized') {
      blocked.push({
        filePath: fp,
        id: frontmatter.id,
        reason: `privacy_not_sanitized:${frontmatter.privacy || 'missing'}`
      });
      continue;
    }
    if (db) {
      const row = db.prepare('SELECT privacy, status FROM notes WHERE id = ?').get(frontmatter.id);
      if (row && row.privacy !== 'sanitized') {
        blocked.push({
          filePath: fp,
          id: frontmatter.id,
          reason: `sqlite_privacy_mismatch:${row.privacy}`
        });
        continue;
      }
    }
    allowed.push(fp);
  }

  return {
    valid: blocked.length === 0,
    allowed,
    blocked
  };
}

/**
 * 精确提交已发布笔记至 Vault 本地 Git（门禁类别 2：白名单边界 + 零远端校验 + 脏暂存隔离）
 * 允许 local_only 笔记、首页.md、50_Bases_Views/*.base、90_Templates/*.md 进入本地 Vault .git 历史供 mem restore 使用。
 *
 * @param {{
 *   vaultDir: string,
 *   filePath: string,
 *   commitMessage: string,
 *   gitRunner?: (args: string[], cwd: string) => string
 * }} options
 * @returns {{ success: boolean, gitState: 'committed' | 'failed', error?: string }}
 */
export function commitPublishedFile({
  vaultDir,
  filePath,
  commitMessage,
  gitRunner
}) {
  if (!isWhitelistedVaultPath(vaultDir, filePath)) {
    throw new Error(`路径不在 AgentMemory 白名单中，严禁提交到 Git: ${filePath}`);
  }

  const normalizedVault = path.resolve(vaultDir);
  const normalizedFile = path.resolve(filePath);
  const relPath = path.relative(normalizedVault, normalizedFile);

  const defaultRunner = (args, cwd) => {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  };

  const runner = gitRunner || defaultRunner;

  try {
    // 0. 门禁类别 2 强制校验：Vault 本地 .git 严禁配置任何 git remote
    if (!gitRunner && fs.existsSync(path.join(normalizedVault, '.git'))) {
      assertVaultGitNoRemote(normalizedVault, runner);
    }

    // 1. 仅针对当前目标文件执行 git add
    runner(['add', relPath], normalizedVault);

    // 2. 使用 git commit -- <relPath> 隔离提交，绝不吸收暂存区中已有的其他无关修改
    runner(['commit', '-m', commitMessage, '--', relPath], normalizedVault);

    return {
      success: true,
      gitState: 'committed'
    };
  } catch (err) {
    // Git 提交失败（例如配置冲突、锁冲突、或检测到违规远端）
    // 铁律：主流程保持 files_published，绝不回滚已发布的物理笔记！
    return {
      success: false,
      gitState: 'failed',
      error: err.message
    };
  }
}

/**
 * 失败重试：补白名单 Git 提交
 * @param {{
 *   vaultDir: string,
 *   filePath: string,
 *   commitMessage: string,
 *   gitRunner?: (args: string[], cwd: string) => string
 * }} options
 * @returns {{ success: boolean, gitState: 'committed' | 'failed', error?: string }}
 */
export function retryGitCommit(options) {
  return commitPublishedFile(options);
}

/**
 * 核对并结算已发布文件的 Git 状态 (B5 统一结算逻辑)：
 *   - 若 HEAD 已包含预期内容指纹，则直接补齐 committed，不重复提交或误报 failed
 *   - 若工作区磁盘文件已被人工改写且与预期指纹不一致，则标为 needs_review，绝不盲目提交
 *   - 若工作区磁盘与预期一致且尚未提交到 HEAD，则执行白名单精确提交
 *
 * @param {{
 *   vaultDir: string,
 *   filePath: string,
 *   expectedSha256?: string | null,
 *   commitMessage: string,
 *   gitRunner?: (args: string[], cwd: string) => string
 * }} options
 */
export function settlePublishedGitCommit({
  vaultDir,
  filePath,
  expectedSha256 = null,
  commitMessage,
  gitRunner = null
}) {
  if (!isWhitelistedVaultPath(vaultDir, filePath)) {
    throw new Error(`路径不在 AgentMemory 白名单中，严禁提交到 Git: ${filePath}`);
  }
  const normalizedVault = path.resolve(vaultDir);
  const normalizedFile = path.resolve(filePath);
  const relPath = path.relative(normalizedVault, normalizedFile).replace(/\\/g, '/');
  const runner = gitRunner || ((args, cwd) => {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  });

  if (!fs.existsSync(normalizedFile)) {
    return {
      success: false,
      gitState: 'needs_review',
      reason: 'target_file_missing_on_disk'
    };
  }

  const normalizeLf = (text) => String(text || '').replace(/\r\n/g, '\n');
  const diskContent = fs.readFileSync(normalizedFile, 'utf8');
  const diskSha256 = sha256Text(diskContent);
  const diskLfSha256 = sha256Text(normalizeLf(diskContent));

  let headContent = null;
  let headSha256 = null;
  let headLfSha256 = null;
  try {
    headContent = runner(['show', `HEAD:${relPath}`], normalizedVault);
    headSha256 = sha256Text(headContent);
    headLfSha256 = sha256Text(normalizeLf(headContent));
  } catch {
    headContent = null;
    headSha256 = null;
    headLfSha256 = null;
  }

  // 1. 若 HEAD 已提交与该作业一致的内容版本（兼容 core.autocrlf=true 在 Windows 下对 CRLF 做的换行规范化）
  if (expectedSha256 && headSha256 === expectedSha256) {
    return {
      success: true,
      gitState: 'committed',
      reason: diskSha256 === expectedSha256 ? 'already_committed_at_head' : 'already_committed_at_head_worktree_later_edited'
    };
  }
  if (expectedSha256 && diskSha256 === expectedSha256 && headLfSha256 !== null && headLfSha256 === diskLfSha256) {
    return {
      success: true,
      gitState: 'committed',
      reason: 'already_committed_at_head'
    };
  }

  // 2. 若工作区磁盘内容已偏离该作业预期指纹（例如人工编辑后中断），待人工核对，严禁盲目提交
  if (expectedSha256 && diskSha256 !== expectedSha256) {
    return {
      success: false,
      gitState: 'needs_review',
      reason: 'worktree_modified_differs_from_expected_sha256'
    };
  }

  // 3. 若未传 expectedSha256 且工作区本身已与 HEAD 一致（含 CRLF/LF 归一化等价）
  if (!expectedSha256 && headSha256 && (headSha256 === diskSha256 || headLfSha256 === diskLfSha256)) {
    return {
      success: true,
      gitState: 'committed',
      reason: 'already_committed_at_head'
    };
  }

  // 4. 尚未提交到 HEAD 且工作区版本与预期完全一致，正常补提交
  return commitPublishedFile({
    vaultDir: normalizedVault,
    filePath: normalizedFile,
    commitMessage,
    gitRunner
  });
}
