import fs from 'node:fs';
import path from 'node:path';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';

const WINDOWS_RESERVED_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
]);

/**
 * 清洗标题以符合 Windows 文件名与路径规范 (R7)
 * 1. 过滤非法字符 < > : " / \ | ? * 以及控制字符 0x00 - 0x1F
 * 2. 剔除首尾空格和句点
 * 3. 拦截 Windows 保留设备名 (CON, PRN, AUX, NUL, COM1-9, LPT1-9)，自动前缀 _
 * 4. 标题长度截断在 40 字符以内且 UTF-8 字节不超过 120
 *
 * @param {string} title
 * @returns {string}
 */
export function sanitizeTitle(title) {
  if (!title || typeof title !== 'string') {
    return '未命名';
  }

  // 1. 过滤非法字符与控制字符
  let clean = title.replace(/[<>:"/\\|?*\x00-\x1f]/g, '');

  // 2. 剔除首尾空格和句点
  clean = clean.replace(/^[\s.]+|[\s.]+$/g, '');

  if (!clean) {
    clean = '未命名';
  }

  // 3. 检查 Windows 保留设备名
  const baseName = clean.split('.')[0].toUpperCase();
  if (WINDOWS_RESERVED_NAMES.has(baseName)) {
    clean = `_${clean}`;
  }

  // 4. 截断到不超过 40 个字符且 UTF-8 不超过 120 字节
  if (clean.length > 40) {
    clean = clean.slice(0, 40);
  }

  while (Buffer.byteLength(clean, 'utf8') > 120 && clean.length > 0) {
    clean = clean.slice(0, -1);
  }

  // 截断后重新去除可能残留的尾部空格和点
  clean = clean.replace(/[\s.]+$/g, '');
  return clean || '未命名';
}

/**
 * 提取 UUID 后缀（剥离前缀与中划线）
 * @param {string} uuid
 * @param {number} length
 * @returns {string}
 */
export function extractUuidSuffix(uuid, length = 6) {
  if (!uuid || typeof uuid !== 'string') {
    return '000000';
  }
  // 去除可能的 KN- 等前缀与连字符
  const hexOnly = uuid.replace(/^[A-Za-z]+-/, '').replace(/-/g, '');
  if (hexOnly.length <= length) {
    return hexOnly;
  }
  return hexOnly.slice(-length);
}

/**
 * 格式化文件名
 * @param {{ prefix: string, dateStr: string, sourceTool?: string | null, uuid: string, title: string, uuidLength?: number }} options
 * @returns {string}
 */
export function formatFileName({ prefix, dateStr, sourceTool = null, uuid, title, uuidLength = 6 }) {
  const safeTitle = sanitizeTitle(title);
  const suffix = extractUuidSuffix(uuid, uuidLength);
  const cleanTool = sourceTool ? String(sourceTool).toLowerCase().replace(/[^a-z0-9_-]/g, '') : '';
  if (cleanTool) {
    return `${prefix}-${dateStr}-${cleanTool}-${suffix}_${safeTitle}.md`;
  }
  return `${prefix}-${dateStr}-${suffix}_${safeTitle}.md`;
}

/**
 * 校验子路径是否位于父目录之内（支持 Windows 大小写不敏感比较）
 * @param {string} parentPath
 * @param {string} childPath
 * @returns {boolean}
 */
export function isPathWithinOrEqual(parentPath, childPath) {
  const normParent = process.platform === 'win32' ? path.resolve(parentPath).toLowerCase() : path.resolve(parentPath);
  const normChild = process.platform === 'win32' ? path.resolve(childPath).toLowerCase() : path.resolve(childPath);
  const rel = path.relative(normParent, normChild);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * 校验目标路径与其中间目录均未通过符号链接/目录链接越界
 * @param {string} targetPath
 * @param {string} boundaryDir
 * @param {{ followSymlinks?: boolean }} [options]
 */
export function assertPathWithinBoundary(targetPath, boundaryDir, { followSymlinks = false } = {}) {
  if (!boundaryDir) return;
  const resolvedBoundary = path.resolve(boundaryDir);
  const resolvedTarget = path.resolve(targetPath);
  if (!isPathWithinOrEqual(resolvedBoundary, resolvedTarget)) {
    throw new Error(`ERR_PATH_OUTSIDE_BOUNDARY: 路径越出允许目录边界 (${path.basename(resolvedTarget)})`);
  }

  let boundaryReal = resolvedBoundary;
  if (fs.existsSync(resolvedBoundary)) {
    boundaryReal = fs.realpathSync(resolvedBoundary);
  }

  // 检查从边界根目录到目标路径之间的每一级已存在节点（含悬空符号链接），默认拦截符号链接/目录链接
  const tryLstat = (p) => {
    try {
      return fs.lstatSync(p);
    } catch {
      return null;
    }
  };
  const rel = path.relative(resolvedBoundary, resolvedTarget);
  if (rel && rel !== '.') {
    const segments = rel.split(path.sep).filter(Boolean);
    let cursor = resolvedBoundary;
    for (const seg of segments) {
      cursor = path.join(cursor, seg);
      const st = tryLstat(cursor);
      if (!st) break;
      if (!followSymlinks && st.isSymbolicLink()) {
        throw new Error(`ERR_SYMLINK_BLOCKED: 默认禁止跟随符号链接或目录链接 (${seg})`);
      }
      if (fs.existsSync(cursor)) {
        const curReal = fs.realpathSync(cursor);
        if (!isPathWithinOrEqual(boundaryReal, curReal)) {
          throw new Error(`ERR_PATH_OUTSIDE_BOUNDARY: 目标真实路径越出边界 (${seg})`);
        }
      }
    }
  } else {
    const st = tryLstat(resolvedTarget);
    if (st) {
      if (!followSymlinks && st.isSymbolicLink()) {
        throw new Error('ERR_SYMLINK_BLOCKED: 默认禁止扫描根目录为符号链接');
      }
      if (fs.existsSync(resolvedTarget)) {
        const targetReal = fs.realpathSync(resolvedTarget);
        if (!isPathWithinOrEqual(boundaryReal, targetReal)) {
          throw new Error('ERR_PATH_OUTSIDE_BOUNDARY: 扫描根目录真实路径越出边界');
        }
      }
    }
  }
}

/**
 * 共享递归 Markdown 文件扫描器
 * 1. 显式字典序排序，确保跨平台确定性
 * 2. 默认排除 90_Templates/
 * 3. 默认不跟随符号链接/目录链接 (followSymlinks=false)，并结合 lstatSync + realpathSync 防循环与边界逃逸
 *
 * @param {string} dir
 * @param {{
 *   excludeTemplates?: boolean,
 *   followSymlinks?: boolean,
 *   boundaryDir?: string | null
 * }} [options]
 * @returns {string[]}
 */
export function findMarkdownFiles(dir, { excludeTemplates = true, followSymlinks = false, boundaryDir = null } = {}) {
  if (!dir) return [];
  const resolvedDir = path.resolve(dir);
  if (boundaryDir) {
    assertPathWithinBoundary(resolvedDir, boundaryDir, { followSymlinks });
  }

  let rootLstat;
  try {
    rootLstat = fs.lstatSync(resolvedDir);
  } catch (err) {
    if (err && err.code === 'ENOENT') return [];
    throw err;
  }

  if (!followSymlinks && rootLstat.isSymbolicLink()) {
    throw new Error(`ERR_SYMLINK_BLOCKED: 扫描根目录不得为符号链接 (${path.basename(resolvedDir)})`);
  }
  if (!rootLstat.isDirectory()) {
    return [];
  }

  const rootReal = fs.realpathSync(resolvedDir);
  const effBoundary = boundaryDir ? path.resolve(boundaryDir) : resolvedDir;
  const boundaryReal = fs.existsSync(effBoundary) ? fs.realpathSync(effBoundary) : effBoundary;
  if (!isPathWithinOrEqual(boundaryReal, rootReal)) {
    throw new Error(`ERR_PATH_OUTSIDE_BOUNDARY: 扫描根目录越出允许边界 (${path.basename(resolvedDir)})`);
  }

  const normKey = (p) => (process.platform === 'win32' ? p.toLowerCase() : p);
  const visitedDirs = new Set([normKey(rootReal)]);
  const results = [];

  function walk(currentDir) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (excludeTemplates && entry.name === '90_Templates') {
        continue;
      }
      const fullPath = path.join(currentDir, entry.name);
      let lstat;
      try {
        lstat = fs.lstatSync(fullPath);
      } catch {
        continue;
      }

      if (lstat.isSymbolicLink()) {
        if (!followSymlinks) {
          continue;
        }
        let targetReal;
        try {
          targetReal = fs.realpathSync(fullPath);
        } catch {
          continue;
        }
        if (!isPathWithinOrEqual(boundaryReal, targetReal) || !isPathWithinOrEqual(rootReal, targetReal)) {
          continue;
        }
        const stReal = fs.statSync(targetReal);
        if (stReal.isDirectory()) {
          const key = normKey(targetReal);
          if (visitedDirs.has(key)) continue;
          visitedDirs.add(key);
          walk(fullPath);
        } else if (stReal.isFile() && entry.name.toLowerCase().endsWith('.md')) {
          results.push(fullPath);
        }
        continue;
      }

      if (lstat.isDirectory()) {
        const dirReal = fs.realpathSync(fullPath);
        if (!isPathWithinOrEqual(boundaryReal, dirReal) || !isPathWithinOrEqual(rootReal, dirReal)) {
          continue;
        }
        const key = normKey(dirReal);
        if (visitedDirs.has(key)) continue;
        visitedDirs.add(key);
        walk(fullPath);
      } else if (lstat.isFile() && entry.name.toLowerCase().endsWith('.md')) {
        const fileReal = fs.realpathSync(fullPath);
        if (!isPathWithinOrEqual(boundaryReal, fileReal) || !isPathWithinOrEqual(rootReal, fileReal)) {
          continue;
        }
        results.push(fullPath);
      }
    }
  }

  walk(resolvedDir);
  results.sort((a, b) => a.localeCompare(b));
  return results;
}

/**
 * 快速读取 Markdown 文件 Frontmatter 中的 id 字段（仅读取文件前 8KB，避免大文件全量加载）
 * @param {string} filePath
 * @returns {string | null}
 */
export function readFrontmatterIdFast(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const fd = fs.openSync(filePath, 'r');
    try {
      const buf = Buffer.alloc(8192);
      const bytesRead = fs.readSync(fd, buf, 0, buf.length, 0);
      const head = buf.subarray(0, bytesRead).toString('utf8');
      const { frontmatter } = parseMarkdownFrontmatter(head);
      if (frontmatter && frontmatter.id) {
        return String(frontmatter.id).trim();
      }
      if (bytesRead < buf.length) return null;
    } finally {
      fs.closeSync(fd);
    }
    return readFrontmatterId(filePath);
  } catch {
    return null;
  }
}

/**
 * 从 Markdown 文件中读取 YAML id 字段
 * @param {string} filePath
 * @returns {string | null}
 */
export function readFrontmatterId(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath, 'utf8');
    const { frontmatter } = parseMarkdownFrontmatter(content);
    return frontmatter.id ? String(frontmatter.id).trim() : null;
  } catch {
    return null;
  }
}

/**
 * R7 碰撞消歧解析目标路径
 * @param {{
 *   targetDir: string,
 *   prefix: string,
 *   dateStr: string,
 *   sourceTool?: string | null,
 *   uuid: string,
 *   title: string,
 *   existingChecker?: (path: string) => string | null
 * }} params
 * @returns {{ targetPath: string, collided: boolean, expanded: boolean, isRetry: boolean }}
 */
export function resolveTargetFilePath({
  targetDir,
  prefix,
  dateStr,
  sourceTool = null,
  uuid,
  title,
  existingChecker = readFrontmatterId
}) {
  const defaultFileName = formatFileName({ prefix, dateStr, sourceTool, uuid, title, uuidLength: 6 });
  const defaultPath = path.join(targetDir, defaultFileName);

  if (!fs.existsSync(defaultPath)) {
    return {
      targetPath: defaultPath,
      collided: false,
      expanded: false,
      isRetry: false
    };
  }

  // 目标已存在，读取已有文件的 id
  const existingId = existingChecker(defaultPath);

  // 1. 同作业重试场景：复用原路径
  if (existingId && existingId === uuid) {
    return {
      targetPath: defaultPath,
      collided: false,
      expanded: false,
      isRetry: true
    };
  }

  // 2. 碰撞场景：扩展为 12 位 UUID
  const expandedFileName12 = formatFileName({ prefix, dateStr, sourceTool, uuid, title, uuidLength: 12 });
  const expandedPath12 = path.join(targetDir, expandedFileName12);

  if (!fs.existsSync(expandedPath12)) {
    return {
      targetPath: expandedPath12,
      collided: true,
      expanded: true,
      isRetry: false
    };
  }

  // 检查 12 位扩展路径是否为同一作业重试
  const existingId12 = existingChecker(expandedPath12);
  if (existingId12 && existingId12 === uuid) {
    return {
      targetPath: expandedPath12,
      collided: true,
      expanded: true,
      isRetry: true
    };
  }

  // 若仍有极端碰撞，扩展为完整 hex UUID
  const fullPath = path.join(
    targetDir,
    formatFileName({ prefix, dateStr, sourceTool, uuid, title, uuidLength: 32 })
  );
  return {
    targetPath: fullPath,
    collided: true,
    expanded: true,
    isRetry: false
  };
}
