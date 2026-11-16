import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { openDatabase, openExistingDatabase } from '../db/sqlite.mjs';
import { acquireWriteLock, inspectWriteLockFile } from '../storage/write-lock.mjs';
import { recoverInterruptedPublish } from '../storage/atomic-publisher.mjs';
import { scanAndSyncNotes } from '../tombstone/tracker.mjs';
import { buildLocalSearchIndex, searchKnowledge } from '../search/query-engine.mjs';
import { rotateInstanceIdentityOnRestore } from '../storage/instance-identity.mjs';
import {
  lockRestoredCloudApprovals,
  openOperatorDatabase
} from '../security/cloud-approvals.mjs';

const VAULT_EPHEMERAL_BASENAMES = new Set(['workspace.json', 'workspace-mobile.json']);
const VAULT_PLUGIN_CREDENTIAL_BASENAMES = new Set(['credentials.json', 'obsidian_askpass.sh']);
const VAULT_PLUGIN_EPHEMERAL_BASENAMES = new Set(['trending-history.json', 'discovery-index.json']);
const VAULT_PLUGIN_RUNTIME_ALLOWLIST = new Set(['manifest.json', 'main.js', 'styles.css', 'versions.json']);

const publisherLockHandles = new Map();

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function collectFilesRecursive(rootDir, baseDir, area, options = {}) {
  const results = [];
  if (!fs.existsSync(rootDir)) return results;

  const entries = fs.readdirSync(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

    if (options.excludeFn && options.excludeFn(relPath, entry)) {
      continue;
    }

    if (entry.isDirectory()) {
      results.push(...collectFilesRecursive(fullPath, baseDir, area, options));
    } else if (entry.isFile()) {
      const stat = fs.statSync(fullPath);
      results.push({
        area,
        relPath,
        fullPath,
        size: stat.size,
        mtimeMs: stat.mtimeMs,
        sha256: sha256File(fullPath)
      });
    }
  }
  return results;
}

function collectPersistentInventory(vaultPath, dataPath, options = {}) {
  const approvedPluginSet = new Set(
    (options.approvedPluginData || []).map(item => String(item).replace(/\\/g, '/').trim()).filter(Boolean)
  );
  const approvedClaudianSet = new Set(
    (options.approvedClaudianPaths || []).map(item => String(item).replace(/\\/g, '/').trim()).filter(Boolean)
  );
  const excludedPrivateDirs = new Set();
  const excludedPluginConfigs = new Set();

  const vaultFiles = collectFilesRecursive(vaultPath, vaultPath, 'vault', {
    excludeFn: (relPath, entry) => {
      if (relPath === '.trash' || relPath.startsWith('.trash/')) return true;
      if (relPath === '.git/index.lock' || (relPath.startsWith('.git/') && relPath.endsWith('.lock'))) return true;
      if (relPath === '.claudian' || relPath.startsWith('.claudian/')) {
        if (approvedClaudianSet.size === 0) {
          excludedPrivateDirs.add('.claudian/');
          return true;
        }
        if (entry && entry.isDirectory()) {
          return false;
        }
        if (!approvedClaudianSet.has(relPath)) {
          excludedPluginConfigs.add(relPath);
          return true;
        }
        return false;
      }
      if (relPath.startsWith('.obsidian/')) {
        const base = path.posix.basename(relPath);
        if (VAULT_EPHEMERAL_BASENAMES.has(base) || relPath === '.obsidian/cache' || relPath.startsWith('.obsidian/cache/')) {
          return true;
        }
        if (relPath.startsWith('.obsidian/plugins/')) {
          const pluginSegments = relPath.slice('.obsidian/plugins/'.length).split('/');
          if (pluginSegments.slice(1).includes('cache')) {
            return true;
          }
          if (
            VAULT_PLUGIN_CREDENTIAL_BASENAMES.has(base) ||
            VAULT_PLUGIN_EPHEMERAL_BASENAMES.has(base) ||
            /-cache\.json$/i.test(base) ||
            /-index\.json$/i.test(base)
          ) {
            return true;
          }
          if (entry && entry.isFile()) {
            const pluginId = pluginSegments[0] || '';
            const pluginSubRel = pluginSegments.slice(1).join('/');
            if (VAULT_PLUGIN_RUNTIME_ALLOWLIST.has(pluginSubRel)) {
              return false;
            }
            if (
              base === 'data.json' &&
              (approvedPluginSet.has(pluginId) || approvedPluginSet.has(relPath))
            ) {
              return false;
            }
            excludedPluginConfigs.add(relPath);
            return true;
          }
        }
      }
      return false;
    }
  });

  if (options.metaOut) {
    options.metaOut.excludedPrivateDirs = Array.from(excludedPrivateDirs).sort();
    options.metaOut.excludedPluginConfigs = Array.from(excludedPluginConfigs).sort();
    options.metaOut.approvedPluginData = Array.from(approvedPluginSet).sort();
  }

  // 按 §2 完整本机持久化清单收集 Data 目录（显式排除可丢弃重建的 runtime/index/ 与锁文件，强制纳入 runtime/revisions/）
  const dataSubdirs = ['raw', 'attachments', 'manifests', 'staging', 'egress', 'cli'];
  const dataFiles = [];
  for (const sub of dataSubdirs) {
    dataFiles.push(...collectFilesRecursive(path.join(dataPath, sub), dataPath, 'data'));
  }
  const revisionsDir = path.join(dataPath, 'runtime', 'revisions');
  if (fs.existsSync(revisionsDir)) {
    dataFiles.push(...collectFilesRecursive(revisionsDir, dataPath, 'data'));
  }
  const logsDir = path.join(dataPath, 'runtime', 'logs');
  if (fs.existsSync(logsDir)) {
    dataFiles.push(...collectFilesRecursive(logsDir, dataPath, 'data'));
  }
  const benchmarksDir = path.join(dataPath, 'runtime', 'benchmarks');
  if (fs.existsSync(benchmarksDir)) {
    dataFiles.push(...collectFilesRecursive(benchmarksDir, dataPath, 'data'));
  }
  const dataGitignore = path.join(dataPath, '.gitignore');
  if (fs.existsSync(dataGitignore)) {
    const st = fs.statSync(dataGitignore);
    dataFiles.push({
      area: 'data',
      relPath: '.gitignore',
      fullPath: dataGitignore,
      size: st.size,
      mtimeMs: st.mtimeMs,
      sha256: sha256File(dataGitignore)
    });
  }

  return [...vaultFiles, ...dataFiles];
}

function compareInventories(beforeList, afterList) {
  const beforeMap = new Map(beforeList.map(item => [`${item.area}::${item.relPath}`, item]));
  const afterMap = new Map(afterList.map(item => [`${item.area}::${item.relPath}`, item]));
  const changed = [];

  for (const [key, b] of beforeMap) {
    const a = afterMap.get(key);
    if (!a) {
      changed.push({ key, change: 'deleted_during_backup' });
    } else if (a.sha256 !== b.sha256 || a.size !== b.size) {
      changed.push({ key, change: 'modified_during_backup' });
    }
  }
  for (const [key] of afterMap) {
    if (!beforeMap.has(key)) {
      changed.push({ key, change: 'created_during_backup' });
    }
  }
  return changed;
}

function copyDirectoryTree(srcDir, dstDir) {
  if (!fs.existsSync(srcDir)) return;
  if (!fs.existsSync(dstDir)) fs.mkdirSync(dstDir, { recursive: true });
  const entries = fs.readdirSync(srcDir, { withFileTypes: true });
  for (const entry of entries) {
    const src = path.join(srcDir, entry.name);
    const dst = path.join(dstDir, entry.name);
    if (entry.isDirectory()) {
      copyDirectoryTree(src, dst);
    } else if (entry.isFile()) {
      fs.copyFileSync(src, dst);
    }
  }
}

/**
 * 获取本地发布器互斥锁（D3：已统一复用 runtime/write.lock，command='backup'）
 * @param {string} dataPath
 * @returns {string} lockPath
 */
export function acquirePublisherLock(dataPath) {
  const handle = acquireWriteLock({
    dataPath,
    command: 'backup',
    timeoutMs: 0
  });
  publisherLockHandles.set(path.resolve(dataPath), handle);
  return handle.lockPath;
}

export function releasePublisherLock(dataPath) {
  const resolved = path.resolve(dataPath);
  const handle = publisherLockHandles.get(resolved);
  if (handle) {
    publisherLockHandles.delete(resolved);
    handle.release();
  }
  const legacyLockPath = path.join(resolved, 'runtime', 'publisher.lock');
  if (fs.existsSync(legacyLockPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(legacyLockPath, 'utf8'));
      if (Number(parsed?.pid) === process.pid) {
        fs.unlinkSync(legacyLockPath);
      }
    } catch {
      // 非本进程遗留锁交由 mem recover-lock 统一处理，禁止静默删除
    }
  }
}

/**
 * 执行 R4 跨文件一致性备份窗口 (mem backup --target <external-path>)
 * 1. 获取发布器互斥锁（统一 runtime/write.lock）暂停一切写入
 * 2. 捕获备份前全量文件指纹 (size, mtime, sha256)
 * 3. 复制持久化文件并通过 SQLite VACUUM INTO 导出一致性 state.sqlite
 * 4. 捕获后二次核对文件指纹：若捕获期间发生变动则重试或标为 incomplete
 *
 * @param {{
 *   vaultPath: string,
 *   dataPath: string,
 *   targetDir: string,
 *   maxRetries?: number,
 *   duringCaptureHook?: () => void,
 *   approvedPluginData?: string[],
 *   approvedClaudianPaths?: string[],
 *   writeLockHandle?: object | null,
 *   lockTimeoutMs?: number
 * }} params
 */
function isSameOrInside(parentDir, childPath) {
  const rel = path.relative(path.resolve(parentDir), path.resolve(childPath));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function createConsistentBackup({
  vaultPath,
  dataPath,
  targetDir,
  maxRetries = 0,
  duringCaptureHook = null,
  approvedPluginData = [],
  approvedClaudianPaths = [],
  writeLockHandle = null,
  lockTimeoutMs = 0
}) {
  if (isSameOrInside(vaultPath, targetDir) || isSameOrInside(dataPath, targetDir)) {
    throw new Error('INVALID_BACKUP_TARGET: 备份目标目录不能位于 Vault 或 Data 目录内部（必须使用独立目录/介质）');
  }

  const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');
  let ownLockHandle = null;
  if (writeLockHandle) {
    const info = inspectWriteLockFile(writeLockHandle.lockPath);
    if (!info.valid || info.payload?.lock_token !== writeLockHandle.lockToken) {
      throw new Error('INVALID_WRITE_LOCK_HANDLE: 传入的写锁句柄无效或已释放');
    }
  } else {
    ownLockHandle = acquireWriteLock({
      dataPath,
      command: 'backup',
      timeoutMs: lockTimeoutMs
    });
  }
  let db = null;

  try {
    db = openExistingDatabase(dbPath);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    let attempt = 0;
    let lastResult = null;

    while (attempt <= maxRetries) {
      attempt++;
      const now = new Date();
      const backupId = `BKP-${now.toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}`;
      const batchDir = path.join(targetDir, backupId);
      const batchVaultDir = path.join(batchDir, 'AgentMemory');
      const batchDataDir = path.join(batchDir, 'AgentMemory-Data');
      const batchRuntimeDir = path.join(batchDataDir, 'runtime');

      fs.mkdirSync(batchVaultDir, { recursive: true });
      fs.mkdirSync(batchRuntimeDir, { recursive: true });

      // 1. 备份前指纹快照
      const invMeta = {};
      const preInventory = collectPersistentInventory(vaultPath, dataPath, {
        approvedPluginData,
        approvedClaudianPaths,
        metaOut: invMeta
      });

      // 测试钩子：允许在备份窗口期间模拟外部写入竞争
      if (duringCaptureHook && attempt === 1) {
        duringCaptureHook();
      }

      // 2. 复制文件归档
      for (const item of preInventory) {
        const destBase = item.area === 'vault' ? batchVaultDir : batchDataDir;
        const destPath = path.join(destBase, item.relPath);
        const destParent = path.dirname(destPath);
        if (!fs.existsSync(destParent)) {
          fs.mkdirSync(destParent, { recursive: true });
        }
        if (fs.existsSync(item.fullPath)) {
          fs.copyFileSync(item.fullPath, destPath);
        }
      }

      // 3. SQLite 在线一致性备份 (VACUUM INTO)
      const backupDbPath = path.join(batchRuntimeDir, 'state.sqlite');
      const escapedDbPath = backupDbPath.replace(/'/g, "''");
      db.exec(`VACUUM INTO '${escapedDbPath}'`);

      // 4. 备份后二次指纹校验
      const postInventory = collectPersistentInventory(vaultPath, dataPath, {
        approvedPluginData,
        approvedClaudianPaths
      });
      const changedFiles = compareInventories(preInventory, postInventory);
      const status = changedFiles.length === 0 ? 'complete' : 'incomplete';

      const manifest = {
        backup_id: backupId,
        status,
        attempt,
        created_at: now.toISOString(),
        classification: 'local_private_backup_not_for_external_export',
        source_vault_path: path.resolve(vaultPath),
        source_data_path: path.resolve(dataPath),
        file_count: preInventory.length,
        sqlite_included: true,
        revisions_included: true,
        excluded_rebuildable: ['runtime/index', 'runtime/write.lock', 'runtime/write.recovering.lock', 'runtime/publisher.lock', 'runtime/stale-locks', '.obsidian/cache', '.obsidian/plugins/*/cache', '.obsidian/plugins/**/*-cache.json', '.obsidian/plugins/**/*-index.json'],
        excluded_private_dirs: invMeta.excludedPrivateDirs || ['.claudian/'],
        excluded_plugin_configs: invMeta.excludedPluginConfigs || [],
        approved_plugin_data: invMeta.approvedPluginData || [],
        excluded_plugin_credentials: ['.obsidian/plugins/**/credentials.json', '.obsidian/plugins/**/obsidian_askpass.sh'],
        changed_files: changedFiles,
        files: preInventory.map(f => ({
          area: f.area,
          rel_path: f.relPath,
          size: f.size,
          sha256: f.sha256
        }))
      };

      const manifestPath = path.join(batchDir, 'backup-manifest.json');
      fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

      db.prepare(`
        INSERT INTO backups (backup_id, target_dir, status, file_count, changed_files_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(backupId, batchDir, status, preInventory.length, JSON.stringify(changedFiles), now.toISOString());

      lastResult = {
        backupId,
        status,
        attempt,
        backupDir: batchDir,
        manifestPath,
        fileCount: preInventory.length,
        changedFiles,
        classification: manifest.classification,
        excludedPrivateDirs: manifest.excluded_private_dirs,
        excludedPluginConfigsCount: manifest.excluded_plugin_configs.length
      };

      if (status === 'complete') {
        return lastResult;
      }
    }

    return lastResult;
  } finally {
    try {
      if (db) db.close();
    } finally {
      if (ownLockHandle) {
        ownLockHandle.release();
      }
    }
  }
}

function remapPathPrefix(originalPath, oldPrefix, newPrefix) {
  if (!originalPath) return originalPath;
  const normOrig = path.resolve(originalPath);
  const normOld = path.resolve(oldPrefix);
  const normNew = path.resolve(newPrefix);
  if (normOrig.toLowerCase() === normOld.toLowerCase()) {
    return normNew;
  }
  const withSep = normOld.endsWith(path.sep) ? normOld : normOld + path.sep;
  if (normOrig.toLowerCase().startsWith(withSep.toLowerCase())) {
    const rel = normOrig.slice(withSep.length);
    return path.join(normNew, rel);
  }
  return originalPath;
}

/**
 * R4 灾难恢复演练顺序 (§6 严禁先清空 staging/):
 *   1. 将备份数据与 state.sqlite 恢复至新位置（并重映射路径前缀）
 *   2. 先按作业台账恢复/确认每一项未完成操作（对残留硬链接严格按 R1 解除链接并保护 Vault 正式文件，保留未发布唯一候选）
 *   3. 确认所有未完成作业妥善处理后，才清理明确废弃的临时暂存
 *   4. 打开只读核验笔记、附件、SHA-256 指纹、SQLite 完整性与墓碑有效性
 *   5. 最后重建可丢弃的 runtime/index/，跑通检索自检后再开放写入
 *
 * @param {{
 *   backupDir: string,
 *   newVaultPath: string,
 *   newDataPath: string,
 *   allowIncomplete?: boolean,
 *   selfCheckQuery?: string
 * }} params
 */
function isDirectoryEmptyOrMissing(dirPath) {
  if (!fs.existsSync(dirPath)) return true;
  const st = fs.statSync(dirPath);
  if (!st.isDirectory()) return false;
  return fs.readdirSync(dirPath).length === 0;
}

export function restoreFromBackup({
  backupDir,
  newVaultPath,
  newDataPath,
  allowIncomplete = false,
  selfCheckQuery = null,
  isolatedRoot = null,
  operatorDbPath = null
}) {
  const resolvedBackupDir = path.resolve(backupDir);
  const resolvedNewVault = path.resolve(newVaultPath);
  const resolvedNewData = path.resolve(newDataPath);

  const manifestPath = path.join(resolvedBackupDir, 'backup-manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`备份清单不存在: ${manifestPath}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.status !== 'complete' && !allowIncomplete) {
    throw new Error(
      `INCOMPLETE_BACKUP_REJECTED: 备份批次 ${manifest.backup_id} 状态为 incomplete，拒绝作为完好备份恢复 (changed: ${manifest.changed_files?.length || 0})`
    );
  }

  // C-blocker 2: 严禁重叠/嵌套目标，严禁触碰原库、原 Data 或源备份目录
  if (
    isSameOrInside(resolvedNewVault, resolvedNewData) ||
    isSameOrInside(resolvedNewData, resolvedNewVault)
  ) {
    throw new Error(
      `RESTORE_INVALID_TARGET: 恢复目标 Vault (${resolvedNewVault}) 与 Data (${resolvedNewData}) 不能相同或互相嵌套`
    );
  }
  const forbiddenOverlapDirs = [
    { label: 'backupDir', dir: resolvedBackupDir },
    manifest.source_vault_path ? { label: 'source_vault_path', dir: path.resolve(manifest.source_vault_path) } : null,
    manifest.source_data_path ? { label: 'source_data_path', dir: path.resolve(manifest.source_data_path) } : null
  ].filter(Boolean);
  for (const item of forbiddenOverlapDirs) {
    if (
      isSameOrInside(item.dir, resolvedNewVault) ||
      isSameOrInside(resolvedNewVault, item.dir) ||
      isSameOrInside(item.dir, resolvedNewData) ||
      isSameOrInside(resolvedNewData, item.dir)
    ) {
      throw new Error(
        `RESTORE_TARGET_OVERLAP: 恢复目标不得与 ${item.label} (${item.dir}) 重叠或互相包含`
      );
    }
  }
  if (isolatedRoot) {
    const resolvedIsoRoot = path.resolve(isolatedRoot);
    if (
      !isSameOrInside(resolvedIsoRoot, resolvedNewVault) ||
      resolvedNewVault.toLowerCase() === resolvedIsoRoot.toLowerCase() ||
      !isSameOrInside(resolvedIsoRoot, resolvedNewData) ||
      resolvedNewData.toLowerCase() === resolvedIsoRoot.toLowerCase()
    ) {
      throw new Error(
        `RESTORE_OUTSIDE_ISOLATED_ROOT: 恢复目标必须位于专用隔离根目录 (${resolvedIsoRoot}) 的独立子目录内`
      );
    }
  }

  // C-blocker 2: 两个恢复目标必须不存在或完全为空（在删除任何锁/WAL或写入文件前先拒绝）
  if (!isDirectoryEmptyOrMissing(resolvedNewVault)) {
    throw new Error(
      `RESTORE_TARGET_NOT_EMPTY: 恢复目标 Vault 目录非空 (${resolvedNewVault})，禁止覆盖既有内容`
    );
  }
  if (!isDirectoryEmptyOrMissing(resolvedNewData)) {
    throw new Error(
      `RESTORE_TARGET_NOT_EMPTY: 恢复目标 Data 目录非空 (${resolvedNewData})，禁止覆盖既有内容`
    );
  }

  // 按清单对备份源先执行预检（只读校验 SHA-256 指纹与 SQLite 存在性）
  const srcVault = path.join(resolvedBackupDir, 'AgentMemory');
  const srcData = path.join(resolvedBackupDir, 'AgentMemory-Data');
  const srcDbPath = path.join(srcData, 'runtime', 'state.sqlite');
  if (!fs.existsSync(srcDbPath)) {
    throw new Error(`RESTORE_SOURCE_DB_MISSING: 备份源缺失 state.sqlite (${srcDbPath})`);
  }
  const sourceManifestMismatches = [];
  let sourcePreflightCheckedCount = 0;
  for (const f of manifest.files || []) {
    const srcBase = f.area === 'vault' ? srcVault : srcData;
    const srcFile = path.resolve(srcBase, f.rel_path);
    if (!isSameOrInside(srcBase, srcFile)) {
      sourceManifestMismatches.push({ area: f.area, rel_path: f.rel_path, reason: 'invalid_rel_path_traversal' });
      continue;
    }
    if (!fs.existsSync(srcFile)) {
      sourceManifestMismatches.push({ area: f.area, rel_path: f.rel_path, reason: 'missing_in_backup_source' });
    } else if (sha256File(srcFile) !== f.sha256) {
      sourceManifestMismatches.push({ area: f.area, rel_path: f.rel_path, reason: 'source_sha256_mismatch' });
    } else {
      sourcePreflightCheckedCount++;
    }
  }
  if (sourceManifestMismatches.length > 0 && !allowIncomplete) {
    throw new Error(
      `RESTORE_SOURCE_MANIFEST_MISMATCH: 源备份预检失败，发现 ${sourceManifestMismatches.length} 个缺失或指纹不匹配的清单文件`
    );
  }

  // Step 1: 将备份完整复制到已校验为空的新隔离目录（严禁预先清空 staging/）
  copyDirectoryTree(srcVault, resolvedNewVault);
  copyDirectoryTree(srcData, resolvedNewData);

  // 仅清理从备份目录复制过来的残留锁/WAL 副产品（绝不会触碰预先存在的目录，因为目标已校验为空）
  const runtimeDir = path.join(resolvedNewData, 'runtime');
  for (const staleSidecar of ['state.sqlite-wal', 'state.sqlite-shm', 'write.lock', 'write.recovering.lock', 'publisher.lock']) {
    const p = path.join(runtimeDir, staleSidecar);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }

  const restoredDbPath = path.join(resolvedNewData, 'runtime', 'state.sqlite');
  if (!fs.existsSync(restoredDbPath)) {
    throw new Error('恢复后缺少 state.sqlite，无法继续');
  }

  const db = openDatabase(restoredDbPath);
  try {
    // 路径前缀重映射（适应异机/新目录恢复）
    const oldVault = manifest.source_vault_path;
    const oldData = manifest.source_data_path;

    const noteRows = db.prepare('SELECT id, path FROM notes').all();
    for (const row of noteRows) {
      const mapped = remapPathPrefix(row.path, oldVault, resolvedNewVault);
      if (mapped !== row.path) {
        db.prepare('UPDATE notes SET path = ? WHERE id = ?').run(mapped, row.id);
      }
    }

    const intentRows = db.prepare('SELECT operation_id, staging_path, target_path FROM publish_intents').all();
    for (const row of intentRows) {
      const mappedStg = remapPathPrefix(row.staging_path, oldData, resolvedNewData);
      const mappedDst = remapPathPrefix(row.target_path, oldVault, resolvedNewVault);
      db.prepare('UPDATE publish_intents SET staging_path = ?, target_path = ? WHERE operation_id = ?').run(
        mappedStg,
        mappedDst,
        row.operation_id
      );
    }

    const snapRows = db.prepare('SELECT snapshot_id, raw_path, readable_session_path FROM session_snapshots').all();
    for (const row of snapRows) {
      const mappedRaw = remapPathPrefix(row.raw_path, oldData, resolvedNewData);
      const mappedSes = remapPathPrefix(row.readable_session_path, oldVault, resolvedNewVault);
      db.prepare('UPDATE session_snapshots SET raw_path = ?, readable_session_path = ? WHERE snapshot_id = ?').run(
        mappedRaw,
        mappedSes,
        row.snapshot_id
      );
    }

    // Step 2: 先恢复未完成作业（R1 协议处理 linking 残留硬链接，保护用户手改内容，保留未发布的唯一 staging 候选）
    const r1Recovery = recoverInterruptedPublish({ db });
    const r1AffectedTargets = new Set(r1Recovery.details.map(d => path.resolve(d.targetPath)));

    const stagingDir = path.join(resolvedNewData, 'staging');
    const preservedStagingCandidates = [];
    const obsoleteCleaned = [];

    if (fs.existsSync(stagingDir)) {
      const stagingEntries = fs.readdirSync(stagingDir, { withFileTypes: true });
      for (const entry of stagingEntries) {
        const fullStgPath = path.join(stagingDir, entry.name);
        if (entry.isFile() && entry.name.startsWith('stg-') && entry.name.endsWith('.md')) {
          const intentForStg = db
            .prepare('SELECT * FROM publish_intents WHERE staging_path = ?')
            .get(fullStgPath);

          if (!intentForStg || intentForStg.state !== 'files_published') {
            // 未发布的唯一候选：必须保留等待后续恢复或发布！
            preservedStagingCandidates.push(fullStgPath);
          } else {
            // Step 3: 确认该作业已 files_published 后，才可清理明确废弃的暂存文件
            fs.unlinkSync(fullStgPath);
            obsoleteCleaned.push(fullStgPath);
          }
        } else if (entry.isFile() && (entry.name.endsWith('.tmp') || entry.name.endsWith('.obsolete'))) {
          fs.unlinkSync(fullStgPath);
          obsoleteCleaned.push(fullStgPath);
        }
      }

      // 清理明确的临时预览 *.tmp（在未完成作业确认完毕之后执行）
      const previewDir = path.join(stagingDir, 'restore-preview');
      if (fs.existsSync(previewDir)) {
        for (const f of fs.readdirSync(previewDir)) {
          if (f.endsWith('.tmp') || f.endsWith('.obsolete')) {
            const p = path.join(previewDir, f);
            fs.unlinkSync(p);
            obsoleteCleaned.push(p);
          }
        }
      }
    }

    // Step 4: 只读核验 SQLite 完整性、备份文件 SHA-256 指纹、笔记、附件与墓碑有效性
    const integrityRow = db.prepare('PRAGMA integrity_check').get();
    const sqliteIntegrityOk = integrityRow && integrityRow.integrity_check === 'ok';
    if (!sqliteIntegrityOk) {
      throw new Error('RESTORE_INTEGRITY_FAILED: 恢复后的 state.sqlite 未通过 PRAGMA integrity_check');
    }

    const cleanedSet = new Set(obsoleteCleaned.map(p => path.resolve(p)));
    const checksumMismatches = [];
    let verifiedFilesCount = 0;
    for (const f of manifest.files || []) {
      const baseDir = f.area === 'vault' ? resolvedNewVault : resolvedNewData;
      const targetFile = path.resolve(baseDir, f.rel_path);
      if (!isSameOrInside(baseDir, targetFile)) {
        throw new Error(`Backup manifest entry escapes target ${f.area || 'unknown'} directory: ${f.rel_path}`);
      }
      if (cleanedSet.has(targetFile) || r1AffectedTargets.has(targetFile)) continue;
      // R1 recoverInterruptedPublish 也会解除 staging 侧硬链接
      if (f.area === 'data' && f.rel_path.startsWith('staging/stg-') && !fs.existsSync(targetFile)) continue;

      if (!fs.existsSync(targetFile)) {
        checksumMismatches.push({ area: f.area, rel_path: f.rel_path, reason: 'missing_after_restore' });
      } else {
        const actualSha = sha256File(targetFile);
        if (actualSha !== f.sha256) {
          checksumMismatches.push({ area: f.area, rel_path: f.rel_path, reason: 'sha256_mismatch' });
        } else {
          verifiedFilesCount++;
        }
      }
    }
    if (checksumMismatches.length > 0) {
      throw new Error(`RESTORE_CHECKSUM_MISMATCH: ${checksumMismatches.length} 个恢复文件校验异常`);
    }

    const syncReport = scanAndSyncNotes({ db, vaultDir: resolvedNewVault });
    const activeNotesCount = db.prepare("SELECT count(*) as c FROM notes WHERE status = 'active'").get().c;
    const tombstonesCount = db.prepare('SELECT count(*) as c FROM tombstones WHERE item_key IS NOT NULL AND output_uuid IS NOT NULL').get().c;
    const attachmentsDir = path.join(resolvedNewData, 'attachments');
    const attachmentsCount = fs.existsSync(attachmentsDir) ? fs.readdirSync(attachmentsDir).length : 0;

    // Step 5: 最后重建可丢弃的 runtime/index/ 并执行检索自检（纯离线）
    const indexDir = path.join(resolvedNewData, 'runtime', 'index');
    const indexRes = buildLocalSearchIndex({ vaultDir: resolvedNewVault, indexDir });
    const selfCheck = selfCheckQuery
      ? searchKnowledge({ db, vaultDir: resolvedNewVault, query: selfCheckQuery, indexDir })
      : null;

    // Step 6: 轮换恢复实例身份并锁定继承的云端外发批准（仅整库恢复触发；单条 mem restore 绝不触发）
    const instanceIdentity = rotateInstanceIdentityOnRestore({
      vaultPath: resolvedNewVault,
      dataPath: resolvedNewData,
      backupId: manifest.backup_id
    });
    const stateDbLock = lockRestoredCloudApprovals(db, {
      newVaultId: instanceIdentity.vaultId,
      newDataId: instanceIdentity.dataId,
      reason: 'whole_db_restore_locked'
    });
    let operatorDbLock = { hasSchema: false, lockedCount: 0, recoveredRetainedCount: 0 };
    const candidateOperatorDb =
      operatorDbPath || path.join(resolvedNewData, 'runtime', 'operator-state.sqlite');
    if (fs.existsSync(candidateOperatorDb)) {
      const opDb = openOperatorDatabase(candidateOperatorDb, { autoMigrate: false });
      try {
        operatorDbLock = lockRestoredCloudApprovals(opDb, {
          newVaultId: instanceIdentity.vaultId,
          newDataId: instanceIdentity.dataId,
          reason: 'whole_db_restore_locked'
        });
      } finally {
        opDb.close();
      }
    }

    return {
      restored: true,
      backupId: manifest.backup_id,
      newVaultPath: resolvedNewVault,
      newDataPath: resolvedNewData,
      instanceIdentity,
      cloudRestoreLock: {
        stateDbLock,
        operatorDbLock
      },
      r1Recovery,
      preservedStagingCandidates,
      obsoleteCleaned,
      verification: {
        sqliteIntegrityOk,
        verifiedFilesCount,
        checksumMismatches,
        activeNotesCount,
        missingCount: syncReport.missing.length,
        untrackedCount: syncReport.untracked ? syncReport.untracked.length : 0,
        tombstonesCount,
        attachmentsCount,
        rebuiltIndexCount: indexRes.indexedCount,
        selfCheckHits: selfCheck ? selfCheck.items.length : null,
        manifestPreflight: {
          ok: sourceManifestMismatches.length === 0,
          checkedFilesCount: sourcePreflightCheckedCount,
          mismatches: sourceManifestMismatches
        },
        postRestoreFingerprints: {
          ok: checksumMismatches.length === 0,
          verifiedFilesCount,
          mismatches: checksumMismatches
        },
        sqliteIntegrity: {
          ok: sqliteIntegrityOk,
          result: integrityRow?.integrity_check ?? null
        },
        businessChecks: {
          activeNotesCount,
          missingCount: syncReport.missing.length,
          untrackedCount: syncReport.untracked ? syncReport.untracked.length : 0,
          tombstonesCount,
          attachmentsCount,
          rebuiltIndexCount: indexRes.indexedCount,
          selfCheckHits: selfCheck ? selfCheck.items.length : null
        }
      }
    };
  } finally {
    db.close();
  }
}
