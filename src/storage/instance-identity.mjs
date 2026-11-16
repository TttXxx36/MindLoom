import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { isSameCanonicalPath, isSubPathOrSame, resolveCanonicalPath } from '../config/paths.mjs';

const IDENTITY_FILENAME = 'instance-identity.json';

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function getCandidatePathHashes(targetPath) {
  const resolved = path.resolve(String(targetPath || ''));
  const canonical = resolveCanonicalPath(resolved);
  const canonicalRawCase = resolveCanonicalPath(resolved, { preserveCase: true });
  return new Set([sha256Hex(resolved), sha256Hex(canonical), sha256Hex(canonicalRawCase)]);
}

export function getInstanceIdentityPath(dataPath) {
  return path.join(path.resolve(dataPath), 'runtime', IDENTITY_FILENAME);
}

/**
 * 只读读取当前 Vault/Data 实例唯一绑定标识；若尚未持久化，则返回确定性派生只读标识（绝不静默写盘）
 * @param {{ vaultPath: string, dataPath: string }} params
 */
export function readInstanceIdentity({ vaultPath, dataPath }) {
  const resolvedVault = path.resolve(vaultPath);
  const resolvedData = path.resolve(dataPath);
  const filePath = getInstanceIdentityPath(resolvedData);

  if (fs.existsSync(filePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, ''));
      if (parsed && typeof parsed.vault_id === 'string' && parsed.vault_id && typeof parsed.data_id === 'string' && parsed.data_id) {
        return {
          vaultId: parsed.vault_id,
          dataId: parsed.data_id,
          vaultPathSha256: typeof parsed.vault_path_sha256 === 'string' ? parsed.vault_path_sha256 : null,
          dataPathSha256: typeof parsed.data_path_sha256 === 'string' ? parsed.data_path_sha256 : null,
          persisted: true,
          corrupt: false,
          filePath,
          restoredFromBackup: parsed.restored_from_backup || null
        };
      }
      return {
        vaultId: `VLT-DERIVED-${sha256Hex(resolvedVault).slice(0, 24)}`,
        dataId: `DAT-DERIVED-${sha256Hex(resolvedData).slice(0, 24)}`,
        vaultPathSha256: null,
        dataPathSha256: null,
        persisted: false,
        corrupt: true,
        filePath,
        restoredFromBackup: null
      };
    } catch {
      return {
        vaultId: `VLT-DERIVED-${sha256Hex(resolvedVault).slice(0, 24)}`,
        dataId: `DAT-DERIVED-${sha256Hex(resolvedData).slice(0, 24)}`,
        vaultPathSha256: null,
        dataPathSha256: null,
        persisted: false,
        corrupt: true,
        filePath,
        restoredFromBackup: null
      };
    }
  }

  return {
    vaultId: `VLT-DERIVED-${sha256Hex(resolvedVault).slice(0, 24)}`,
    dataId: `DAT-DERIVED-${sha256Hex(resolvedData).slice(0, 24)}`,
    vaultPathSha256: null,
    dataPathSha256: null,
    persisted: false,
    corrupt: false,
    filePath,
    restoredFromBackup: null
  };
}

/**
 * 显式创建或读取持久化实例身份文件 (runtime/instance-identity.json)
 * @param {{ vaultPath: string, dataPath: string }} params
 */
export function ensureInstanceIdentity({ vaultPath, dataPath }) {
  const existing = readInstanceIdentity({ vaultPath, dataPath });
  if (existing.persisted) {
    return existing;
  }

  const canonicalVault = resolveCanonicalPath(vaultPath);
  const canonicalData = resolveCanonicalPath(dataPath);
  const filePath = getInstanceIdentityPath(dataPath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const payload = {
    schema_version: 1,
    vault_id: `VLT-${crypto.randomUUID()}`,
    data_id: `DAT-${crypto.randomUUID()}`,
    vault_path_sha256: sha256Hex(canonicalVault),
    data_path_sha256: sha256Hex(canonicalData),
    created_at: new Date().toISOString()
  };
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', 'utf8');

  return {
    vaultId: payload.vault_id,
    dataId: payload.data_id,
    vaultPathSha256: payload.vault_path_sha256,
    dataPathSha256: payload.data_path_sha256,
    persisted: true,
    corrupt: false,
    filePath,
    restoredFromBackup: null
  };
}

/**
 * 整库恢复时为恢复副本分配全新实例绑定标识，确保无法复用原库云授权
 * @param {{ vaultPath: string, dataPath: string, backupId?: string | null }} params
 */
export function rotateInstanceIdentityOnRestore({ vaultPath, dataPath, backupId = null }) {
  const canonicalVault = resolveCanonicalPath(vaultPath);
  const canonicalData = resolveCanonicalPath(dataPath);
  const filePath = getInstanceIdentityPath(dataPath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const payload = {
    schema_version: 1,
    vault_id: `VLT-${crypto.randomUUID()}`,
    data_id: `DAT-${crypto.randomUUID()}`,
    vault_path_sha256: sha256Hex(canonicalVault),
    data_path_sha256: sha256Hex(canonicalData),
    restored_from_backup: backupId || null,
    created_at: new Date().toISOString()
  };
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', 'utf8');

  return {
    vaultId: payload.vault_id,
    dataId: payload.data_id,
    vaultPathSha256: payload.vault_path_sha256,
    dataPathSha256: payload.data_path_sha256,
    persisted: true,
    corrupt: false,
    filePath,
    restoredFromBackup: payload.restored_from_backup
  };
}

function isLexicalWithinOrSame(baseNorm, targetPath) {
  const normTarget = process.platform === 'win32' ? path.resolve(targetPath).toLowerCase() : path.resolve(targetPath);
  const rel = path.relative(baseNorm, normTarget);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function validateVaultDataIsolation({ vaultPath, dataPath }) {
  const resolvedVault = path.resolve(String(vaultPath || ''));
  const resolvedData = path.resolve(String(dataPath || ''));

  if (fs.existsSync(resolvedVault) && !fs.statSync(resolvedVault).isDirectory()) {
    return { ok: false, code: 'ERR_VAULT_NOT_DIRECTORY', message: `Vault 路径不是目录: ${resolvedVault}` };
  }
  if (fs.existsSync(resolvedData) && !fs.statSync(resolvedData).isDirectory()) {
    return { ok: false, code: 'ERR_DATA_NOT_DIRECTORY', message: `Data 路径不是目录: ${resolvedData}` };
  }
  if (fs.existsSync(path.join(resolvedVault, 'runtime', 'state.sqlite'))) {
    return { ok: false, code: 'ERR_VAULT_IS_DATA_DIR', message: `目标 Vault (${resolvedVault}) 实为 Data 运行目录` };
  }
  const canonicalVault = resolveCanonicalPath(resolvedVault);
  const canonicalData = resolveCanonicalPath(resolvedData);
  if (isLexicalWithinOrSame(canonicalVault, canonicalData) || isLexicalWithinOrSame(canonicalData, canonicalVault)) {
    return {
      ok: false,
      code: 'ERR_VAULT_DATA_NESTED',
      message: `Vault (${resolvedVault}) 与 Data (${resolvedData}) 不得重叠、同路径或相互嵌套（含目录别名）`
    };
  }
  return {
    ok: true,
    vaultPath: resolvedVault,
    dataPath: resolvedData,
    canonicalVault,
    canonicalData
  };
}

export function assertVaultDataIsolation({ vaultPath, dataPath }) {
  const res = validateVaultDataIsolation({ vaultPath, dataPath });
  if (!res.ok) {
    const err = new Error(`[${res.code}] ${res.message}`);
    err.code = res.code;
    throw err;
  }
  return res;
}

export function validateVaultDataPairing({ db = null, vaultPath, dataPath }) {
  const isolation = validateVaultDataIsolation({ vaultPath, dataPath });
  if (!isolation.ok) return isolation;

  const resolvedVault = isolation.vaultPath;
  const resolvedData = isolation.dataPath;
  const canonicalVault = isolation.canonicalVault;
  const canonicalData = isolation.canonicalData;

  if (!fs.existsSync(resolvedVault) || !fs.statSync(resolvedVault).isDirectory()) {
    return { ok: false, code: 'ERR_VAULT_NOT_FOUND', message: `Vault 目录不存在: ${resolvedVault}` };
  }

  const identity = readInstanceIdentity({ vaultPath: resolvedVault, dataPath: resolvedData });
  if (identity.corrupt) {
    return {
      ok: false,
      code: 'ERR_INSTANCE_IDENTITY_CORRUPT',
      message: `实例身份文件已损坏，无法安全校验配对: ${identity.filePath}`
    };
  }

  if (identity.persisted) {
    if (identity.vaultPathSha256) {
      const vaultHashes = getCandidatePathHashes(resolvedVault);
      if (!vaultHashes.has(identity.vaultPathSha256)) {
        return {
          ok: false,
          code: 'ERR_VAULT_DATA_MISMATCH',
          message: `Vault 与 Data 不配对：Data 实例身份 (${identity.filePath}) 绑定到另一 Vault 路径`
        };
      }
    }
    if (identity.dataPathSha256) {
      const dataHashes = getCandidatePathHashes(resolvedData);
      if (!dataHashes.has(identity.dataPathSha256)) {
        return {
          ok: false,
          code: 'ERR_VAULT_DATA_MISMATCH',
          message: `Vault 与 Data 不配对：Data 实例身份 (${identity.filePath}) 与当前 Data 目录路径不一致`
        };
      }
    }
  } else {
    // Legacy instance without instance-identity.json: check manifests/install-config.json if present
    const installCfgPath = path.join(resolvedData, 'manifests', 'install-config.json');
    if (fs.existsSync(installCfgPath)) {
      try {
        const cfg = JSON.parse(fs.readFileSync(installCfgPath, 'utf8').replace(/^\uFEFF/, ''));
        if (cfg && typeof cfg === 'object') {
          if (cfg.vaultPath && resolveCanonicalPath(cfg.vaultPath) !== canonicalVault) {
            return {
              ok: false,
              code: 'ERR_VAULT_DATA_MISMATCH',
              message: `Vault 与 Data 不配对：旧实例 install-config.json 绑定到另一 Vault (${cfg.vaultPath})`
            };
          }
          if (cfg.dataPath && resolveCanonicalPath(cfg.dataPath) !== canonicalData) {
            return {
              ok: false,
              code: 'ERR_VAULT_DATA_MISMATCH',
              message: `Vault 与 Data 不配对：旧实例 install-config.json 绑定到另一 Data (${cfg.dataPath})`
            };
          }
        }
      } catch {
        // ignore unreadable legacy install-config.json
      }
    }
  }

  let matchedNotesInVault = 0;
  let totalDbNotes = 0;
  let unmatchedNotesCount = 0;

  if (db) {
    const dirCanonicalCache = new Map();
    const isPathInBaseFast = (baseCanonical, candidatePath) => {
      const resolvedCandidate = path.resolve(candidatePath);
      const dir = path.dirname(resolvedCandidate);
      let canonDir = dirCanonicalCache.get(dir);
      if (canonDir === undefined) {
        canonDir = resolveCanonicalPath(dir);
        dirCanonicalCache.set(dir, canonDir);
      }
      return isLexicalWithinOrSame(baseCanonical, path.join(canonDir, path.basename(resolvedCandidate)));
    };

    const noteRows = db.prepare('SELECT id, path FROM notes').all();
    totalDbNotes = noteRows.length;
    const absRows = noteRows.filter((r) => r.path && path.isAbsolute(r.path));
    for (const row of absRows) {
      if (isPathInBaseFast(canonicalVault, row.path)) {
        matchedNotesInVault++;
      }
    }
    if (absRows.length > 0 && matchedNotesInVault === 0) {
      return {
        ok: false,
        code: 'ERR_VAULT_DATA_MISMATCH',
        message: `Vault 与 Data 不配对：Data 台账 (${resolvedData}) 中 ${absRows.length} 篇笔记均不在 Vault (${resolvedVault}) 内`
      };
    }
    unmatchedNotesCount = Math.max(0, absRows.length - matchedNotesInVault);

    if (absRows.length === 0) {
      const intentRows = db.prepare('SELECT target_path, staging_path FROM publish_intents').all();
      const snapRows = db.prepare('SELECT readable_session_path, raw_path FROM session_snapshots').all();
      const absVaultRefs = [
        ...intentRows.map((r) => r.target_path),
        ...snapRows.map((r) => r.readable_session_path)
      ].filter((p) => p && path.isAbsolute(p));
      const absDataRefs = [
        ...intentRows.map((r) => r.staging_path),
        ...snapRows.map((r) => r.raw_path)
      ].filter((p) => p && path.isAbsolute(p));

      if (
        (absVaultRefs.length > 0 && absVaultRefs.every((p) => !isPathInBaseFast(canonicalVault, p))) ||
        (absDataRefs.length > 0 && absDataRefs.every((p) => !isPathInBaseFast(canonicalData, p)))
      ) {
        return {
          ok: false,
          code: 'ERR_VAULT_DATA_MISMATCH',
          message: `Vault (${resolvedVault}) 与 Data (${resolvedData}) 不配对：意图/快照台账记录指向其他目录`
        };
      }

      if (!identity.persisted && absVaultRefs.length === 0 && absDataRefs.length === 0) {
        const hasVaultMarkers =
          fs.existsSync(path.join(resolvedVault, '50_Bases_Views')) ||
          fs.existsSync(path.join(resolvedVault, '90_Templates')) ||
          fs.existsSync(path.join(resolvedVault, '首页.md'));
        if (!hasVaultMarkers) {
          return {
            ok: false,
            code: 'ERR_VAULT_DATA_MISMATCH',
            message: `Vault (${resolvedVault}) 未初始化且 Data (${resolvedData}) 缺少实例身份绑定文件，拒绝盲目配对`
          };
        }
      }
    }
  }

  return {
    ok: true,
    vaultPath: resolvedVault,
    dataPath: resolvedData,
    identityPersisted: identity.persisted,
    matchedNotesInVault,
    totalDbNotes,
    unmatchedNotesCount
  };
}
