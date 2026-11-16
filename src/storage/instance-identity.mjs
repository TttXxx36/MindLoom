import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const IDENTITY_FILENAME = 'instance-identity.json';

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

export function getInstanceIdentityPath(dataPath) {
  return path.join(path.resolve(dataPath), 'runtime', IDENTITY_FILENAME);
}

/**
 * 只读读取当前 Vault/Data 实例唯一绑定标识；若尚未持久化，则返回确定性派生只读标识（绝不静默写盘）
 * @param {{ vaultPath: string, dataPath: string }} params
 * @returns {{ vaultId: string, dataId: string, persisted: boolean, filePath: string }}
 */
export function readInstanceIdentity({ vaultPath, dataPath }) {
  const resolvedVault = path.resolve(vaultPath);
  const resolvedData = path.resolve(dataPath);
  const filePath = getInstanceIdentityPath(resolvedData);

  if (fs.existsSync(filePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (parsed && typeof parsed.vault_id === 'string' && parsed.vault_id && typeof parsed.data_id === 'string' && parsed.data_id) {
        return {
          vaultId: parsed.vault_id,
          dataId: parsed.data_id,
          persisted: true,
          filePath,
          restoredFromBackup: parsed.restored_from_backup || null
        };
      }
    } catch {
      // fall through to derived identity
    }
  }

  return {
    vaultId: `VLT-DERIVED-${sha256Hex(resolvedVault).slice(0, 24)}`,
    dataId: `DAT-DERIVED-${sha256Hex(resolvedData).slice(0, 24)}`,
    persisted: false,
    filePath,
    restoredFromBackup: null
  };
}

/**
 * 显式创建或读取持久化实例身份文件 (runtime/instance-identity.json)
 * @param {{ vaultPath: string, dataPath: string }} params
 * @returns {{ vaultId: string, dataId: string, persisted: boolean, filePath: string }}
 */
export function ensureInstanceIdentity({ vaultPath, dataPath }) {
  const existing = readInstanceIdentity({ vaultPath, dataPath });
  if (existing.persisted) {
    return existing;
  }

  const resolvedVault = path.resolve(vaultPath);
  const resolvedData = path.resolve(dataPath);
  const filePath = getInstanceIdentityPath(resolvedData);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const payload = {
    schema_version: 1,
    vault_id: `VLT-${crypto.randomUUID()}`,
    data_id: `DAT-${crypto.randomUUID()}`,
    vault_path_sha256: sha256Hex(resolvedVault),
    data_path_sha256: sha256Hex(resolvedData),
    created_at: new Date().toISOString()
  };
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', 'utf8');

  return {
    vaultId: payload.vault_id,
    dataId: payload.data_id,
    persisted: true,
    filePath,
    restoredFromBackup: null
  };
}

/**
 * 整库恢复时为恢复副本分配全新实例绑定标识，确保无法复用原库云授权
 * @param {{ vaultPath: string, dataPath: string, backupId?: string | null }} params
 * @returns {{ vaultId: string, dataId: string, persisted: boolean, filePath: string, restoredFromBackup: string | null }}
 */
export function rotateInstanceIdentityOnRestore({ vaultPath, dataPath, backupId = null }) {
  const resolvedVault = path.resolve(vaultPath);
  const resolvedData = path.resolve(dataPath);
  const filePath = getInstanceIdentityPath(resolvedData);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const payload = {
    schema_version: 1,
    vault_id: `VLT-${crypto.randomUUID()}`,
    data_id: `DAT-${crypto.randomUUID()}`,
    vault_path_sha256: sha256Hex(resolvedVault),
    data_path_sha256: sha256Hex(resolvedData),
    restored_from_backup: backupId || null,
    created_at: new Date().toISOString()
  };
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', 'utf8');

  return {
    vaultId: payload.vault_id,
    dataId: payload.data_id,
    persisted: true,
    filePath,
    restoredFromBackup: payload.restored_from_backup
  };
}
