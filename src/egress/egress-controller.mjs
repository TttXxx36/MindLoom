import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  SANITIZER_VERSION,
  createSessionSanitizer,
  detectResidualSecrets,
  sanitizeOutputText
} from '../security/sanitizer.mjs';
import { verifyEgressApproval } from '../security/trusted-approvals.mjs';

/**
 * 出口 A 强制检查链与脱敏外发打包器 (PLAN.md §3.1, §8.2, B02)
 * 流程：
 *   1. 核验由人类可信入口签发的 egress_approval_id（绑定 snapshotId, provider, purpose）
 *   2. 严厉拦截任何 privacy !== 'sanitized' 的条目（含 local_only、缺失或非法值；并校验快照台账自身隐私属性防止篡改 YAML 蒙混）
 *   3. 执行同会话一致脱敏器替换所有凭据、密钥、连接串、Cookie、内嵌密码 URL 与高熵机密
 *   4. 审计残留秘密，确保零秘密外泄后写入 egress/EGR-*.json 与脱敏安全日志
 *
 * @param {{
 *   db: any,
 *   dataPath: string,
 *   snapshotId: string,
 *   egressApprovalId: string,
 *   provider: string,
 *   purpose: string,
 *   items: Array<{ id?: string, privacy?: string, text?: string, title?: string, [key: string]: any }>
 * }} params
 */
export function exportEgressPackage({
  db,
  dataPath,
  snapshotId,
  egressApprovalId,
  provider,
  purpose,
  items = []
}) {
  if (!db) {
    throw new Error('出口 A 操作必须提供已打开的 state.sqlite 数据库实例');
  }

  // 1. 核验可信批准凭据
  const approvalCheck = verifyEgressApproval({
    db,
    egressApprovalId,
    snapshotId,
    provider,
    purpose
  });
  if (!approvalCheck.valid) {
    throw new Error(`EXIT_A_APPROVAL_DENIED: 出口 A 批准凭据核验失败 (${approvalCheck.reason})`);
  }

  // 若快照在台账中有记录，额外检查是否处于 needs_reaudit
  const snapRow = db.prepare('SELECT * FROM session_snapshots WHERE snapshot_id = ?').get(snapshotId);
  if (snapRow && snapRow.status === 'needs_reaudit') {
    throw new Error(`EXIT_A_SNAPSHOT_NEEDS_REAUDIT: 快照 ${snapshotId} 处于 needs_reaudit 状态，禁止直接外发`);
  }

  // 2. 拦截任何 privacy !== 'sanitized' 的条目
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error('EXIT_A_EMPTY_PAYLOAD: 外发条目列表不能为空');
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!item || typeof item !== 'object') {
      throw new Error(`EXIT_A_INVALID_ITEM: 第 ${i + 1} 条数据格式非法`);
    }
    if (item.privacy !== 'sanitized') {
      throw new Error(
        `EXIT_A_PRIVACY_BLOCKED: 第 ${i + 1} 条数据 privacy="${item.privacy || 'missing'}" 非 sanitized，严禁进入外部模型出口 A`
      );
    }
    // 防止模型通过正文伪造 YAML block 蒙混：如果记录已在 notes 表登记，核对数据库中真实 privacy
    if (item.id) {
      const dbNote = db.prepare('SELECT privacy FROM notes WHERE id = ?').get(item.id);
      if (dbNote && dbNote.privacy !== 'sanitized') {
        throw new Error(
          `EXIT_A_PRIVACY_TAMPER_BLOCKED: 条目 ${item.id} 在 state.sqlite 台账中为 privacy="${dbNote.privacy}"，禁止通过自改 YAML 绕过出口过滤`
        );
      }
    }
  }

  // 3. 同会话一致脱敏（递归覆盖全部字符串字段与嵌套对象，绝不遗漏 summary/content/body 等字段）
  const sessionSanitizer = createSessionSanitizer();
  function sanitizeItemValue(val) {
    if (val === null || val === undefined) return val;
    if (typeof val === 'string') {
      return sanitizeOutputText(val, { sanitizer: sessionSanitizer, scrubRawPaths: true });
    }
    if (Array.isArray(val)) {
      return val.map(sanitizeItemValue);
    }
    if (typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (k === 'rawPath' || k === 'raw_path') {
          out[k] = '[REDACTED_RAW_PATH]';
        } else {
          out[k] = sanitizeItemValue(v);
        }
      }
      return out;
    }
    return val;
  }

  const sanitizedItems = items.map((item) => {
    const cleanedItem = sanitizeItemValue(item);
    const payloadStr = JSON.stringify(cleanedItem);
    const residual = detectResidualSecrets(payloadStr);
    if (!residual.clean) {
      throw new Error(`EXIT_A_RESIDUAL_SECRET_BLOCKED: 脱敏后仍检出残留敏感模式 (${residual.findings.join(', ')})`);
    }
    return cleanedItem;
  });

  // 4. 写入 egress/EGR-<id>.json 并记录安全审计摘要日志（严禁写入原文或密钥）
  const egressDir = path.join(dataPath, 'egress');
  const logsDir = path.join(dataPath, 'runtime', 'logs');
  if (!fs.existsSync(egressDir)) fs.mkdirSync(egressDir, { recursive: true });
  if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

  const packageId = `${egressApprovalId}-${crypto.randomBytes(4).toString('hex')}`;
  const egressPath = path.join(egressDir, `${packageId}.json`);
  const pkg = {
    package_id: packageId,
    egress_approval_id: egressApprovalId,
    snapshot_id: snapshotId,
    provider,
    purpose,
    sanitizer_version: SANITIZER_VERSION,
    created_at: new Date().toISOString(),
    redaction_stats: sessionSanitizer.getStats(),
    items: sanitizedItems
  };

  const pkgJson = JSON.stringify(pkg, null, 2);
  fs.writeFileSync(egressPath, pkgJson, 'utf8');

  // 审计日志仅含脱敏统计摘要，零原文、零密钥
  const auditEntry = {
    timestamp: pkg.created_at,
    event: 'egress_package_created',
    package_id: packageId,
    egress_approval_id: egressApprovalId,
    snapshot_id: snapshotId,
    provider,
    purpose,
    item_count: sanitizedItems.length,
    egress_bytes: Buffer.byteLength(pkgJson, 'utf8'),
    redaction_stats: pkg.redaction_stats
  };
  fs.appendFileSync(path.join(logsDir, 'egress-audit.jsonl'), JSON.stringify(auditEntry) + '\n', 'utf8');

  return {
    packageId,
    egressPath,
    egressBytes: Buffer.byteLength(pkgJson, 'utf8'),
    redactionStats: pkg.redaction_stats,
    sanitizedItems
  };
}

const DEFAULT_EXIT_A_ALLOWED_FIELDS = Object.freeze([
  'ephemeralId',
  'title',
  'content',
  'text',
  'summary'
]);

const FORBIDDEN_EXIT_A_FIELDS = new Set([
  'raw',
  'rawPath',
  'raw_path',
  'rawText',
  'raw_text',
  'filePath',
  'file_path',
  'vaultPath',
  'vault_path',
  'dataPath',
  'data_path',
  'sourceRef',
  'source_ref'
]);

function checkRegisteredSanitizedNote(db, item) {
  const lookupKey = item.noteId || item.note_id || item.id || item.notePath || item.path;
  if (!lookupKey || typeof lookupKey !== 'string') {
    const err = new Error('Registered note identifier missing for Exit A payload item');
    err.code = 'ERR_EXIT_A_UNREGISTERED_ITEM';
    throw err;
  }
  const row = db
    .prepare(
      `SELECT id, path, status, privacy
       FROM notes
       WHERE id = ? OR path = ?
       LIMIT 1`
    )
    .get(lookupKey, lookupKey);
  if (!row) {
    const err = new Error(`Unregistered manual/unknown note blocked from Exit A: ${lookupKey}`);
    err.code = 'ERR_EXIT_A_UNREGISTERED_ITEM';
    throw err;
  }
  if (row.status !== 'active') {
    const err = new Error(`Non-active note blocked from Exit A: ${lookupKey} (${row.status})`);
    err.code = 'ERR_EXIT_A_INACTIVE_ITEM';
    throw err;
  }
  if (row.privacy !== 'sanitized') {
    const err = new Error(
      `Non-sanitized note blocked from Exit A: ${lookupKey} (privacy=${row.privacy})`
    );
    err.code = 'ERR_EXIT_A_PRIVACY_BLOCKED';
    throw err;
  }
}

export function sanitizePayloadForExitA({
  db = null,
  items,
  allowedFields = DEFAULT_EXIT_A_ALLOWED_FIELDS,
  requireRegisteredSanitized = true
} = {}) {
  if (!Array.isArray(items)) {
    const err = new Error('sanitizePayloadForExitA requires items array');
    err.code = 'ERR_EXIT_A_INVALID_ITEMS';
    throw err;
  }
  if (!Array.isArray(allowedFields) || allowedFields.length === 0) {
    const err = new Error('sanitizePayloadForExitA requires non-empty allowedFields');
    err.code = 'ERR_EXIT_A_INVALID_FIELDS';
    throw err;
  }
  for (const field of allowedFields) {
    if (FORBIDDEN_EXIT_A_FIELDS.has(field)) {
      const err = new Error(`Forbidden raw/path field in Exit A whitelist: ${field}`);
      err.code = 'ERR_EXIT_A_FORBIDDEN_FIELD';
      throw err;
    }
  }

  const sessionSanitizer = createSessionSanitizer();
  const sanitizedItems = [];

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!item || typeof item !== 'object') {
      const err = new Error(`Exit A item at index ${i} must be an object`);
      err.code = 'ERR_EXIT_A_INVALID_ITEM';
      throw err;
    }

    const isAdHocQuery = item.kind === 'query';
    if (!isAdHocQuery) {
      if (item.privacy !== 'sanitized') {
        const err = new Error(
          `Blocked Exit A egress: item ${i} has privacy=${String(item.privacy)} (must be 'sanitized')`
        );
        err.code = 'ERR_EXIT_A_PRIVACY_BLOCKED';
        throw err;
      }
      if (requireRegisteredSanitized) {
        if (!db) {
          const err = new Error('Database handle required when requireRegisteredSanitized is true');
          err.code = 'ERR_EXIT_A_DB_REQUIRED';
          throw err;
        }
        checkRegisteredSanitizedNote(db, item);
      }
    } else if (item.privacy === 'local_only') {
      const err = new Error('Blocked Exit A egress: query item marked local_only');
      err.code = 'ERR_EXIT_A_PRIVACY_BLOCKED';
      throw err;
    }

    const cleanObj = {};
    for (const field of allowedFields) {
      if (!Object.prototype.hasOwnProperty.call(item, field)) {
        continue;
      }
      const val = item[field];
      if (val === undefined || val === null) {
        continue;
      }
      if (typeof val === 'string') {
        cleanObj[field] = sanitizeOutputText(val, {
          sanitizer: sessionSanitizer,
          scrubRawPaths: true
        });
      } else if (typeof val === 'number' || typeof val === 'boolean') {
        cleanObj[field] = val;
      } else if (Array.isArray(val)) {
        cleanObj[field] = val.map((entry) =>
          typeof entry === 'string'
            ? sanitizeOutputText(entry, { sanitizer: sessionSanitizer, scrubRawPaths: true })
            : entry
        );
      }
    }

    const residual = detectResidualSecrets(JSON.stringify(cleanObj));
    if (!residual.clean) {
      const err = new Error(
        `Residual secret detected in Exit A in-memory payload item ${i}: ${residual.findings
          .map((f) => f.type)
          .join(', ')}`
      );
      err.code = 'ERR_EXIT_A_RESIDUAL_SECRET';
      throw err;
    }

    sanitizedItems.push(cleanObj);
  }

  const serialized = JSON.stringify(sanitizedItems);
  return {
    clean: true,
    inMemoryOnly: true,
    sanitizerVersion: SANITIZER_VERSION,
    egressBytes: Buffer.byteLength(serialized, 'utf8'),
    redactionStats: sessionSanitizer.getStats(),
    sanitizedItems
  };
}
