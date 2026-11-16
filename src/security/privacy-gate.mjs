import { detectResidualSecrets } from './sanitizer.mjs';

/**
 * 统一隐私与公开可见性门禁：
 * 供检索 (Mode 0/1/2)、MOC 主题地图生成与导出路径共用同一套资料状态判定规则。
 *
 * @param {{
 *   raw?: string | null,
 *   frontmatter?: object | null,
 *   dbRow?: { status?: string, privacy?: string, lifecycle?: string } | null,
 *   duplicateIdCount?: number,
 *   checkResidualSecrets?: boolean,
 *   requireActiveLifecycle?: boolean
 * }} params
 * @returns {{ allowed: boolean, reason: string | null }}
 */
export function evaluateSanitizedVisibility({
  raw = null,
  frontmatter = null,
  dbRow = null,
  duplicateIdCount = 0,
  checkResidualSecrets = false,
  requireActiveLifecycle = false
} = {}) {
  if (duplicateIdCount > 1) {
    return { allowed: false, reason: 'duplicate_id_conflict' };
  }
  if (!frontmatter || frontmatter.privacy !== 'sanitized') {
    return { allowed: false, reason: 'frontmatter_not_sanitized' };
  }
  if (dbRow) {
    if (dbRow.status === 'missing' || dbRow.status === 'deleted') {
      return { allowed: false, reason: `db_status_${dbRow.status}` };
    }
    if (dbRow.privacy && dbRow.privacy !== 'sanitized') {
      return { allowed: false, reason: 'db_privacy_not_sanitized' };
    }
    if (requireActiveLifecycle && dbRow.lifecycle && dbRow.lifecycle !== 'active') {
      return { allowed: false, reason: `db_lifecycle_${dbRow.lifecycle}` };
    }
  }
  if (requireActiveLifecycle && frontmatter.lifecycle && frontmatter.lifecycle !== 'active') {
    return { allowed: false, reason: `frontmatter_lifecycle_${frontmatter.lifecycle}` };
  }
  if (checkResidualSecrets && raw !== null && raw !== undefined) {
    const residual = detectResidualSecrets(raw);
    if (!residual.clean) {
      return { allowed: false, reason: `residual_secrets_detected:${residual.findings.join(',')}` };
    }
  }
  return { allowed: true, reason: null };
}
