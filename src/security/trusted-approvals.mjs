import crypto from 'node:crypto';
import fs from 'node:fs';
import { calculateSha256, parseProposalContent } from '../reconcile/engine.mjs';

/**
 * 通用 mem.mjs CLI 中严格禁止的可伪造参数清单 (C2 / R3)
 * 拥有 Shell 权限的 Agent 传入下列任何参数必须立即拒绝
 */
export const FORBIDDEN_AGENT_CLI_FLAGS = [
  '--confirm-proposal',
  '--confirm-rewrite',
  '--user-confirmed-rewrite',
  '--audience',
  '--bypass-filter',
  '--skip-sanitize',
  '--approve-egress',
  '--approve-cloud-egress',
  '--approve-ingest',
  '--force-actionable',
  '--ignore-conflicts',
  '--raw'
];

/**
 * 检查 CLI 参数列表中是否夹带可伪造特权参数
 * @param {string[]} argv
 */
export function assertNoForbiddenCliFlags(argv = []) {
  for (const arg of argv) {
    const flagName = String(arg).split('=')[0].trim().toLowerCase();
    if (FORBIDDEN_AGENT_CLI_FLAGS.includes(flagName)) {
      throw new Error(
        `SECURITY_POLICY_VIOLATION: 禁止在通用 CLI 中传入受限参数 "${flagName}" (R3/C2：防止 Agent 自行伪造人工确认或绕过安全边界)`
      );
    }
  }
}

/**
 * 人类专用可信入口：签发绑定快照范围、目标服务商与用途的 egress_approval_id (Exit A)
 * 绝不暴露于通用 mem.mjs 无隔离参数；模型自改 YAML 或候选文件无法制造此凭据
 *
 * @param {{
 *   db: any,
 *   snapshotId: string,
 *   provider: string,
 *   purpose: string,
 *   approvedBy?: string,
 *   ttlHours?: number,
 *   trustedHumanContext: boolean
 * }} params
 * @returns {{ egressApprovalId: string, snapshotId: string, provider: string, purpose: string, expiresAt: string }}
 */
export function issueTrustedEgressApproval({
  db,
  snapshotId,
  provider,
  purpose,
  approvedBy = 'local_human_operator',
  ttlHours = 24,
  trustedHumanContext = false
}) {
  if (trustedHumanContext !== true) {
    throw new Error(
      'UNTRUSTED_EGRESS_APPROVAL_ATTEMPT: egress_approval_id 必须由人类专用可信确认入口签发，拒绝非可信上下文请求'
    );
  }
  if (!snapshotId || !provider || !purpose) {
    throw new Error('签发 egress_approval_id 必须明确绑定 snapshotId、provider 与 purpose');
  }

  const now = new Date();
  const expires = new Date(now.getTime() + ttlHours * 3600 * 1000);
  const randomSuffix = crypto.randomBytes(8).toString('hex');
  const egressApprovalId = `EGR-${now.toISOString().slice(0, 10).replace(/-/g, '')}-${randomSuffix}`;
  const approvalTokenSha256 = crypto
    .createHash('sha256')
    .update(`${egressApprovalId}::${snapshotId}::${provider}::${purpose}::${approvedBy}`, 'utf8')
    .digest('hex');

  db.prepare(`
    INSERT INTO egress_approvals (
      egress_approval_id, snapshot_id, provider, purpose, approved_by,
      approval_token_sha256, status, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `).run(
    egressApprovalId,
    snapshotId,
    provider,
    purpose,
    approvedBy,
    approvalTokenSha256,
    now.toISOString(),
    expires.toISOString()
  );

  return {
    egressApprovalId,
    snapshotId,
    provider,
    purpose,
    expiresAt: expires.toISOString()
  };
}

/**
 * 核验出口 A 批准凭据是否真实有效且精确匹配绑定范围
 * @param {{
 *   db: any,
 *   egressApprovalId: string,
 *   snapshotId: string,
 *   provider: string,
 *   purpose: string
 * }} params
 * @returns {{ valid: boolean, record?: object, reason?: string }}
 */
export function verifyEgressApproval({ db, egressApprovalId, snapshotId, provider, purpose }) {
  if (!egressApprovalId || typeof egressApprovalId !== 'string') {
    return { valid: false, reason: 'missing_egress_approval_id' };
  }

  const record = db
    .prepare('SELECT * FROM egress_approvals WHERE egress_approval_id = ?')
    .get(egressApprovalId);

  if (!record) {
    return { valid: false, reason: 'untrusted_or_forged_egress_approval_id' };
  }
  if (record.status !== 'active') {
    return { valid: false, reason: `egress_approval_not_active:${record.status}` };
  }
  if (new Date(record.expires_at).getTime() <= Date.now()) {
    return { valid: false, reason: 'egress_approval_expired' };
  }
  if (record.snapshot_id !== snapshotId) {
    return { valid: false, reason: 'egress_approval_snapshot_mismatch' };
  }
  if (record.provider !== provider) {
    return { valid: false, reason: 'egress_approval_provider_mismatch' };
  }
  if (record.purpose !== purpose) {
    return { valid: false, reason: 'egress_approval_purpose_mismatch' };
  }

  const expectedTokenSha = crypto
    .createHash('sha256')
    .update(
      `${record.egress_approval_id}::${record.snapshot_id}::${record.provider}::${record.purpose}::${record.approved_by}`,
      'utf8'
    )
    .digest('hex');

  if (expectedTokenSha !== record.approval_token_sha256) {
    return { valid: false, reason: 'egress_approval_integrity_mismatch' };
  }

  return { valid: true, record };
}

/**
 * 人类专用可信确认入口：登记 user_confirmed_rewrite (C2)
 * 在可信人工入口未完成宿主隔离验证前，默认保持此确认捷径关闭！
 *
 * @param {{
 *   db: any,
 *   proposalPath: string,
 *   targetPath: string,
 *   trustedChannelVerified?: boolean
 * }} params
 */
export function registerTrustedRewriteConfirmation({
  db,
  proposalPath,
  targetPath,
  trustedChannelVerified = false
}) {
  if (trustedChannelVerified !== true) {
    throw new Error(
      'TRUSTED_HUMAN_CHANNEL_DISABLED: 宿主隔离未完成验证，user_confirmed_rewrite 人工快捷确认默认关闭；请通过结构化前后置条件核对 (verified_applied) 放行 (C2)'
    );
  }
  if (!fs.existsSync(proposalPath) || !fs.existsSync(targetPath)) {
    throw new Error('提案或目标笔记文件不存在，无法登记可信人工改写确认');
  }

  const propRaw = fs.readFileSync(proposalPath, 'utf8');
  const targetRaw = fs.readFileSync(targetPath, 'utf8');
  const { frontmatter } = parseProposalContent(propRaw);

  if (!frontmatter.id || !frontmatter.target_id) {
    throw new Error('提案缺少 id 或 target_id');
  }
  if (frontmatter.proposal_status !== 'accepted') {
    throw new Error(`提案状态必须先为 accepted，当前为: ${frontmatter.proposal_status}`);
  }

  const propSha = calculateSha256(propRaw);
  const targetSha = calculateSha256(targetRaw);
  const nowIso = new Date().toISOString();
  const confirmationId = `HC-${crypto.randomBytes(8).toString('hex')}`;

  db.prepare(`
    INSERT INTO trusted_human_confirmations (
      confirmation_id, proposal_id, proposal_version_sha256,
      target_id, target_version_sha256, action, created_at
    ) VALUES (?, ?, ?, ?, ?, 'user_confirmed_rewrite', ?)
  `).run(confirmationId, frontmatter.id, propSha, frontmatter.target_id, targetSha, nowIso);

  db.prepare(`
    INSERT INTO reconcile_states (
      proposal_id, proposal_version_sha256, target_id, target_version_sha256,
      reconcile_state, reason, updated_at
    ) VALUES (?, ?, ?, ?, 'user_confirmed_rewrite', 'trusted_human_confirmation', ?)
    ON CONFLICT(proposal_id) DO UPDATE SET
      proposal_version_sha256 = excluded.proposal_version_sha256,
      target_id = excluded.target_id,
      target_version_sha256 = excluded.target_version_sha256,
      reconcile_state = 'user_confirmed_rewrite',
      reason = 'trusted_human_confirmation',
      updated_at = excluded.updated_at
  `).run(frontmatter.id, propSha, frontmatter.target_id, targetSha, nowIso);

  return {
    confirmationId,
    proposalId: frontmatter.id,
    reconcile_state: 'user_confirmed_rewrite',
    proposal_version_sha256: propSha,
    target_version_sha256: targetSha
  };
}

/**
 * 人类专用可信入口：签发低敏会话持久化导入授权凭据 (B6)
 * 仅 `--sensitivity approved_low_sensitivity` 参数只表达分类，不能代替明确的低敏授权。
 *
 * @param {{
 *   db: any,
 *   sourceTool: string,
 *   sessionId: string,
 *   approvedBy?: string,
 *   ttlHours?: number,
 *   trustedHumanContext: boolean
 * }} params
 */
export function issueTrustedLowSensitivityApproval({
  db,
  sourceTool,
  sessionId,
  approvedBy = 'local_human_operator',
  ttlHours = 24,
  trustedHumanContext = false
}) {
  if (trustedHumanContext !== true) {
    throw new Error(
      'UNTRUSTED_INGEST_APPROVAL_ATTEMPT: 低敏导入授权必须由人类专用可信上下文签发，拒绝非可信请求'
    );
  }
  if (!sourceTool || !sessionId) {
    throw new Error('签发低敏导入授权必须明确绑定 sourceTool 与 sessionId');
  }
  const boundScope = `${String(sourceTool).toLowerCase()}:${sessionId}`;
  const res = issueTrustedEgressApproval({
    db,
    snapshotId: boundScope,
    provider: 'local_ingest',
    purpose: 'approved_low_sensitivity_ingest',
    approvedBy,
    ttlHours,
    trustedHumanContext: true
  });
  return {
    ingestApprovalId: res.egressApprovalId,
    sourceTool: String(sourceTool).toLowerCase(),
    sessionId,
    boundScope,
    expiresAt: res.expiresAt
  };
}

/**
 * 核验低敏持久化导入授权凭据
 * @param {{ db: any, approvalId: string, sourceTool: string, sessionId: string }} params
 */
export function verifyLowSensitivityIngestApproval({ db, approvalId, sourceTool, sessionId }) {
  if (!approvalId || typeof approvalId !== 'string') {
    return { valid: false, reason: 'missing_low_sensitivity_ingest_approval_id' };
  }
  const normTool = String(sourceTool || '').toLowerCase();
  const exactScope = `${normTool}:${sessionId}`;
  const exactCheck = verifyEgressApproval({
    db,
    egressApprovalId: approvalId,
    snapshotId: exactScope,
    provider: 'local_ingest',
    purpose: 'approved_low_sensitivity_ingest'
  });
  if (exactCheck.valid) {
    return exactCheck;
  }
  if (exactCheck.reason === 'egress_approval_snapshot_mismatch') {
    const wildcardCheck = verifyEgressApproval({
      db,
      egressApprovalId: approvalId,
      snapshotId: `${normTool}:*`,
      provider: 'local_ingest',
      purpose: 'approved_low_sensitivity_ingest'
    });
    if (wildcardCheck.valid) {
      return wildcardCheck;
    }
  }
  return exactCheck;
}
