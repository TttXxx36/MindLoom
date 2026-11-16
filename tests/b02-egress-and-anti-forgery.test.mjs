import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import {
  createSessionSanitizer,
  detectResidualSecrets,
  formatSafeErrorForExitB
} from '../src/security/sanitizer.mjs';
import {
  issueTrustedEgressApproval,
  registerTrustedRewriteConfirmation,
  assertNoForbiddenCliFlags
} from '../src/security/trusted-approvals.mjs';
import { exportEgressPackage } from '../src/egress/egress-controller.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { restoreNote } from '../src/storage/restore-manager.mjs';
import { createProposal, reconcileProposal, checkProposalReconcileState } from '../src/reconcile/engine.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

// 动态组装合成测试凭据（遵循工作区规范 §8：绝不在源码或测试中硬编码连续密钥字面量）
function makeSyntheticSecrets() {
  const apiKey = ['sk', 'proj', 'SynthTest99887766AABBCCDDEEFF'].join('-');
  const ghTok = ['ghp', 'SyntheticTestToken1234567890ABCD'].join('_');
  const jwt = [
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    'eyJzdWIiOiJzeW50aC11c2VyIiwicm9sZSI6InRlc3QifQ',
    'SyntheticSigValue1234567890'
  ].join('.');
  const bearer = ['Bea', 'rer ', jwt].join('');
  const dbUrl = ['postgres', '://', 'appuser', ':', 'Sup3rP4ssW0rd!99', '@', 'db.internal.local:5432/prod'].join('');
  const pemKey = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEASyntheticFakeKeyMaterialLine1234567890',
    '-----END RSA PRIVATE KEY-----'
  ].join('\n');
  const cookie = ['Cookie', ': ', 'sid=SynthSession998877665544; csrf=AbCdEf123456'].join('');
  return { apiKey, ghTok, jwt, bearer, dbUrl, pemKey, cookie };
}

test('B02: 全出口、全通道秘密拦截与防 CLI 伪造确认', async (t) => {
  const baseDir = path.resolve('.tmp/test-b02-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  const db = openDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));

  t.after(() => {
    try {
      db.close();
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  const secrets = makeSyntheticSecrets();

  await t.test('1. 同会话一致占位符脱敏器拦截全部秘密类型并保持占位符映射稳定', () => {
    const sanitizer = createSessionSanitizer();
    const rawLine1 = `调用 ${secrets.apiKey} 与 ${secrets.bearer} 连接 ${secrets.dbUrl}，头 ${secrets.cookie}`;
    const rawLine2 = `重复使用同一 Key ${secrets.apiKey}，并附带私钥\n${secrets.pemKey}\n及 GitHub ${secrets.ghTok}`;

    const out1 = sanitizer.sanitize(rawLine1).text;
    const out2 = sanitizer.sanitize(rawLine2).text;

    assert.equal(detectResidualSecrets(out1).clean, true);
    assert.equal(detectResidualSecrets(out2).clean, true);
    assert.equal(out1.includes(secrets.apiKey), false);
    assert.equal(out1.includes('Sup3rP4ssW0rd!99'), false);
    assert.equal(out2.includes('PRIVATE KEY'), false);

    // 验证相同 Key 在同一会话内映射为完全一致的占位符
    const tokenMatch1 = out1.match(/\[TOKEN_\d+\]/);
    const tokenMatch2 = out2.match(/\[TOKEN_\d+\]/);
    assert.ok(tokenMatch1 && tokenMatch2);
    assert.equal(tokenMatch1[0], tokenMatch2[0], '同会话重复秘密必须映射到同一占位符');

    // 验证无标签高熵随机密钥串被拦截，同时系统 ID 与 snake_case 错误码不被误伤
    const highEntropySecret = ['xK9mP', '2vQ8n', 'L4wR7', 'zT1yB', '6cF3h', 'J5d+9Q'].join('');
    const mixedLine = `ID=EGR-20261110-1a2b3c4d5e6f7a8b-deadbeef KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f err=missing_egress_approval_fallback_to_mode0 raw=${highEntropySecret}`;
    const outMixed = sanitizer.sanitize(mixedLine).text;
    assert.ok(outMixed.includes('EGR-20261110-1a2b3c4d5e6f7a8b-deadbeef'), 'EGR 凭据编号绝不可被高熵检测误伤');
    assert.ok(outMixed.includes('KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f'), 'UUID 主键绝不可被误伤');
    assert.ok(outMixed.includes('missing_egress_approval_fallback_to_mode0'), 'snake_case 错误码绝不可被误伤');
    assert.equal(outMixed.includes(highEntropySecret), false, '高熵随机密钥串必须被拦截');
  });

  await t.test('2. 出口 A 强制检查链：未批准/伪造/跨范围/local_only/自改YAML均被阻断', () => {
    const snapId = 'codex-sess-b02-1111';

    // 2a. 非可信上下文无法签发 egress_approval_id
    assert.throws(() => {
      issueTrustedEgressApproval({
        db,
        snapshotId: snapId,
        provider: 'siliconflow',
        purpose: 'distill',
        trustedHumanContext: false
      });
    }, /UNTRUSTED_EGRESS_APPROVAL_ATTEMPT/);

    // 2b. 伪造的 egress_approval_id 被出口 A 拦截
    assert.throws(() => {
      exportEgressPackage({
        db,
        dataPath: dataDir,
        snapshotId: snapId,
        egressApprovalId: 'EGR-FORGED-9999',
        provider: 'siliconflow',
        purpose: 'distill',
        items: [{ id: 'EV-1', privacy: 'sanitized', text: '普通文本' }]
      });
    }, /EXIT_A_APPROVAL_DENIED/);

    // 2c. 签发真实可信批准，但跨快照/跨服务商/跨用途使用均被拒绝
    const approval = issueTrustedEgressApproval({
      db,
      snapshotId: snapId,
      provider: 'siliconflow',
      purpose: 'distill',
      trustedHumanContext: true
    });

    assert.throws(() => {
      exportEgressPackage({
        db,
        dataPath: dataDir,
        snapshotId: 'codex-sess-OTHER',
        egressApprovalId: approval.egressApprovalId,
        provider: 'siliconflow',
        purpose: 'distill',
        items: [{ id: 'EV-1', privacy: 'sanitized', text: '普通文本' }]
      });
    }, /egress_approval_snapshot_mismatch/);

    assert.throws(() => {
      exportEgressPackage({
        db,
        dataPath: dataDir,
        snapshotId: snapId,
        egressApprovalId: approval.egressApprovalId,
        provider: 'openai',
        purpose: 'distill',
        items: [{ id: 'EV-1', privacy: 'sanitized', text: '普通文本' }]
      });
    }, /egress_approval_provider_mismatch/);

    // 2d. privacy != sanitized (local_only / 缺失) 严禁外发
    assert.throws(() => {
      exportEgressPackage({
        db,
        dataPath: dataDir,
        snapshotId: snapId,
        egressApprovalId: approval.egressApprovalId,
        provider: 'siliconflow',
        purpose: 'distill',
        items: [{ id: 'EV-2', privacy: 'local_only', text: '绝对私密' }]
      });
    }, /EXIT_A_PRIVACY_BLOCKED/);

    // 2e. 防止模型伪造 YAML privacy: sanitized 绕过 DB 中真实 local_only 登记
    db.prepare(`
      INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at)
      VALUES ('KN-LOCAL-REAL', 'playbook', '绝密笔记本', 'P1', 'local_only', 'p.md', 'h', 'active', datetime('now'))
    `).run();

    assert.throws(() => {
      exportEgressPackage({
        db,
        dataPath: dataDir,
        snapshotId: snapId,
        egressApprovalId: approval.egressApprovalId,
        provider: 'siliconflow',
        purpose: 'distill',
        items: [{ id: 'KN-LOCAL-REAL', privacy: 'sanitized', text: '试图伪造 YAML privacy 绕过' }]
      });
    }, /EXIT_A_PRIVACY_TAMPER_BLOCKED/);

    // 2f. 合规外发：自动脱敏全部秘密并记录无原文的脱敏审计日志
    const okRes = exportEgressPackage({
      db,
      dataPath: dataDir,
      snapshotId: snapId,
      egressApprovalId: approval.egressApprovalId,
      provider: 'siliconflow',
      purpose: 'distill',
      items: [{
        id: 'EV-SAFE-1',
        privacy: 'sanitized',
        title: '故障现场',
        text: `请求失败，凭据 ${secrets.apiKey} 与 ${secrets.dbUrl}`
      }]
    });

    assert.ok(fs.existsSync(okRes.egressPath));
    const pkgText = fs.readFileSync(okRes.egressPath, 'utf8');
    assert.equal(detectResidualSecrets(pkgText).clean, true);
    assert.equal(pkgText.includes(secrets.apiKey), false);

    const auditLog = fs.readFileSync(path.join(dataDir, 'runtime', 'logs', 'egress-audit.jsonl'), 'utf8');
    assert.equal(auditLog.includes(secrets.apiKey), false);
    assert.equal(auditLog.includes('请求失败'), false, '审计日志严禁写入原文');
  });

  await t.test('3. 出口 B 全通道清洗：检索、预览文件、stdout/stderr/异常堆栈全脱敏且剥离 local_only', () => {
    const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');

    // 笔记 A: local_only（绝对不能进入出口 B）
    fs.writeFileSync(path.join(notesDir, 'KN-local.md'), `---
schema_version: 1
id: "KN-LOCAL-001"
note_type: "playbook"
title: "秘密指令 local_only"
project: "Ops"
privacy: "local_only"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "win"
created_at: "2026-11-10T12:00:00+08:00"
---
搜索关键词 B02ProbeTarget
`, 'utf8');

    // 笔记 B: 缺失 privacy 字段（§3.2 同样严禁进入返回通道）
    fs.writeFileSync(path.join(notesDir, 'KN-missing-priv.md'), `---
schema_version: 1
id: "KN-MISSING-PRIV"
note_type: "playbook"
title: "缺失隐私字段 B02ProbeTarget"
project: "Ops"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "win"
created_at: "2026-11-10T12:00:00+08:00"
---
B02ProbeTarget
`, 'utf8');

    // 笔记 C: 标为 sanitized 但用户手工粘入了新秘密
    fs.writeFileSync(path.join(notesDir, 'KN-edited-secret.md'), `---
schema_version: 1
id: "KN-EDITED-SEC"
note_type: "playbook"
title: "人工新粘入秘密 B02ProbeTarget"
project: "Ops"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "win"
created_at: "2026-11-10T12:00:00+08:00"
---
B02ProbeTarget 现场命令带入 ${secrets.apiKey} 与 ${secrets.bearer}
`, 'utf8');

    const res = searchKnowledge({ db, vaultDir, query: 'B02ProbeTarget' });
    assert.equal(res.items.length, 1, '仅 sanitized 笔记可返回，local_only 与缺失 privacy 必须完全剥离');
    assert.equal(res.items[0].id, 'KN-EDITED-SEC');
    assert.equal(res.items[0].snippet.includes(secrets.apiKey), false, 'sanitized 笔记中新粘入秘密必须实时脱敏');
    assert.equal(detectResidualSecrets(res.items[0].snippet).clean, true);

    // 预览文件脱敏检验 (restoreNote -> staging/restore-preview/)
    const prevRes = restoreNote({
      db,
      noteId: 'KN-EDITED-SEC',
      revision: 'rev-0001',
      content: `---\nprivacy: "sanitized"\n---\n旧版本含 ${secrets.apiKey}`,
      targetVaultPath: path.join(notesDir, 'KN-edited-secret.md'),
      stagingDir: path.join(dataDir, 'staging')
    });
    const previewBody = fs.readFileSync(prevRes.previewPath, 'utf8');
    assert.equal(previewBody.includes(secrets.apiKey), false);
    assert.equal(detectResidualSecrets(previewBody).clean, true);

    // 异常堆栈脱敏检验：包含 raw/ 路径与秘密的错误必须被清洗
    const dangerousRawPath = path.join(dataDir, 'raw', `leak-${secrets.ghTok}.jsonl`);
    const safeErrText = formatSafeErrorForExitB(new Error(`读取 ${dangerousRawPath} 失败: token=${secrets.apiKey}`), { includeStack: true });
    assert.equal(safeErrText.includes(secrets.apiKey), false);
    assert.equal(safeErrText.includes(secrets.ghTok), false);
    assert.equal(safeErrText.includes('AgentMemory-Data\\raw'), false);
    assert.ok(safeErrText.includes('[REDACTED_RAW_PATH]'));

    // 真实 CLI 子进程 stdout/stderr 检验
    const env = { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir };
    const cliStdout = execFileSync(process.execPath, [CLI_PATH, 'search', 'B02ProbeTarget', '--json'], {
      env,
      encoding: 'utf8'
    });
    assert.equal(cliStdout.includes(secrets.apiKey), false);
    assert.equal(detectResidualSecrets(cliStdout).clean, true);

    let cliStderr = '';
    try {
      execFileSync(process.execPath, [CLI_PATH, 'ingest', '--session', 's1', '--source-file', dangerousRawPath], {
        env,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (e) {
      cliStderr = (e.stderr || '') + (e.stdout || '');
    }
    assert.ok(cliStderr.length > 0);
    assert.equal(cliStderr.includes(secrets.ghTok), false);
    assert.equal(cliStderr.includes('AgentMemory-Data\\raw'), false);
  });

  await t.test('4. 防 CLI 伪造确认与 C2 人工快捷确认默认关闭校验', () => {
    const forbiddenFlags = [
      '--confirm-proposal',
      '--audience=local',
      '--user-confirmed-rewrite',
      '--bypass-filter',
      '--approve-egress',
      '--force-actionable'
    ];
    for (const flag of forbiddenFlags) {
      assert.throws(() => assertNoForbiddenCliFlags([flag]), /SECURITY_POLICY_VIOLATION/);

      // 真实 CLI 进程必须拒收上述参数
      let exitCode = 0;
      let stderr = '';
      try {
        execFileSync(process.execPath, [CLI_PATH, 'search', 'test', flag], {
          env: { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir },
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (e) {
        exitCode = e.status || 1;
        stderr = e.stderr || '';
      }
      assert.notEqual(exitCode, 0);
      assert.ok(stderr.includes('SECURITY_POLICY_VIOLATION'));
    }

    // 准备一个冲突提案测试 C2 默认关闭
    const targetPath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-c2-target.md');
    fs.writeFileSync(targetPath, '---\nid: "KN-C2-TARGET"\nprivacy: "sanitized"\nlifecycle: "active"\nreview_state: "accepted"\n---\n旧错误命令\n', 'utf8');
    const prop = createProposal({
      queueDir: path.join(vaultDir, '40_Review_Queue'),
      proposalUuid: 'PROP-019316a8-7c40-7000-8000-c20000000001',
      title: 'C2 冲突测试',
      project: 'Ops',
      targetId: 'KN-C2-TARGET',
      targetNoteRef: '[[KN-c2-target]]',
      proposalKind: 'conflict',
      preConditions: ['旧错误命令'],
      postConditions: ['新正确命令']
    });
    const acceptedProp = fs.readFileSync(prop.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"');
    fs.writeFileSync(prop.proposalPath, acceptedProp, 'utf8');

    // 未完成宿主隔离前，user_confirmed_rewrite 默认关闭
    assert.throws(() => {
      registerTrustedRewriteConfirmation({
        db,
        proposalPath: prop.proposalPath,
        targetPath,
        trustedChannelVerified: false
      });
    }, /TRUSTED_HUMAN_CHANNEL_DISABLED/);

    // 即使在已验证可信通道登记 user_confirmed_rewrite，后续修改任一文件仍退回 unverified (version_changed)
    const conf = registerTrustedRewriteConfirmation({
      db,
      proposalPath: prop.proposalPath,
      targetPath,
      trustedChannelVerified: true
    });
    assert.equal(conf.reconcile_state, 'user_confirmed_rewrite');
    fs.appendFileSync(prop.proposalPath, '\n<!-- 改写提案 -->\n', 'utf8');
    const afterEdit = checkProposalReconcileState({ db, proposalPath: prop.proposalPath, targetPath });
    assert.equal(afterEdit.reconcile_state, 'unverified');
    assert.equal(afterEdit.reason, 'version_changed');
  });
});
