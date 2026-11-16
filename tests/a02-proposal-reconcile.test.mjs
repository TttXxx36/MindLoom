import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { openDatabase } from '../src/db/sqlite.mjs';
import {
  createProposal,
  reconcileProposal,
  checkProposalReconcileState
} from '../src/reconcile/engine.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';

test('A02: 独立提案机制、前后置条件双校验与双版本哈希绑定退回', async (t) => {
  const baseDir = path.resolve('.tmp/test-a02-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const queueDir = path.join(vaultDir, '40_Review_Queue');
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');
  const dbPath = path.join(baseDir, 'AgentMemory-Data', 'runtime', 'state.sqlite');

  fs.mkdirSync(queueDir, { recursive: true });
  fs.mkdirSync(notesDir, { recursive: true });

  const db = openDatabase(dbPath);

  t.after(() => {
    try {
      db.close();
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  const targetUuid = 'KN-019316a8-7c40-7000-8000-111122223333';
  const targetNotePath = path.join(notesDir, 'KN-20261110-223333_端口排查手册.md');
  const originalTargetContent = `---
schema_version: 1
id: "${targetUuid}"
note_type: "playbook"
title: "端口排查手册"
project: "ObsidianOps"
privacy: "sanitized"
created_at: "2026-11-10T12:00:00+08:00"
lifecycle: "active"
evidence_level: "user_confirmed"
review_state: "accepted"
env: "linux"
---

## 1. 现象与触发情境
容器无法启动，提示端口冲突。

## 4. 处理步骤
执行旧版排查命令：
netstat -an | grep 8080
`;

  fs.writeFileSync(targetNotePath, originalTargetContent, 'utf8');

  // 在 SQLite 登记目标笔记
  db.prepare(`
    INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, evidence_level, review_state, status, created_at)
    VALUES (?, 'playbook', '端口排查手册', 'ObsidianOps', 'sanitized', ?, 'hash1', 'active', 'user_confirmed', 'accepted', 'active', datetime('now'))
  `).run(targetUuid, targetNotePath);

  let proposalUuid = 'PROP-019316a8-7c40-7000-8000-444455556666';
  let proposalPath;

  await t.test('1. 只增不改：生成独立提案 PROP-*.md，目标文件保持零改动', () => {
    const propResult = createProposal({
      queueDir,
      proposalUuid,
      title: '更新建议: 修正端口排查命令',
      project: 'ObsidianOps',
      targetId: targetUuid,
      targetNoteRef: '[[KN-20261110-223333_端口排查手册]]',
      baseRevisionId: 'rev-0001',
      proposalKind: 'conflict',
      preConditions: ['netstat -an | grep 8080'],
      postConditions: ['ss -tulpn | grep 8080'],
      reason: 'netstat 在较新 Linux 发行版中已被淘汰，建议使用 ss'
    });

    proposalPath = propResult.proposalPath;
    assert.ok(fs.existsSync(proposalPath), '提案文件应当已在 40_Review_Queue 中创建');

    // 验证目标原文件零改动
    const targetContentAfter = fs.readFileSync(targetNotePath, 'utf8');
    assert.equal(targetContentAfter, originalTargetContent, '目标原文件必须保持 100% 零修改');
  });

  await t.test('2. 结构化前后置条件核对：未移除旧错误步骤时拒绝放行', () => {
    // 模拟用户在 Obsidian 将提案状态改为 accepted
    let propContent = fs.readFileSync(proposalPath, 'utf8');
    propContent = propContent.replace('proposal_status: "pending"', 'proposal_status: "accepted"');
    fs.writeFileSync(proposalPath, propContent, 'utf8');

    // 用户在目标笔记中追加了新标题和新命令，但旧的错误命令 netstat 仍然保留！
    fs.appendFileSync(targetNotePath, '\nss -tulpn | grep 8080\n', 'utf8');

    // 运行 reconcile
    const reconcileResult = reconcileProposal({
      db,
      proposalPath,
      targetPath: targetNotePath
    });

    assert.equal(reconcileResult.reconcile_state, 'unverified');
    assert.ok(reconcileResult.reason.includes('pre_condition_unmet'), `核对原因应指出前置条件未满足: ${reconcileResult.reason}`);

    // 此时检索，目标笔记必须保持 actionable: false
    const searchRes = searchKnowledge({
      db,
      vaultDir,
      query: '端口排查'
    });
    assert.equal(searchRes.items.length, 1);
    assert.equal(searchRes.items[0].actionable, false);
  });

  await t.test('3. 前后置条件均满足：核对通过并绑定双版本 SHA256 哈希', () => {
    // 用户真正移除了旧错误步骤 netstat，并确保只有 ss 新命令
    const fixedTargetContent = `---
schema_version: 1
id: "${targetUuid}"
note_type: "playbook"
title: "端口排查手册"
project: "ObsidianOps"
privacy: "sanitized"
created_at: "2026-11-10T12:00:00+08:00"
lifecycle: "active"
evidence_level: "user_confirmed"
review_state: "accepted"
env: "linux"
---

## 1. 现象与触发情境
容器无法启动，提示端口冲突。

## 4. 处理步骤
执行最新排查命令：
ss -tulpn | grep 8080
`;
    fs.writeFileSync(targetNotePath, fixedTargetContent, 'utf8');

    const reconcileResult = reconcileProposal({
      db,
      proposalPath,
      targetPath: targetNotePath
    });

    assert.equal(reconcileResult.reconcile_state, 'verified_applied');
    assert.equal(reconcileResult.reason, null);

    // 验证检索：因提案已 verified_applied，目标笔记升级进入 Channel 1 (actionable: true)
    const searchRes = searchKnowledge({
      db,
      vaultDir,
      query: '端口排查'
    });
    assert.equal(searchRes.items.length, 1);
    assert.equal(searchRes.items[0].actionable, true);
  });

  await t.test('4. 双版本哈希失配退回分支 1：修改目标笔记导致失配退回 unverified (reason: version_changed)', () => {
    // 模拟用户在 Obsidian 中又修改了目标笔记（例如重新添加了一行注释）
    fs.appendFileSync(targetNotePath, '\n<!-- 用户后续又编辑了目标笔记 -->\n', 'utf8');

    // 状态检查
    const checkState = checkProposalReconcileState({
      db,
      proposalPath,
      targetPath: targetNotePath
    });

    assert.equal(checkState.reconcile_state, 'unverified');
    assert.equal(checkState.reason, 'version_changed');

    // 检索联动：实时比对双版本哈希，检测到失配立即降为 actionable: false
    const searchRes = searchKnowledge({
      db,
      vaultDir,
      query: '端口排查'
    });
    assert.equal(searchRes.items.length, 1);
    assert.equal(searchRes.items[0].actionable, false);
    assert.ok(searchRes.items[0].reason.includes('version_changed'));
  });

  await t.test('5. 双版本哈希失配退回分支 2：仅修改提案文件导致失配退回 unverified (reason: version_changed)', () => {
    // 先重新核对通过
    reconcileProposal({
      db,
      proposalPath,
      targetPath: targetNotePath
    });

    // 此时仅手改提案正文，目标笔记完全不变！
    fs.appendFileSync(proposalPath, '\n<!-- 仅修改提案正文说明 -->\n', 'utf8');

    // 状态检查
    const checkState = checkProposalReconcileState({
      db,
      proposalPath,
      targetPath: targetNotePath
    });

    assert.equal(checkState.reconcile_state, 'unverified');
    assert.equal(checkState.reason, 'version_changed');

    // 检索联动：同样自动降级为 actionable: false
    const searchRes = searchKnowledge({
      db,
      vaultDir,
      query: '端口排查'
    });
    assert.equal(searchRes.items.length, 1);
    assert.equal(searchRes.items[0].actionable, false);
    assert.ok(searchRes.items[0].reason.includes('version_changed'));
  });
});
