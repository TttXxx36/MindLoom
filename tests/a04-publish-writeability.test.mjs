import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { openDatabase } from '../src/db/sqlite.mjs';
import {
  stageCandidate,
  publishFile,
  recoverInterruptedPublish
} from '../src/storage/atomic-publisher.mjs';

test('A04: NTFS 硬链接原子发布、可写性保障与 R1 中断恢复', async (t) => {
  const baseDir = path.resolve('.tmp/test-a04-' + Date.now());
  const stagingDir = path.join(baseDir, 'AgentMemory-Data', 'staging');
  const vaultDir = path.join(baseDir, 'AgentMemory', '30_Knowledge_Notes', 'Playbooks');
  const dbPath = path.join(baseDir, 'AgentMemory-Data', 'runtime', 'state.sqlite');

  fs.mkdirSync(stagingDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });

  const db = openDatabase(dbPath);

  t.after(() => {
    try {
      db.close();
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  const sampleUuid = 'KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f';
  const initialContent = `---
schema_version: 1
id: "${sampleUuid}"
note_type: "playbook"
title: "容器端口绑定失败排查"
project: "ObsidianOps"
privacy: "sanitized"
created_at: "2026-11-10T12:00:00+08:00"
lifecycle: "active"
evidence_level: "observed"
review_state: "pending"
env: "production"
---

## 1. 现象与触发情境
容器启动时报端口已被占用错误。
`;

  await t.test('1. 暂存文件 wx 独占创建，严禁设置 OS 只读属性 (Panel B 铁律)', () => {
    const { stagingPath, contentSha256 } = stageCandidate({
      stagingDir,
      outputUuid: sampleUuid,
      content: initialContent
    });

    assert.ok(fs.existsSync(stagingPath));
    const stat = fs.statSync(stagingPath);
    // 验证文件权限：在 Windows / POSIX 上均保持可写（非只读）
    // mode 掩码 0o200 表示所有者可写
    assert.ok((stat.mode & 0o200) !== 0, 'staging 文件必须具有可写权限，严禁设为只读');

    const expectedHash = crypto.createHash('sha256').update(initialContent).digest('hex');
    assert.equal(contentSha256, expectedHash);

    // 验证 wx 独占写入：同一 staging 路径再次创建应当抛出 EEXIST
    assert.throws(() => {
      stageCandidate({
        stagingDir,
        outputUuid: sampleUuid,
        content: initialContent
      });
    }, /EEXIST/);
  });

  await t.test('2. NTFS 硬链接原子发布与正式笔记 100% 可写性 (Panel B 核心指标)', () => {
    const stagingPath = path.join(stagingDir, `stg-${sampleUuid}.md`);
    const vaultTargetPath = path.join(vaultDir, 'KN-20261110-4d5e6f_容器端口绑定失败排查.md');
    const contentSha256 = crypto.createHash('sha256').update(initialContent).digest('hex');

    const publishResult = publishFile({
      db,
      operationId: 'op-001',
      outputUuid: sampleUuid,
      stagingPath,
      vaultTargetPath,
      contentSha256
    });

    assert.equal(publishResult.success, true);
    assert.ok(fs.existsSync(vaultTargetPath), 'Vault 正式笔记应当存在');
    assert.equal(fs.existsSync(stagingPath), false, 'stagingPath 应当已在发布后安全 unlink');

    // 检查 SQLite 台账状态
    const intent = db.prepare('SELECT * FROM publish_intents WHERE operation_id = ?').get('op-001');
    assert.equal(intent.state, 'files_published');

    // 核心可写性验证：模拟用户在 Obsidian 中编辑（追加内容与覆写），必须 100% 成功，零 EPERM
    assert.doesNotThrow(() => {
      fs.appendFileSync(vaultTargetPath, '\n<!-- 用户在 Obsidian 中手写追加的补充注释 -->\n', 'utf8');
      const fd = fs.openSync(vaultTargetPath, 'r+');
      fs.writeSync(fd, '<!-- 追加头部 -->', 0, 'utf8');
      fs.closeSync(fd);
    });

    const editedContent = fs.readFileSync(vaultTargetPath, 'utf8');
    assert.ok(editedContent.includes('用户在 Obsidian 中手写追加的补充注释'));
  });

  await t.test('3. R1 中断恢复协议：在 link 成功、unlink 发生前崩溃后的恢复与手改内容保护', () => {
    const crashUuid = 'KN-019316a8-7c40-7000-8000-999999999999';
    const crashContent = `---
schema_version: 1
id: "${crashUuid}"
note_type: "playbook"
title: "崩溃中断恢复测试"
project: "ObsidianOps"
privacy: "sanitized"
created_at: "2026-11-10T12:00:00+08:00"
lifecycle: "active"
evidence_level: "observed"
review_state: "pending"
env: "test"
---
## 1. 原始发布内容
`;

    // 1. 模拟 stage
    const { stagingPath, contentSha256 } = stageCandidate({
      stagingDir,
      outputUuid: crashUuid,
      content: crashContent
    });

    const vaultTargetPath = path.join(vaultDir, 'KN-20261110-999999_崩溃中断恢复测试.md');

    // 2. 登记 linking 状态
    db.prepare(`
      INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'linking', datetime('now'), datetime('now'))
    `).run('op-crash-001', crashUuid, stagingPath, vaultTargetPath, contentSha256);

    // 3. 建立硬链接
    fs.linkSync(stagingPath, vaultTargetPath);

    // 4. 模拟在 unlinkSync 前进程崩溃！此时 stagingPath 与 vaultTargetPath 并存
    assert.ok(fs.existsSync(stagingPath));
    assert.ok(fs.existsSync(vaultTargetPath));

    // 5. 模拟崩溃期间用户在 Obsidian 中打开并修改了 vaultTargetPath！
    const userEdits = '\n## 用户紧急修改\n用户在崩溃中断期间手工补充了排错方案。';
    fs.appendFileSync(vaultTargetPath, userEdits, 'utf8');

    // 6. 恢复流程启动
    const recoverResult = recoverInterruptedPublish({
      db,
      operationId: 'op-crash-001'
    });

    assert.equal(recoverResult.recovered, true);

    // 7. 验证：
    // - stagingPath 已被安全移除
    assert.equal(fs.existsSync(stagingPath), false, '残留暂存硬链接必须被安全 unlink');
    // - vaultTargetPath 完好保留，且用户手改内容绝对未丢失！
    const currentVaultContent = fs.readFileSync(vaultTargetPath, 'utf8');
    assert.ok(currentVaultContent.includes('用户在崩溃中断期间手工补充了排错方案'), '恢复流程严禁覆盖用户手改内容');
    // - 正式笔记依然保持可写
    assert.doesNotThrow(() => {
      fs.appendFileSync(vaultTargetPath, '\n<!-- 恢复后依然可写 -->\n', 'utf8');
    });

    // - 数据库意图状态已更新为 files_published
    const updatedIntent = db.prepare('SELECT * FROM publish_intents WHERE operation_id = ?').get('op-crash-001');
    assert.equal(updatedIntent.state, 'files_published');
  });
});
