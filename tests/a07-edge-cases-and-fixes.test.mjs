import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { openDatabase } from '../src/db/sqlite.mjs';
import { readFrontmatterId } from '../src/storage/path-sanitizer.mjs';
import { stageCandidate, publishFile, recoverInterruptedPublish } from '../src/storage/atomic-publisher.mjs';
import { restoreNote } from '../src/storage/restore-manager.mjs';
import { parseProposalContent } from '../src/reconcile/engine.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { isWhitelistedVaultPath } from '../src/git/repo-manager.mjs';

test('A07: 边缘用例与审计修复全量回归测试', async (t) => {
  const baseDir = path.resolve('.tmp/test-a07-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');
  const queueDir = path.join(vaultDir, '40_Review_Queue');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const stagingDir = path.join(dataDir, 'staging');
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');

  fs.mkdirSync(notesDir, { recursive: true });
  fs.mkdirSync(queueDir, { recursive: true });
  fs.mkdirSync(stagingDir, { recursive: true });

  const db = openDatabase(dbPath);

  t.after(() => {
    try {
      db.close();
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  await t.test('1. Windows UTF-8 BOM 兼容性：带 BOM 的 Frontmatter 解析与 ID 读取', () => {
    const bomFilePath = path.join(notesDir, 'KN-BOM-test.md');
    const contentWithBom = '\uFEFF---\nid: "KN-BOM-001"\ntitle: "带BOM标题"\n---\n正文内容';
    fs.writeFileSync(bomFilePath, contentWithBom, 'utf8');

    // 验证 readFrontmatterId 正常读取
    const extractedId = readFrontmatterId(bomFilePath);
    assert.equal(extractedId, 'KN-BOM-001');

    // 验证 parseProposalContent 正常解析
    const propWithBom = '\uFEFF---\nid: "PROP-BOM-001"\ntarget_id: "KN-001"\nproposal_status: "pending"\n---\n提案正文';
    const parsed = parseProposalContent(propWithBom);
    assert.equal(parsed.frontmatter.id, 'PROP-BOM-001');
    assert.equal(parsed.frontmatter.target_id, 'KN-001');
    assert.equal(parsed.frontmatter.proposal_status, 'pending');
  });

  await t.test('2. publishFile 遇到目标已存在时的 R7 碰撞消歧与重试处理', () => {
    const uuid1 = 'KN-019316a8-7c40-7000-8000-1111114d5e6f';
    const uuid2 = 'KN-019316a8-7c40-7000-8000-2222224d5e6f';
    const initialTarget = path.join(notesDir, 'KN-20261110-4d5e6f_碰撞测试笔记.md');

    // 1. 发布第一篇笔记
    const stage1 = stageCandidate({
      stagingDir,
      outputUuid: uuid1,
      content: `---\nschema_version: 1\nid: "${uuid1}"\ntitle: "碰撞测试笔记"\n---\n第一篇正文`
    });

    const pub1 = publishFile({
      db,
      operationId: 'op-edge-001',
      outputUuid: uuid1,
      stagingPath: stage1.stagingPath,
      vaultTargetPath: initialTarget,
      contentSha256: stage1.contentSha256,
      metadata: { title: '碰撞测试笔记', prefix: 'KN', dateStr: '20261110' }
    });

    assert.equal(pub1.success, true);
    assert.equal(pub1.vaultTargetPath, initialTarget);
    assert.equal(pub1.collided, false);

    // 2. 同作业重试场景：再次调用 publishFile 发布同一 uuid1 到 initialTarget
    const stage1Retry = stageCandidate({
      stagingDir,
      outputUuid: uuid1 + '-retry',
      content: `---\nschema_version: 1\nid: "${uuid1}"\ntitle: "碰撞测试笔记"\n---\n第一篇正文重试`
    });

    const pub1Retry = publishFile({
      db,
      operationId: 'op-edge-001-retry',
      outputUuid: uuid1,
      stagingPath: stage1Retry.stagingPath,
      vaultTargetPath: initialTarget,
      contentSha256: stage1Retry.contentSha256
    });

    assert.equal(pub1Retry.success, true);
    assert.equal(pub1Retry.isRetry, true);
    assert.equal(pub1Retry.vaultTargetPath, initialTarget);

    // 3. 碰撞场景：另一篇不同 uuid2 的笔记发布到同一个 initialTarget 路径
    const stage2 = stageCandidate({
      stagingDir,
      outputUuid: uuid2,
      content: `---\nschema_version: 1\nid: "${uuid2}"\ntitle: "碰撞测试笔记"\n---\n第二篇正文`
    });

    const pub2 = publishFile({
      db,
      operationId: 'op-edge-002',
      outputUuid: uuid2,
      stagingPath: stage2.stagingPath,
      vaultTargetPath: initialTarget,
      contentSha256: stage2.contentSha256,
      metadata: { title: '碰撞测试笔记', prefix: 'KN', dateStr: '20261110' }
    });

    assert.equal(pub2.success, true);
    assert.equal(pub2.collided, true);
    assert.equal(pub2.expanded, true);
    assert.notEqual(pub2.vaultTargetPath, initialTarget);
    assert.ok(pub2.vaultTargetPath.includes('2222224d5e6f'));

    // 验证两篇物理笔记均完好无损存在
    assert.ok(fs.existsSync(initialTarget));
    assert.ok(fs.existsSync(pub2.vaultTargetPath));
    assert.ok(fs.readFileSync(initialTarget, 'utf8').includes(uuid1));
    assert.ok(fs.readFileSync(pub2.vaultTargetPath, 'utf8').includes(uuid2));
  });

  await t.test('3. recoverInterruptedPublish 遭遇目标路径已存在其他 ID 时的消歧恢复', () => {
    const crashUuid = 'KN-019316a8-7c40-7000-8000-3333334d5e6f';
    const occupiedTarget = path.join(notesDir, 'KN-20261110-4d5e6f_碰撞测试笔记.md'); // 已被 uuid1 占用

    const stageCrash = stageCandidate({
      stagingDir,
      outputUuid: crashUuid,
      content: `---\nschema_version: 1\nid: "${crashUuid}"\ntitle: "碰撞测试笔记"\n---\n崩溃恢复新笔记`
    });

    db.prepare(`
      INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'linking', datetime('now'), datetime('now'))
    `).run('op-crash-collision', crashUuid, stageCrash.stagingPath, occupiedTarget, stageCrash.contentSha256);

    const recResult = recoverInterruptedPublish({
      db,
      operationId: 'op-crash-collision'
    });

    assert.equal(recResult.recovered, true);
    assert.equal(recResult.details[0].action, 'disambiguated_collision_expanded');
    assert.notEqual(recResult.details[0].targetPath, occupiedTarget);
    assert.ok(recResult.details[0].targetPath.includes('3333334d5e6f'));
    assert.ok(fs.existsSync(recResult.details[0].targetPath));
  });

  await t.test('4. restoreNote 保护现有笔记：原文件存在时禁止原地覆写，仅生成差异预览', () => {
    const existingNoteUuid = 'KN-EXISTING-001';
    const existingPath = path.join(notesDir, 'KN-existing.md');
    fs.writeFileSync(existingPath, '原始用户未丢失内容', 'utf8');

    const res = restoreNote({
      db,
      noteId: existingNoteUuid,
      revision: 'rev-0001',
      content: '旧版历史恢复内容',
      targetVaultPath: existingPath,
      stagingDir
    });

    assert.equal(res.restored, false);
    assert.equal(res.reason, 'target_file_exists_merge_in_obsidian');
    assert.ok(fs.existsSync(res.previewPath));
    assert.equal(fs.readFileSync(existingPath, 'utf8'), '原始用户未丢失内容', '现有正式文件严禁被原地覆写');
  });

  await t.test('5. searchKnowledge 行为契约：暂停召回 missing 笔记，且 supplement 提案不阻塞 actionable', () => {
    const searchUuid1 = 'KN-019316a8-7c40-7000-8000-search111111';
    const note1Path = path.join(notesDir, 'KN-search1.md');
    fs.writeFileSync(note1Path, `---
schema_version: 1
id: "${searchUuid1}"
note_type: "playbook"
title: "搜索测试手册"
project: "SearchOps"
privacy: "sanitized"
created_at: "2026-11-10T12:00:00+08:00"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "linux"
---
测试搜索内容
`, 'utf8');

    // 在 SQLite 标记为 missing
    db.prepare(`
      INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, evidence_level, review_state, status, created_at)
      VALUES (?, 'playbook', '搜索测试手册', 'SearchOps', 'sanitized', ?, 'sha1', 'active', 'observed', 'accepted', 'missing', datetime('now'))
      ON CONFLICT(id) DO UPDATE SET status = 'missing'
    `).run(searchUuid1, note1Path);

    // 验证 missing 笔记暂停召回
    const res1 = searchKnowledge({ db, vaultDir, query: '搜索测试' });
    assert.equal(res1.items.length, 0, 'missing 状态的笔记必须被暂停召回');

    // 恢复为 active
    db.prepare(`UPDATE notes SET status = 'active' WHERE id = ?`).run(searchUuid1);

    // 添加一个补充型提案 (supplement)
    const propUuid = 'PROP-SUPPLEMENT-001';
    const propPath = path.join(queueDir, 'PROP-supplement.md');
    fs.writeFileSync(propPath, `---
schema_version: 1
id: "${propUuid}"
note_type: "proposal"
title: "仅补充说明"
project: "SearchOps"
privacy: "sanitized"
target_id: "${searchUuid1}"
target_note: "[[KN-search1.md]]"
base_revision_id: "rev-0001"
proposal_kind: "supplement"
proposal_status: "pending"
created_at: "2026-11-10T12:00:00+08:00"
---
补充说明内容
`, 'utf8');

    // 验证：仅有 supplement 提案时，目标笔记仍然保持 actionable: true
    const res2 = searchKnowledge({ db, vaultDir, query: '搜索测试' });
    assert.equal(res2.items.length, 1);
    assert.equal(res2.items[0].actionable, true, '纯 supplement 提案不应破坏现有笔记的 actionable 属性');
  });

  await t.test('6. isWhitelistedVaultPath 严格阻断同前缀兄弟目录 (如 AgentMemory-Data)', () => {
    const siblingDir = path.resolve(vaultDir + '-Data');
    const siblingFile = path.join(siblingDir, 'raw', 'secret.jsonl');
    assert.equal(isWhitelistedVaultPath(vaultDir, siblingFile), false);

    const normalVaultFile = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-001.md');
    assert.equal(isWhitelistedVaultPath(vaultDir, normalVaultFile), true);
  });
});
