import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { openDatabase } from '../src/db/sqlite.mjs';
import {
  scanAndSyncNotes,
  calculateItemKey,
  confirmDeleteNote,
  isFactTombstoned
} from '../src/tombstone/tracker.mjs';
import { restoreNote } from '../src/storage/restore-manager.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';

test('A06: 改名检测、缺失识别、跨快照稳定墓碑与单篇历史恢复', async (t) => {
  const baseDir = path.resolve('.tmp/test-a06-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const stagingDir = path.join(dataDir, 'staging');
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');

  fs.mkdirSync(notesDir, { recursive: true });
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

  const noteUuid = 'KN-019316a8-7c40-7000-8000-aaaaaaaaaaaa';
  let initialNotePath = path.join(notesDir, 'KN-20261110-aaaaaa_初始文件名.md');
  const noteContent = `---
schema_version: 1
id: "${noteUuid}"
note_type: "playbook"
title: "Nginx 工作进程调优"
project: "WebInfra"
privacy: "sanitized"
created_at: "2026-11-10T12:00:00+08:00"
lifecycle: "active"
evidence_level: "user_confirmed"
review_state: "accepted"
env: "linux"
source_tool: "claude-code"
session_id: "sess-20261110-001"
canonical_event_anchor: "^event-000042"
fact_type: "playbook"
normalized_subject: "nginx worker_processes tuning"
---

## 1. 现象与触发情境
高并发下 Nginx 报 worker 瓶颈。
`;

  fs.writeFileSync(initialNotePath, noteContent, 'utf8');

  // 在 SQLite 初始登记该笔记
  db.prepare(`
    INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, evidence_level, review_state, status, created_at)
    VALUES (?, 'playbook', 'Nginx 工作进程调优', 'WebInfra', 'sanitized', ?, 'sha1', 'active', 'user_confirmed', 'accepted', 'active', datetime('now'))
  `).run(noteUuid, initialNotePath);

  await t.test('1. 改名自动识别：路径变更但 YAML id 一致时更新路径，保持 active', () => {
    // 模拟用户在 Obsidian 中将文件重命名
    const renamedPath = path.join(notesDir, 'KN-20261110-aaaaaa_用户重命名后的文件.md');
    fs.renameSync(initialNotePath, renamedPath);

    const syncReport = scanAndSyncNotes({ db, vaultDir });
    assert.equal(syncReport.renamed.length, 1);
    assert.equal(syncReport.renamed[0].id, noteUuid);
    assert.equal(syncReport.renamed[0].newPath, renamedPath);

    // 检查 SQLite 中的记录已更新为新路径
    const noteInDb = db.prepare('SELECT * FROM notes WHERE id = ?').get(noteUuid);
    assert.equal(noteInDb.path, renamedPath);
    assert.equal(noteInDb.status, 'active');

    initialNotePath = renamedPath;
  });

  await t.test('2. 缺失识别：文件丢失且未找到对应 UUID 时标为 missing，不误转墓碑', () => {
    // 模拟用户在 Vault 外移走或删除了该文件
    const tempBackup = initialNotePath + '.bak';
    fs.renameSync(initialNotePath, tempBackup);

    const syncReport = scanAndSyncNotes({ db, vaultDir });
    assert.equal(syncReport.missing.length, 1);
    assert.equal(syncReport.missing[0].id, noteUuid);

    // 检查 SQLite 状态被置为 missing，但 tombstones 表中绝无此条目
    const noteInDb = db.prepare('SELECT * FROM notes WHERE id = ?').get(noteUuid);
    assert.equal(noteInDb.status, 'missing');

    const tombstone = db.prepare('SELECT * FROM tombstones WHERE output_uuid = ?').get(noteUuid);
    assert.equal(tombstone, undefined, '未确认删除前绝不自动转入 tombstones 表');

    // 还原文件准备后续测试
    fs.renameSync(tempBackup, initialNotePath);
    scanAndSyncNotes({ db, vaultDir });
  });

  let tombstonedItemKey;

  await t.test('3. 跨快照稳定 item_key 与墓碑抑制 (D2 核心验收点)', () => {
    // 计算事实 1 的 item_key (严禁包含 snapshot_id)
    tombstonedItemKey = calculateItemKey({
      sourceTool: 'claude-code',
      sessionId: 'sess-20261110-001',
      canonicalEventAnchor: '^event-000042',
      factType: 'playbook',
      normalizedSubject: 'nginx worker_processes tuning'
    });

    // 严禁包含 snapshot_id 校验：传入不同 snapshot_id 应该产生完全相同的 item_key
    const itemKeySnapshotA = calculateItemKey({
      sourceTool: 'claude-code',
      sessionId: 'sess-20261110-001',
      canonicalEventAnchor: '^event-000042',
      factType: 'playbook',
      normalizedSubject: 'nginx worker_processes tuning',
      snapshotId: 'snap-version-1' // 传入也必须被忽略
    });
    assert.equal(tombstonedItemKey, itemKeySnapshotA, 'item_key 必须跨快照稳定，严禁受 snapshot_id 影响');

    // 用户显式确认删除该笔记 (mem delete <id> --confirm)
    const delResult = confirmDeleteNote({
      db,
      noteId: noteUuid,
      notePath: initialNotePath,
      reason: '用户手动确认废弃该调优建议'
    });

    assert.equal(delResult.deleted, true);
    assert.equal(delResult.itemKey, tombstonedItemKey);

    // 验证 tombstones 表已写入
    const tomb = db.prepare('SELECT * FROM tombstones WHERE item_key = ?').get(tombstonedItemKey);
    assert.ok(tomb);
    assert.equal(tomb.output_uuid, noteUuid);

    // 核心断言：当该会话追加新事件产生新快照 (snap-version-2) 触发显式重审时
    // 已删除的事实项通过稳定 item_key 检查依然被抑制，绝对不会复活！
    const fact1Suppressed = isFactTombstoned({ db, itemKey: tombstonedItemKey });
    assert.equal(fact1Suppressed, true, '已删除事实项在追加新快照后必须持续受墓碑抑制，绝不复活');

    // 同会话下的另一个事实项（例如事件 ^event-000088）不受影响
    const fact2ItemKey = calculateItemKey({
      sourceTool: 'claude-code',
      sessionId: 'sess-20261110-001',
      canonicalEventAnchor: '^event-000088',
      factType: 'decision',
      normalizedSubject: 'nginx keepalive_timeout setting'
    });
    const fact2Suppressed = isFactTombstoned({ db, itemKey: fact2ItemKey });
    assert.equal(fact2Suppressed, false, '同会话未删除的事实项绝不受影响');
  });

  await t.test('4. 单篇历史恢复 (mem restore <id> --revision <rev>)', () => {
    // 准备恢复历史版本
    const revContent = noteContent.replace('初始文件名', '历史版本恢复内容');

    const restoreRes = restoreNote({
      db,
      noteId: noteUuid,
      revision: 'rev-0001',
      content: revContent,
      targetVaultPath: path.join(notesDir, 'KN-20261110-aaaaaa_恢复后的笔记.md'),
      stagingDir
    });

    assert.equal(restoreRes.restored, true);
    assert.ok(fs.existsSync(restoreRes.targetPath));

    // 墓碑精确解除
    const tombAfter = db.prepare('SELECT * FROM tombstones WHERE output_uuid = ?').get(noteUuid);
    assert.equal(tombAfter, undefined, '单篇恢复后墓碑表必须被精确解除');

    // 状态已恢复为 active
    const noteInDb = db.prepare('SELECT * FROM notes WHERE id = ?').get(noteUuid);
    assert.equal(noteInDb.status, 'active');

    // 检索自检：可以重新检索到该笔记
    const searchRes = searchKnowledge({
      db,
      vaultDir,
      query: 'Nginx 工作进程调优'
    });
    assert.equal(searchRes.items.length, 1);
    assert.equal(searchRes.items[0].id, noteUuid);
    assert.equal(searchRes.items[0].actionable, true);
  });
});
