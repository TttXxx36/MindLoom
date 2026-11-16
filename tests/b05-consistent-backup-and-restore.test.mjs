import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';
import { commitPublishedFile, initGitRepo } from '../src/git/repo-manager.mjs';
import { confirmDeleteNote, isFactTombstoned, calculateItemKey } from '../src/tombstone/tracker.mjs';
import { buildLocalSearchIndex } from '../src/search/query-engine.mjs';
import {
  acquirePublisherLock,
  releasePublisherLock,
  createConsistentBackup,
  restoreFromBackup
} from '../src/backup/backup-manager.mjs';

test('B05: R4 跨文件一致性备份与灾难恢复演练', async (t) => {
  const baseDir = path.resolve('.tmp/test-b05-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const backupRoot = path.join(baseDir, 'ExternalBackups');
  const restoredRoot = path.join(baseDir, 'RestoredEnv');
  const newVaultDir = path.join(restoredRoot, 'AgentMemory');
  const newDataDir = path.join(restoredRoot, 'AgentMemory-Data');

  initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  initGitRepo(vaultDir);
  execFileSync('git', ['config', 'user.name', 'BackupTester'], { cwd: vaultDir });
  execFileSync('git', ['config', 'user.email', 'bkp@example.com'], { cwd: vaultDir });
  execFileSync('git', ['add', '首页.md'], { cwd: vaultDir });
  execFileSync('git', ['commit', '-m', 'init vault'], { cwd: vaultDir });

  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
  const db = openDatabase(dbPath);

  t.after(() => {
    try {
      db.close();
    } catch {}
    try {
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {}
  });

  // 1. 准备完整持久态要素：已发布笔记、未提交 Git 变更、附件、raw、manifest、tombstone、linking 残留硬链接 + 手改内容、未发布 staging 候选
  const stagingDir = path.join(dataDir, 'staging');
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');

  // 1a. 正常已发布笔记 KN-1 (供恢复后检索自检)
  const kn1Uuid = 'KN-019316a8-7c40-7000-8000-b05000000001';
  const kn1Path = path.join(notesDir, 'KN-20261110-000001_备份恢复验证手册.md');
  const kn1Content = `---
schema_version: 1
id: "${kn1Uuid}"
note_type: "playbook"
title: "备份恢复验证手册"
project: "BackupOps"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "user_confirmed"
review_state: "accepted"
env: "windows"
created_at: "2026-11-10T12:00:00+08:00"
---
关键恢复步骤：先恢复未完成作业再清废弃暂存。
`;
  const stg1 = stageCandidate({ stagingDir, outputUuid: kn1Uuid, content: kn1Content });
  publishFile({
    db,
    operationId: 'op-b05-kn1',
    outputUuid: kn1Uuid,
    stagingPath: stg1.stagingPath,
    vaultTargetPath: kn1Path,
    contentSha256: stg1.contentSha256,
    metadata: { note_type: 'playbook', title: '备份恢复验证手册', project: 'BackupOps', privacy: 'sanitized', lifecycle: 'active', evidence_level: 'user_confirmed', review_state: 'accepted' }
  });
  commitPublishedFile({ vaultDir, filePath: kn1Path, commitMessage: 'feat: add kn1' });

  // 1b. 未提交 Git 的正式笔记变更（用户草稿 / 待提交文件）
  const uncommittedVaultFile = path.join(notesDir, 'KN-uncommitted-draft.md');
  fs.writeFileSync(uncommittedVaultFile, '---\nid: "KN-DRAFT-B05"\nprivacy: "sanitized"\n---\n未提交 Git 的最新用户笔记\n', 'utf8');

  // 1c. 已删除并登记墓碑的事实（恢复后绝不能再生）
  const delUuid = 'KN-019316a8-7c40-7000-8000-b05000000002';
  const delPath = path.join(notesDir, 'KN-20261110-000002_已删废弃项.md');
  const delContent = `---
schema_version: 1
id: "${delUuid}"
note_type: "playbook"
title: "已删废弃项"
project: "BackupOps"
privacy: "sanitized"
source_tool: "codex"
session_id: "sess-b05"
canonical_event_anchor: "^event-000007"
fact_type: "playbook"
normalized_subject: "deleted backup rule"
---
已废弃内容
`;
  fs.writeFileSync(delPath, delContent, 'utf8');
  db.prepare(`
    INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at)
    VALUES (?, 'playbook', '已删废弃项', 'BackupOps', 'sanitized', ?, 'sha', 'active', datetime('now'))
  `).run(delUuid, delPath);
  const delRes = confirmDeleteNote({ db, noteId: delUuid, notePath: delPath });

  // 1d. 附件、raw、manifest、egress 批准记录
  fs.writeFileSync(path.join(dataDir, 'attachments', 'att-b05.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  fs.writeFileSync(path.join(dataDir, 'raw', 'b05-raw.jsonl'), '{"type":"user","content":"b05"}\n', 'utf8');
  fs.writeFileSync(path.join(dataDir, 'manifests', 'b05-manifest.json'), '{"snapshot_id":"b05"}', 'utf8');
  fs.writeFileSync(path.join(dataDir, 'egress', 'EGR-b05.json'), '{"package_id":"EGR-b05"}', 'utf8');

  // 1e. 模拟中断的硬链接发布 (state = 'linking') 且崩溃期间用户手改了 Vault 文件！
  const crashUuid = 'KN-019316a8-7c40-7000-8000-b05000000003';
  const crashVaultPath = path.join(notesDir, 'KN-20261110-000003_中断硬链接笔记.md');
  const crashContent = `---
schema_version: 1
id: "${crashUuid}"
note_type: "playbook"
title: "中断硬链接笔记"
project: "BackupOps"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "windows"
---
原始暂存内容
`;
  const crashStaged = stageCandidate({ stagingDir, outputUuid: crashUuid, content: crashContent });
  db.prepare(`
    INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
    VALUES ('op-b05-crash', ?, ?, ?, ?, 'linking', datetime('now'), datetime('now'))
  `).run(crashUuid, crashStaged.stagingPath, crashVaultPath, crashStaged.contentSha256);
  fs.linkSync(crashStaged.stagingPath, crashVaultPath);
  // 用户手改了正式笔记
  fs.appendFileSync(crashVaultPath, '\n<!-- 用户在崩溃期间在 Obsidian 手写补充的关键内容 -->\n', 'utf8');

  // 1f. 一个尚未进入 publish 的唯一 staging 候选（灾难恢复严禁先清 staging/！）
  const pendingUuid = 'KN-019316a8-7c40-7000-8000-b05000000004';
  const pendingStaged = stageCandidate({
    stagingDir,
    outputUuid: pendingUuid,
    content: `---\nid: "${pendingUuid}"\ntitle: "未发布唯一候选"\n---\n珍贵的待发布候选正文\n`
  });

  // 1g. 构建可丢弃重建索引 runtime/index/
  buildLocalSearchIndex({ vaultDir, indexDir: path.join(dataDir, 'runtime', 'index') });

  await t.test('1. 一致性备份窗口互斥锁与捕获期间并发改动检测 (标为 incomplete)', () => {
    // 持有互斥锁期间禁止写入 staging/publish
    const lockPath = acquirePublisherLock(dataDir);
    assert.ok(fs.existsSync(lockPath));
    assert.throws(() => {
      stageCandidate({ stagingDir, outputUuid: 'KN-LOCKED', content: 'blocked' });
    }, /PUBLISHER_LOCKED/);
    releasePublisherLock(dataDir);

    // 模拟备份捕获期间外部文件发生改动 -> 二次指纹校验发现不一致并标为 incomplete
    const raceRes = createConsistentBackup({
      vaultPath: vaultDir,
      dataPath: dataDir,
      targetDir: backupRoot,
      maxRetries: 0,
      duringCaptureHook: () => {
        fs.appendFileSync(uncommittedVaultFile, '\n<!-- 备份窗口期间意外写入 -->\n', 'utf8');
      }
    });

    assert.equal(raceRes.status, 'incomplete');
    assert.ok(raceRes.changedFiles.length > 0);
    assert.throws(() => {
      restoreFromBackup({
        backupDir: raceRes.backupDir,
        newVaultPath: newVaultDir,
        newDataPath: newDataDir
      });
    }, /INCOMPLETE_BACKUP_REJECTED/);
  });

  await t.test('2. 完好一致性备份与按 R4 五步顺序恢复到新目录', () => {
    const cleanBackup = createConsistentBackup({
      vaultPath: vaultDir,
      dataPath: dataDir,
      targetDir: backupRoot
    });

    assert.equal(cleanBackup.status, 'complete');
    assert.equal(cleanBackup.changedFiles.length, 0);
    // 验证排除可重建目录 runtime/index/
    assert.equal(
      fs.existsSync(path.join(cleanBackup.backupDir, 'AgentMemory-Data', 'runtime', 'index')),
      false,
      '备份清单应排除可丢弃重建的 runtime/index/'
    );

    // 执行灾难恢复到全新目录 RestoredEnv
    const restoreRes = restoreFromBackup({
      backupDir: cleanBackup.backupDir,
      newVaultPath: newVaultDir,
      newDataPath: newDataDir,
      selfCheckQuery: '备份恢复验证手册'
    });

    assert.equal(restoreRes.restored, true);
    assert.equal(restoreRes.r1Recovery.recovered, true);
    assert.equal(restoreRes.r1Recovery.details[0].action, 'unlinked_staging_kept_user_content');

    // 验证 1: 中断硬链接的 Vault 用户手改内容 100% 保留，且残留 staging 硬链接已安全移除
    const restoredCrashVault = path.join(newVaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-000003_中断硬链接笔记.md');
    const restoredCrashStg = path.join(newDataDir, 'staging', `stg-${crashUuid}.md`);
    assert.ok(fs.existsSync(restoredCrashVault));
    assert.equal(fs.existsSync(restoredCrashStg), false, 'R1 恢复后应移除已发布硬链接的 staging 侧');
    assert.ok(
      fs.readFileSync(restoredCrashVault, 'utf8').includes('用户在崩溃期间在 Obsidian 手写补充的关键内容'),
      'R4 恢复严禁覆盖用户手改内容'
    );

    // 验证 2: 未发布的唯一 staging 候选未被预先清空，完好保留！
    const restoredPendingStg = path.join(newDataDir, 'staging', path.basename(pendingStaged.stagingPath));
    assert.ok(fs.existsSync(restoredPendingStg), '严禁先清空 staging/，未发布的唯一候选必须保留');
    assert.ok(restoreRes.preservedStagingCandidates.some(p => p.endsWith(path.basename(pendingStaged.stagingPath))));

    // 验证 3: 附件、raw、manifests、egress、未提交 Git 草稿全部完好恢复
    assert.ok(fs.existsSync(path.join(newDataDir, 'attachments', 'att-b05.png')));
    assert.ok(fs.existsSync(path.join(newDataDir, 'raw', 'b05-raw.jsonl')));
    assert.ok(fs.existsSync(path.join(newDataDir, 'manifests', 'b05-manifest.json')));
    assert.ok(fs.existsSync(path.join(newDataDir, 'egress', 'EGR-b05.json')));
    assert.ok(fs.existsSync(path.join(newVaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-uncommitted-draft.md')));

    // 验证 4: 删除墓碑持续有效（已删除项不再生）
    const restoredDb = openDatabase(path.join(newDataDir, 'runtime', 'state.sqlite'));
    try {
      const tombKey = calculateItemKey({
        sourceTool: 'codex',
        sessionId: 'sess-b05',
        canonicalEventAnchor: '^event-000007',
        factType: 'playbook',
        normalizedSubject: 'deleted backup rule'
      });
      assert.equal(tombKey, delRes.itemKey);
      assert.equal(isFactTombstoned({ db: restoredDb, itemKey: tombKey }), true, '恢复后墓碑抑制必须保持生效');
    } finally {
      restoredDb.close();
    }

    // 验证 5: 重建 runtime/index/ 并跑通检索自检
    assert.ok(fs.existsSync(path.join(newDataDir, 'runtime', 'index', 'lexical-index.json')));
    assert.equal(restoreRes.verification.selfCheckHits, 1);
  });
});
