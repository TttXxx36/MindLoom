import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { openDatabase, openExistingDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import { ingestSession, distillSnapshotFacts } from '../src/ingest/session-ingestor.mjs';
import { confirmDeleteNote, isFactTombstoned, calculateItemKey } from '../src/tombstone/tracker.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

test('B03: R5 增量前缀验证、版本隔离与跨快照墓碑保持', async (t) => {
  const baseDir = path.resolve('.tmp/test-b03-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const sourcesDir = path.join(baseDir, 'sources');

  fs.mkdirSync(sourcesDir, { recursive: true });
  initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
  const db = openDatabase(dbPath);

  t.after(() => {
    try {
      db.close();
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  await t.test('1. state.sqlite 缺失时立即阻断导入，严禁自动初始化为空库 (§2)', () => {
    const missingDb = path.join(baseDir, 'nonexistent', 'state.sqlite');
    assert.throws(() => openExistingDatabase(missingDb), /严禁自动初始化为空库/);

    // 通过真实 CLI 验证缺失 state.sqlite 时 mem ingest 立即阻断且不建库
    const missingData = path.join(baseDir, 'missing-data');
    fs.mkdirSync(missingData, { recursive: true });
    const dummySrc = path.join(sourcesDir, 'dummy.jsonl');
    fs.writeFileSync(dummySrc, '{"type":"user","content":"hi"}\n', 'utf8');

    let exitCode = 0;
    try {
      execFileSync(
        process.execPath,
        [CLI_PATH, 'ingest', '--session', 's-missing', '--source-file', dummySrc],
        {
          env: { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: missingData },
          stdio: ['pipe', 'pipe', 'pipe']
        }
      );
    } catch (e) {
      exitCode = e.status || 1;
    }
    assert.notEqual(exitCode, 0);
    assert.equal(fs.existsSync(path.join(missingData, 'runtime', 'state.sqlite')), false, '严禁静默初始化为空库');
  });

  const event1 = { type: 'user', content: 'Docker 端口绑定失败如何排查？' };
  const event2 = { type: 'tool_use', command: 'netstat -ano | findstr :8080' };
  const event3 = { type: 'assistant', content: '确认端口被 PID 4321 占用，需调整端口映射。' };
  const event4 = { type: 'user', content: '追加：Nginx 502 超时怎么设置？' };
  const event5 = { type: 'assistant', content: '追加：设置 proxy_read_timeout 120s。' };

  const snap1File = path.join(sourcesDir, 'sess-r5-v1.jsonl');
  fs.writeFileSync(snap1File, [event1, event2, event3].map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');

  let snap1Id;

  await t.test('2. 首次导入与同快照重跑严格幂等', () => {
    const res1 = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: snap1File,
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      project: 'Ops',
      title: 'R5 增量会话测试',
      sensitivity: 'synthetic'
    });

    assert.equal(res1.status, 'ingested');
    assert.deepEqual(res1.incrementalRange, { start: 1, end: 3 });
    assert.ok(fs.existsSync(res1.readableSessionPath));
    snap1Id = res1.snapshotId;

    // 幂等重跑同快照
    const resRetry = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: snap1File,
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      project: 'Ops',
      title: 'R5 增量会话测试',
      sensitivity: 'synthetic'
    });
    assert.equal(resRetry.status, 'idempotent_skip');
    assert.equal(resRetry.snapshotId, snap1Id);
  });

  await t.test('3. 增量前缀 100% 匹配才切片 K+1..N；中间修改、截断或分叉一律标 needs_reaudit', () => {
    // 3a. 合法追加事件 4..5 (前缀 1..3 完全一致)
    const snap2File = path.join(sourcesDir, 'sess-r5-v2-appended.jsonl');
    fs.writeFileSync(snap2File, [event1, event2, event3, event4, event5].map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');

    const resAppend = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: snap2File,
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      project: 'Ops',
      title: 'R5 增量会话测试 v2',
      sensitivity: 'synthetic'
    });
    assert.equal(resAppend.status, 'ingested');
    assert.equal(resAppend.previousSnapshotId, snap1Id);
    assert.deepEqual(resAppend.incrementalRange, { start: 4, end: 5 }, '仅允许对 K+1..N 做增量提炼');

    // 验证 snapshot_lineage 记录完整
    const lineage = db.prepare('SELECT * FROM snapshot_lineage WHERE snapshot_id = ?').get(resAppend.snapshotId);
    assert.equal(lineage.previous_snapshot_id, snap1Id);

    // 3b. 中间事件 2 被改写（即使总事件数增加到 6，也禁止猜测增量！）
    const modifiedEvent2 = { type: 'tool_use', command: 'ss -tulpn | grep 9090' };
    const snapForkFile = path.join(sourcesDir, 'sess-r5-fork.jsonl');
    fs.writeFileSync(
      snapForkFile,
      [event1, modifiedEvent2, event3, event4, event5, { type: 'user', content: '额外事件' }].map(e => JSON.stringify(e)).join('\n') + '\n',
      'utf8'
    );

    const resFork = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: snapForkFile,
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      project: 'Ops',
      sensitivity: 'synthetic'
    });
    assert.equal(resFork.status, 'needs_reaudit');
    assert.equal(resFork.reason, 'prefix_hash_mismatch');
    assert.equal(resFork.mismatchEventId, 2);
    assert.equal(resFork.incrementalRange, null);

    // needs_reaudit 快照在未显式重审前禁止提炼
    const blockedDistill = distillSnapshotFacts({
      db,
      snapshotId: resFork.snapshotId,
      facts: [{ eventId: 6, factType: 'playbook', normalizedSubject: 'extra', title: 'X', summary: 'Y' }]
    });
    assert.equal(blockedDistill.status, 'blocked_needs_reaudit');

    // 3c. 快照截断（总事件数减少到 2 < 5）同样标为 needs_reaudit
    const snapTruncFile = path.join(sourcesDir, 'sess-r5-trunc.jsonl');
    fs.writeFileSync(snapTruncFile, [event1, event2].map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');

    const resTrunc = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: snapTruncFile,
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      project: 'Ops',
      sensitivity: 'synthetic'
    });
    assert.equal(resTrunc.status, 'needs_reaudit');
    assert.equal(resTrunc.reason, 'snapshot_truncated');
  });

  await t.test('4. 版本隔离 (parser/distiller 升级) 与跨快照稳定 item_key 墓碑持续抑制', () => {
    // 4a. 发布事件 3 对应的知识笔记并确认删除，写入跨快照墓碑
    const fact3Subject = 'docker port pid conflict';
    const noteUuid = 'KN-019316a8-7c40-7000-8000-b03000000003';
    const notePath = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-000003_Docker端口冲突.md');
    const noteContent = `---
schema_version: 1
id: "${noteUuid}"
note_type: "playbook"
title: "Docker端口冲突"
project: "Ops"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "windows"
source_tool: "codex"
session_id: "sess-r5-001"
canonical_event_anchor: "^event-000003"
fact_type: "playbook"
normalized_subject: "${fact3Subject}"
created_at: "2026-11-10T12:00:00+08:00"
---
正文内容
`;
    const staged = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: noteUuid, content: noteContent });
    publishFile({
      db,
      operationId: 'op-b03-note',
      outputUuid: noteUuid,
      stagingPath: staged.stagingPath,
      vaultTargetPath: notePath,
      contentSha256: staged.contentSha256,
      metadata: {
        note_type: 'playbook',
        title: 'Docker端口冲突',
        project: 'Ops',
        privacy: 'sanitized'
      }
    });

    const delRes = confirmDeleteNote({ db, noteId: noteUuid, notePath });
    const expectedKey = calculateItemKey({
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      canonicalEventAnchor: '^event-000003',
      factType: 'playbook',
      normalizedSubject: fact3Subject
    });
    assert.equal(delRes.itemKey, expectedKey);
    assert.equal(isFactTombstoned({ db, itemKey: expectedKey }), true);

    // 4b. parser_version 升级仅重建派生可读会话，不改动现有知识笔记与墓碑
    const rebuildRes = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: snap1File,
      sourceTool: 'codex',
      sessionId: 'sess-r5-001',
      project: 'Ops',
      title: 'R5 增量会话测试',
      parserVersion: 'v2.5.0',
      sensitivity: 'synthetic'
    });
    assert.equal(rebuildRes.status, 'rebuilt_derived_session');
    assert.equal(rebuildRes.derivedOnly, true);
    assert.equal(isFactTombstoned({ db, itemKey: expectedKey }), true);

    // 4c. 针对追加快照 snap2 执行增量/显式重审提炼：已删除事实 #3 持续受墓碑抑制绝不复活，事实 #5 正常产出
    const snap2Row = db.prepare("SELECT snapshot_id FROM session_snapshots WHERE session_id = 'sess-r5-001' AND event_count = 5").get();
    const reauditRes = distillSnapshotFacts({
      db,
      snapshotId: snap2Row.snapshot_id,
      explicitReaudit: true,
      facts: [
        { eventId: 3, factType: 'playbook', normalizedSubject: fact3Subject, title: 'Docker端口冲突', summary: '已删事实' },
        { eventId: 5, factType: 'decision', normalizedSubject: 'nginx proxy_read_timeout 120s', title: 'Nginx超时配置', summary: '设置 proxy_read_timeout 120s' }
      ]
    });
    assert.equal(reauditRes.status, 'completed');
    assert.equal(reauditRes.suppressedFacts.length, 1);
    assert.equal(reauditRes.suppressedFacts[0].eventId, 3);
    assert.equal(reauditRes.acceptedFacts.length, 1);
    assert.equal(reauditRes.acceptedFacts[0].eventId, 5);

    // 4d. distiller_version 升级而不发起显式重审时，必须阻断静默覆写
    const versionUpgradeCheck = distillSnapshotFacts({
      db,
      snapshotId: snap2Row.snapshot_id,
      distillerVersion: 'v2.9.0',
      explicitReaudit: false,
      facts: []
    });
    assert.equal(versionUpgradeCheck.status, 'reaudit_required_version_upgrade');
  });
});
