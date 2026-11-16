import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { openDatabase, openExistingDatabase, checkpointDatabaseBestEffort } from '../src/db/sqlite.mjs';
import { initRepository, ensureMissingTemplates, previewBaseViewChanges, BASES_VIEWS } from '../src/init.mjs';
import { evaluateBaseFilter } from '../src/schema/validator.mjs';
import { PLAN_B01_SIX_SURFACES, runMultiHostIsolationMatrix } from '../src/security/isolation-sentinel.mjs';
import { scanAndSyncNotes, registerManualNote, confirmDeleteNote } from '../src/tombstone/tracker.mjs';
import { buildLocalSearchIndex, searchKnowledge } from '../src/search/query-engine.mjs';
import {
  createProposal,
  reconcileProposal,
  checkProposalReconcileState,
  evaluateProposalConditions
} from '../src/reconcile/engine.mjs';
import {
  acquireWriteLock,
  releaseWriteLock,
  recoverStaleWriteLock,
  inspectWriteLockFile
} from '../src/storage/write-lock.mjs';
import { stageCandidate, publishFile, assertPublisherUnlocked } from '../src/storage/atomic-publisher.mjs';
import { initGitRepo, commitPublishedFile, settlePublishedGitCommit } from '../src/git/repo-manager.mjs';
import { createConsistentBackup, restoreFromBackup } from '../src/backup/backup-manager.mjs';
import { listDiscoverableSessions } from '../src/ingest/session-ingestor.mjs';
import { readZstdPrefixLinesFromFile } from '../src/ingest/zstd-utils.mjs';
import { inspectCodexSessionMetadata, discoverCodexSessions } from '../src/ingest/adapters/codex-adapter.mjs';
import { discoverAntigravitySessions } from '../src/ingest/adapters/antigravity-adapter.mjs';
import { inspectDshSessionMetadata } from '../src/ingest/adapters/dsh-adapter.mjs';
import { issueTrustedLowSensitivityApproval } from '../src/security/trusted-approvals.mjs';
import { runBenchmarkSuite } from '../src/benchmark/runner.mjs';
import { runDeploy, REPO_ROOT } from '../cli/deploy.mjs';
import { collectAcceptanceReadiness } from '../src/verify/client-acceptance.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

function makeTempEnv(prefix = 'v25-audit-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const vaultPath = path.join(root, 'AgentMemory');
  const dataPath = path.join(root, 'AgentMemory-Data');
  initRepository({ vaultPath, dataPath });
  const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');
  const env = {
    ...process.env,
    AGENT_MEMORY_VAULT: vaultPath,
    AGENT_MEMORY_DATA: dataPath
  };
  return { root, vaultPath, dataPath, dbPath, env };
}

function makeNoteMarkdown({
  id,
  title = '审计回归笔记',
  project = 'AuditOps',
  privacy = 'sanitized',
  lifecycle = 'active',
  evidenceLevel = 'observed',
  reviewState = 'accepted',
  asOf = '2026-11-12',
  reviewAfter = '2027-06-01',
  envName = 'windows',
  body = '标准正文内容'
}) {
  return [
    '---',
    'schema_version: 1',
    `id: "${id}"`,
    'note_type: "playbook"',
    `title: "${title}"`,
    `project: "${project}"`,
    `privacy: "${privacy}"`,
    `lifecycle: "${lifecycle}"`,
    `evidence_level: "${evidenceLevel}"`,
    `review_state: "${reviewState}"`,
    `as_of: "${asOf}"`,
    `review_after: "${reviewAfter}"`,
    `env: "${envName}"`,
    'created_at: "2026-11-12T08:00:00+08:00"',
    '---',
    body,
    ''
  ].join('\n');
}

function publishAuditNote({ db, vaultPath, dataPath, id, relTarget, content, opId = `op-${id}` }) {
  const stg = stageCandidate({
    stagingDir: path.join(dataPath, 'staging'),
    outputUuid: id,
    content,
    validateSchema: true
  });
  const targetPath = path.join(vaultPath, relTarget);
  const pub = publishFile({
    db,
    operationId: opId,
    outputUuid: id,
    stagingPath: stg.stagingPath,
    vaultTargetPath: targetPath,
    contentSha256: stg.contentSha256,
    revisionsDir: path.join(dataPath, 'runtime', 'revisions')
  });
  return { targetPath, sha256: stg.contentSha256, pub };
}

function buildSkippableZstdFrame(payloadText) {
  const payload = Buffer.from(payloadText, 'utf8');
  const header = Buffer.alloc(8);
  header.writeUInt32LE(0x184d2a50, 0);
  header.writeUInt32LE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

test('V2.5 Audit Fixes Regression Suite (B1-B6, C1-C3, D1-D7, WAL, DSH Synthetic)', async t => {
  await t.test('1. [B1] initRepository 拒绝重复及半初始化目录覆盖，保留配置/视图/模板，ensureMissingTemplates 仅补缺失', () => {
    const { root, vaultPath, dataPath } = makeTempEnv('v25-b1-');
    try {
      // 模拟实库个性化配置与自定义模板/视图
      const pluginsPath = path.join(vaultPath, '.obsidian', 'community-plugins.json');
      const customPlugins = JSON.stringify(['obsidian-git', 'dataview', 'templater-obsidian'], null, 2);
      fs.writeFileSync(pluginsPath, customPlugins, 'utf8');

      const gitignorePath = path.join(vaultPath, '.gitignore');
      fs.writeFileSync(gitignorePath, '.obsidian/workspace.json\ncustom-ignore.log\n', 'utf8');

      const tplPlaybook = path.join(vaultPath, '90_Templates', 'Template_Playbook.md');
      fs.writeFileSync(tplPlaybook, '# CUSTOM TEMPLATE KEEP\n', 'utf8');
      const tplSession = path.join(vaultPath, '90_Templates', 'Template_Session.md');
      fs.unlinkSync(tplSession);

      // 第二次初始化必须阻断且不改任何现有文件
      assert.throws(() => initRepository({ vaultPath, dataPath }), /INIT_ALREADY_INITIALIZED/);
      assert.equal(fs.readFileSync(pluginsPath, 'utf8'), customPlugins);
      assert.ok(fs.readFileSync(gitignorePath, 'utf8').includes('custom-ignore.log'));
      assert.equal(fs.readFileSync(tplPlaybook, 'utf8'), '# CUSTOM TEMPLATE KEEP\n');

      // CLI mem init 对半初始化（删除 sqlite 但目录仍有文件）也必须拒绝且不生成 sqlite
      fs.unlinkSync(path.join(dataPath, 'runtime', 'state.sqlite'));
      let partialExit = 0;
      let partialErr = '';
      try {
        execFileSync(process.execPath, [CLI_PATH, 'init'], {
          env: { ...process.env, AGENT_MEMORY_VAULT: vaultPath, AGENT_MEMORY_DATA: dataPath },
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (e) {
        partialExit = e.status || 1;
        partialErr = (e.stderr || '') + (e.stdout || '');
      }
      assert.notEqual(partialExit, 0);
      assert.ok(partialErr.includes('INIT_ALREADY_INITIALIZED') || partialErr.includes('CRITICAL_STATE_DB_MISSING'));
      assert.equal(fs.existsSync(path.join(dataPath, 'runtime', 'state.sqlite')), false);

      // ensureMissingTemplates 只补缺失项，绝不覆写用户已改模板
      const repair = ensureMissingTemplates({ vaultPath });
      assert.ok(repair.created.includes('Template_Session.md'));
      assert.equal(fs.readFileSync(tplPlaybook, 'utf8'), '# CUSTOM TEMPLATE KEEP\n');

      // previewBaseViewChanges 仅只读预览，不直接覆盖现有视图
      const basePath = path.join(vaultPath, '50_Bases_Views', '知识总览.base');
      fs.writeFileSync(basePath, 'views:\n  - type: table\n    name: Custom\n', 'utf8');
      const preview = previewBaseViewChanges({ vaultPath });
      assert.ok(preview.views.some(p => p.filename === '知识总览.base' && p.status === 'modified_requires_manual_confirm'));
      assert.ok(fs.readFileSync(basePath, 'utf8').includes('name: Custom'));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('2. [B2] scanAndSyncNotes 同步手改字段与指纹、检出重复 ID 与 Schema 错误；手建笔记未受控登记不得升格 Channel 1', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-b2-');
    const db = openDatabase(dbPath);
    try {
      const id1 = 'KN-019316a8-7c40-7000-8000-b20000000001';
      const { targetPath } = publishAuditNote({
        db,
        vaultPath,
        dataPath,
        id: id1,
        relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-b2-orig.md'),
        content: makeNoteMarkdown({ id: id1, title: '旧标题 B2', body: '旧正文 B2' })
      });

      // 手改标题、project、review_state 与正文
      const editedRaw = makeNoteMarkdown({
        id: id1,
        title: '手工更新后标题 B2',
        project: 'AuditOpsV2',
        reviewState: 'accepted',
        body: '更新后正文 B2'
      });
      fs.writeFileSync(targetPath, editedRaw, 'utf8');

      // 手建未知合规笔记（未调用 registerManualNote）与一份重复 ID 冲突笔记、一份 Schema 错误笔记
      const manualId = 'KN-019316a8-7c40-7000-8000-b20000000002';
      const manualPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-manual-untracked.md');
      fs.writeFileSync(
        manualPath,
        makeNoteMarkdown({ id: manualId, title: '手建未登记关键词 ManualUntrackedToken', project: 'AuditOps' }),
        'utf8'
      );

      const badSchemaPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-bad-schema.md');
      fs.writeFileSync(badSchemaPath, '---\nid: "KN-BAD"\nnote_type: "invalid_type"\n---\n坏 Schema\n', 'utf8');

      const sync1 = scanAndSyncNotes({ db, vaultDir: vaultPath });
      assert.ok(sync1.metadataUpdated.some(u => u.id === id1 && u.changedFields.includes('title') && u.changedFields.includes('content_sha256')));
      assert.ok(sync1.untracked.some(u => u.id === manualId && u.status === 'pending_enrollment'));
      assert.ok(sync1.schemaErrors.some(s => s.path === badSchemaPath));
      assert.equal(db.prepare('SELECT title, project, content_sha256 FROM notes WHERE id = ?').get(id1).title, '手工更新后标题 B2');
      assert.equal(db.prepare('SELECT id FROM notes WHERE id = ?').get(manualId), undefined, '未知手建笔记绝不可自动写入 notes 台账');

      // 搜索未知手建笔记：可发现但严禁提升为 Channel 1 (actionable: true)
      const searchUntracked = searchKnowledge({ db, vaultDir: vaultPath, query: 'ManualUntrackedToken', project: 'AuditOps' });
      assert.equal(searchUntracked.items.length, 1);
      assert.equal(searchUntracked.items[0].actionable, false);
      assert.equal(searchUntracked.items[0].reason, 'unregistered_note_pending_enrollment');

      // 重复 ID 冲突检测：新增同 UUID 文件后，scanAndSyncNotes 必须报错冲突且不覆写 path
      const dupPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-b2-dup.md');
      fs.writeFileSync(dupPath, editedRaw, 'utf8');
      const syncDup = scanAndSyncNotes({ db, vaultDir: vaultPath });
      assert.ok(syncDup.conflicts.some(c => c.id === id1 && c.paths.length === 2));
      assert.equal(db.prepare('SELECT path FROM notes WHERE id = ?').get(id1).path, targetPath);
      fs.unlinkSync(dupPath);

      // 含残余凭据的 sanitized 手建笔记禁止通过受控登记；去除凭据后受控登记并升格为 Channel 1
      const dynTok = ['ghp', 'AuditFixValidSecretToken1234567890'].join('_');
      const dirtyManualPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-manual-dirty.md');
      fs.writeFileSync(
        dirtyManualPath,
        makeNoteMarkdown({ id: 'KN-019316a8-7c40-7000-8000-b20000000003', title: '带凭据笔记', body: `tok=${dynTok}` }),
        'utf8'
      );
      assert.throws(() => registerManualNote({ db, vaultDir: vaultPath, filePath: dirtyManualPath }), /ERR_MANUAL_NOTE_RESIDUAL_SECRETS/);
      fs.unlinkSync(dirtyManualPath);

      const enrolled = registerManualNote({ db, vaultDir: vaultPath, filePath: manualPath });
      assert.equal(enrolled.enrolled, true);
      const searchEnrolled = searchKnowledge({ db, vaultDir: vaultPath, query: 'ManualUntrackedToken', project: 'AuditOps' });
      assert.equal(searchEnrolled.items.length, 1);
      assert.equal(searchEnrolled.items[0].actionable, true);
    } finally {
      db.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('3. [B3] Mode 1/2 按 doc_sha256 校验索引词元：删词/增词/改名/删除/隐私降级/损坏索引均即时准确且不写索引', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-b3-');
    const db = openDatabase(dbPath);
    try {
      const id = 'KN-019316a8-7c40-7000-8000-b30000000001';
      const { targetPath } = publishAuditNote({
        db,
        vaultPath,
        dataPath,
        id,
        relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-b3-index.md'),
        content: makeNoteMarkdown({ id, title: '索引漂移探测', project: 'IdxOps', body: '旧关键词 AlphaStaleToken 解决方案' })
      });
      const indexDir = path.join(dataPath, 'runtime', 'index');
      const idxRes = buildLocalSearchIndex({ vaultDir: vaultPath, indexDir });
      assert.equal(idxRes.indexedCount, 1);
      const idxBeforeBuf = fs.readFileSync(idxRes.indexPath);

      // 删掉 AlphaStaleToken、新增 BetaFreshToken（不重建索引）
      fs.writeFileSync(
        targetPath,
        makeNoteMarkdown({ id, title: '索引漂移探测', project: 'IdxOps', body: '新关键词 BetaFreshToken 解决方案' }),
        'utf8'
      );

      for (const mode of ['hybrid', 'rerank']) {
        const staleHit = searchKnowledge({ db, vaultDir: vaultPath, query: 'AlphaStaleToken', project: 'IdxOps', mode, indexDir });
        assert.equal(staleHit.items.length, 0, `${mode} 绝不可命中已被删除的旧词`);
        const freshHit = searchKnowledge({ db, vaultDir: vaultPath, query: 'BetaFreshToken', project: 'IdxOps', mode, indexDir });
        assert.equal(freshHit.items.length, 1, `${mode} 必须即时命中新文本分词结果`);
      }
      assert.equal(Buffer.compare(fs.readFileSync(idxRes.indexPath), idxBeforeBuf), 0, '查询不得写入或改写 lexical-index.json');

      // 改名后仍可即时命中
      const renamedPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-b3-renamed.md');
      fs.renameSync(targetPath, renamedPath);
      scanAndSyncNotes({ db, vaultDir: vaultPath });
      assert.equal(searchKnowledge({ db, vaultDir: vaultPath, query: 'BetaFreshToken', project: 'IdxOps', mode: 'hybrid', indexDir }).items.length, 1);

      // 损坏索引 JSON 时优雅回退内存分词
      fs.writeFileSync(idxRes.indexPath, '{BROKEN_JSON_INDEX', 'utf8');
      assert.equal(searchKnowledge({ db, vaultDir: vaultPath, query: 'BetaFreshToken', project: 'IdxOps', mode: 'hybrid', indexDir }).items.length, 1);

      // 隐私降级（磁盘 local_only）立即剥离召回
      fs.writeFileSync(
        renamedPath,
        makeNoteMarkdown({ id, title: '索引漂移探测', project: 'IdxOps', privacy: 'local_only', body: '新关键词 BetaFreshToken 解决方案' }),
        'utf8'
      );
      assert.equal(searchKnowledge({ db, vaultDir: vaultPath, query: 'BetaFreshToken', project: 'IdxOps', mode: 'hybrid', indexDir }).items.length, 0);

      // 恢复 sanitized 后执行 confirmDeleteNote 墓碑删除 -> 绝不可由旧索引复活命中
      fs.writeFileSync(
        renamedPath,
        makeNoteMarkdown({ id, title: '索引漂移探测', project: 'IdxOps', privacy: 'sanitized', body: '新关键词 BetaFreshToken 解决方案' }),
        'utf8'
      );
      buildLocalSearchIndex({ vaultDir: vaultPath, indexDir });
      confirmDeleteNote({ db, noteId: id, revisionsDir: path.join(dataPath, 'runtime', 'revisions') });
      assert.equal(searchKnowledge({ db, vaultDir: vaultPath, query: 'BetaFreshToken', project: 'IdxOps', mode: 'hybrid', indexDir }).items.length, 0);
    } finally {
      db.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('4. [B4 + WAL可见性] search/proposal show/status 严格只读零写库，且立即算得 version_changed；WAL 未 checkpoint 对只读连接可见', () => {
    const { root, vaultPath, dataPath, dbPath, env } = makeTempEnv('v25-b4-');
    const id = 'KN-019316a8-7c40-7000-8000-b40000000001';
    const propId = 'PROP-019316a8-7c40-7000-8000-b40000000002';

    const db = openDatabase(dbPath);
    let targetPath;
    let propPath;
    try {
      const pub = publishAuditNote({
        db,
        vaultPath,
        dataPath,
        id,
        relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-b4-target.md'),
        content: makeNoteMarkdown({ id, title: 'B4 只读检验 B4ProbeKey', project: 'RoOps', body: '正确步骤 NewStepB4' })
      });
      targetPath = pub.targetPath;

      const prop = createProposal({
        queueDir: path.join(vaultPath, '40_Review_Queue'),
        proposalUuid: propId,
        title: 'B4 提案',
        project: 'RoOps',
        targetId: id,
        targetNoteRef: `[[${path.basename(targetPath, '.md')}]]`,
        proposalKind: 'conflict',
        preConditions: ['OldStepB4'],
        postConditions: ['NewStepB4']
      });
      propPath = prop.proposalPath;
      fs.writeFileSync(propPath, fs.readFileSync(propPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
      const rec = reconcileProposal({ db, proposalPath: propPath, targetPath });
      assert.equal(rec.reconcile_state, 'verified_applied');

      // WAL 未 checkpoint 时由并发只读连接验证可见性
      const uncommittedTitle = 'WAL并发可见标题';
      db.prepare('INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run('KN-WAL-PROBE', 'playbook', uncommittedTitle, 'RoOps', 'sanitized', targetPath, 'sha', 'active', '2026-11-12T00:00:00Z');
      const roConn = openExistingDatabase(dbPath, { readOnly: true });
      try {
        const seen = roConn.prepare('SELECT title FROM notes WHERE id = ?').get('KN-WAL-PROBE');
        assert.equal(seen?.title, uncommittedTitle, 'WAL 模式中已提交未 checkpoint 的事务必须对只读连接即时可见');
      } finally {
        roConn.close();
      }
      db.prepare("DELETE FROM notes WHERE id = 'KN-WAL-PROBE'").run();
      checkpointDatabaseBestEffort(db);
    } finally {
      db.close();
    }

    try {
      // 修改目标笔记正文，不运行 reconcile
      fs.writeFileSync(targetPath, makeNoteMarkdown({ id, title: 'B4 只读检验 B4ProbeKey', project: 'RoOps', body: '已手工修改 NewStepB4 与新补充' }), 'utf8');

      // 在无 write.lock 且记录 DB 文件哈希的情况下依次运行 search / proposal show / status
      const dbSnapBefore = fs.readFileSync(dbPath);
      const dbMtimeBefore = fs.statSync(dbPath).mtimeMs;

      const sJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'search', 'B4ProbeKey', '--project', 'RoOps', '--json'], { env, encoding: 'utf8' }));
      assert.equal(sJson.items.length, 1);
      assert.equal(sJson.items[0].actionable, false);
      assert.ok(sJson.items[0].reason.includes('version_changed'));

      const pJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', propId], { env, encoding: 'utf8' }));
      assert.equal(pJson.reconcile_state, 'unverified');
      assert.equal(pJson.reconcile_reason, 'version_changed');

      const stJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'status', '--json'], { env, encoding: 'utf8' }));
      assert.equal(stJson.proposals.versionChanged, 1);
      assert.equal(stJson.proposals.effective.versionChanged, 1);

      assert.equal(Buffer.compare(fs.readFileSync(dbPath), dbSnapBefore), 0, '只读命令绝不得改动 state.sqlite 字节内容');
      assert.equal(fs.statSync(dbPath).mtimeMs, dbMtimeBefore, '只读命令绝不得修改 state.sqlite mtime');

      // 确认 reconcile_states 存储行仍保留执行前状态，直到 mem reconcile 持久化
      const roVerify = openExistingDatabase(dbPath, { readOnly: true });
      try {
        assert.equal(roVerify.prepare('SELECT reconcile_state FROM reconcile_states WHERE proposal_id = ?').get(propId).reconcile_state, 'verified_applied');
      } finally {
        roVerify.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('5. [B5] Git 已提交但台账未落盘时 recover-lock 补账 committed 而非误标 failed；工作区遭手改则标 needs_review', () => {
    // 5a. Git HEAD 已精确提交 expectedSha256 但 auxiliary_states 尚空（写结算前崩溃）+ 死 write.lock
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-b5-');
    try {
      initGitRepo(vaultPath);
      const id = 'KN-019316a8-7c40-7000-8000-b50000000001';
      const content = makeNoteMarkdown({ id, title: 'B5 已提交补账测试', project: 'B5Ops', body: '已落盘内容' });
      const opId = 'op-b5-crash-01';
      const db = openDatabase(dbPath);
      let targetPath;
      let expectedSha;
      try {
        const pub = publishAuditNote({
          db,
          vaultPath,
          dataPath,
          id,
          relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-b5.md'),
          content,
          opId
        });
        targetPath = pub.targetPath;
        expectedSha = pub.sha256;
      } finally {
        db.close();
      }

      // 模拟 Git 提交已成功但 auxiliary_states 尚未写入就崩溃
      const gitCommit = settlePublishedGitCommit({ vaultDir: vaultPath, filePath: targetPath, expectedSha256: expectedSha, commitMessage: 'b5 precommit' });
      assert.equal(gitCommit.gitState, 'committed');
      const headBefore = execFileSync('git', ['rev-list', '--count', 'HEAD'], { cwd: vaultPath, encoding: 'utf8' }).trim();
      fs.writeFileSync(path.join(dataPath, 'runtime', 'write.lock'), JSON.stringify({ token: 't', pid: 999999, command: 'publish' }), 'utf8');

      const rec = recoverStaleWriteLock({ vaultPath, dataPath });
      assert.equal(rec.recovered, true);
      assert.equal(rec.retriedGitCommits.length, 1);
      assert.equal(rec.retriedGitCommits[0].gitState, 'committed');
      assert.equal(execFileSync('git', ['rev-list', '--count', 'HEAD'], { cwd: vaultPath, encoding: 'utf8' }).trim(), headBefore, 'HEAD 已含同内容提交时不重复提交');

      const dbCheck = openExistingDatabase(dbPath, { readOnly: true });
      try {
        const auxRow = dbCheck.prepare('SELECT git_state, index_state FROM auxiliary_states WHERE operation_id = ?').get(opId);
        assert.equal(auxRow.git_state, 'committed');
      } finally {
        dbCheck.close();
      }

      // 5b. 若工作区文件被人工改动偏离 expectedSha256 且尚未提交，绝不盲目提交，标 needs_review
      const editedPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-b5-human.md');
      fs.writeFileSync(editedPath, makeNoteMarkdown({ id: 'KN-B5-H', title: '手改冲突', body: '人工改动后的正文' }), 'utf8');
      const expectedOtherSha = crypto.createHash('sha256').update('expected original text', 'utf8').digest('hex');
      const needsRev = settlePublishedGitCommit({ vaultDir: vaultPath, filePath: editedPath, expectedSha256: expectedOtherSha, commitMessage: 'should not commit' });
      assert.equal(needsRev.gitState, 'needs_review');
      assert.equal(execFileSync('git', ['status', '--porcelain', '--', '30_Knowledge_Notes/Playbooks/KN-b5-human.md'], { cwd: vaultPath, encoding: 'utf8' }).startsWith('??'), true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('6. [B6] benchmark 默认/isolated 绝不写入生产 Data，指定库评测强校验四参数与禁用生产索引写入；ingest 禁止省略 sensitivity', () => {
    const { root, vaultPath, dataPath, dbPath, env } = makeTempEnv('v25-b6-');
    try {
      const bmDefault = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'benchmark', '--suite', 'pilot', '--json'], { env, encoding: 'utf8' }));
      assert.ok(bmDefault.reportPath.startsWith(os.tmpdir()));
      assert.equal(fs.readdirSync(path.join(dataPath, 'runtime', 'benchmarks')).length, 0, '默认评测不得写默认 Data runtime/benchmarks');
      assert.equal(fs.existsSync(path.join(dataPath, 'runtime', 'index', 'lexical-index.json')), false, '默认评测不得写默认 Data runtime/index');

      const bmIso = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'benchmark', '--suite', 'pilot', '--isolated', '--json'], { env, encoding: 'utf8' }));
      assert.ok(bmIso.reportPath.startsWith(os.tmpdir()));
      assert.equal(fs.readdirSync(path.join(dataPath, 'runtime', 'benchmarks')).length, 0);

      // 目标库评测缺少 --questions / --out 时必须拒绝
      let missingArgExit = 0;
      let missingArgErr = '';
      try {
        execFileSync(process.execPath, [CLI_PATH, 'benchmark', '--vault', vaultPath, '--data', dataPath], { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        missingArgExit = e.status || 1;
        missingArgErr = (e.stderr || '') + (e.stdout || '');
      }
      assert.notEqual(missingArgExit, 0);
      assert.ok(missingArgErr.includes('BENCHMARK_TARGET_REQUIRES_EXPLICIT_ISOLATED_ARGS'));

      // 合法独立输出目录与真题集运行目标库评测，不创建或改写生产 runtime/index
      const qPath = path.join(root, 'questions.json');
      fs.writeFileSync(qPath, JSON.stringify([{ id: 'Q1', query: '首页', expectedIds: [] }]), 'utf8');
      const outDir = path.join(root, 'isolated-bm-out');
      const bmTarget = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'benchmark', '--vault', vaultPath, '--data', dataPath, '--questions', qPath, '--out', outDir, '--json'], { env, encoding: 'utf8' }));
      assert.ok(bmTarget.reportPath.startsWith(outDir));
      assert.equal(fs.existsSync(path.join(dataPath, 'runtime', 'index', 'lexical-index.json')), false, '目标库评测禁止写入生产索引');

      // ingest 未传 --dry-run 时省略 --sensitivity 必须拒绝
      let noSensExit = 0;
      let noSensErr = '';
      const rawCodex = path.join(root, 'codex-b6.jsonl');
      fs.writeFileSync(rawCodex, JSON.stringify({ type: 'user', content: 'b6 sensitivity required' }) + '\n', 'utf8');
      try {
        execFileSync(process.execPath, [CLI_PATH, 'ingest', '--source', 'codex', '--session', 'b6-sess', '--source-file', rawCodex], { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        noSensExit = e.status || 1;
        noSensErr = (e.stderr || '') + (e.stdout || '');
      }
      assert.notEqual(noSensExit, 0);
      assert.ok(noSensErr.includes('INGEST_SENSITIVITY_REQUIRED'));

      // 成长题集门禁验证：40 道重复或缺失留出题/缺三来源的语料绝不标为 growthSuiteReady，且真实库显式记录当日评测日期
      const dupQuestions = Array.from({ length: 40 }, () => ({ query: '端口绑定', project: 'AuditOps', expectedIds: [] }));
      const dupQPath = path.join(root, 'dup-growth-q.json');
      const dupOutPath = path.join(root, 'dup-growth-out.json');
      fs.writeFileSync(dupQPath, JSON.stringify(dupQuestions), 'utf8');
      const dupReport = runBenchmarkSuite({
        suite: 'growth',
        vaultDir: vaultPath,
        dataDir: dataPath,
        questionsPath: dupQPath,
        outputPath: dupOutPath,
        allowIndexWrite: false
      });
      assert.equal(dupReport.growthSuiteReady, false);
      assert.equal(dupReport.growthSwitchGatePassed, false);
      assert.equal(dupReport.uniqueQuestionCount, 1);
      assert.equal(dupReport.holdoutCount, 0);
      assert.notEqual(dupReport.evalTodayStr, '2026-11-10');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('7. [C1] 不存在版本 rev-9999 严格报错且不解除墓碑，预览与 --confirm 实际恢复彻底分离', () => {
    const { root, vaultPath, dataPath, dbPath, env } = makeTempEnv('v25-c1-');
    const id = 'KN-019316a8-7c40-7000-8000-c10000000001';
    let targetPath;
    const db = openDatabase(dbPath);
    try {
      const pub = publishAuditNote({
        db,
        vaultPath,
        dataPath,
        id,
        relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-c1.md'),
        content: makeNoteMarkdown({ id, title: 'C1 恢复版本检验', project: 'C1Ops', body: 'rev-0001 正文' })
      });
      targetPath = pub.targetPath;
    } finally {
      db.close();
    }

    try {
      execFileSync(process.execPath, [CLI_PATH, 'delete', id, '--confirm'], { env, encoding: 'utf8' });
      assert.equal(fs.existsSync(targetPath), false);

      // 请求 rev-9999 必须失败且不得回退到 latest.md 或解除墓碑
      let revErr = '';
      let revExit = 0;
      try {
        execFileSync(process.execPath, [CLI_PATH, 'restore', id, '--revision', 'rev-9999', '--confirm'], { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        revExit = e.status || 1;
        revErr = (e.stderr || '') + (e.stdout || '');
      }
      assert.notEqual(revExit, 0);
      assert.ok(revErr.includes('REVISION_NOT_FOUND'));
      assert.equal(fs.existsSync(targetPath), false);
      assert.equal(fs.existsSync(path.join(dataPath, 'staging', 'restore-preview', `${id}-rev-9999.md`)), false);

      // 仅预览 rev-0001 不解除墓碑也不写回 Vault
      const prevOut = execFileSync(process.execPath, [CLI_PATH, 'restore', id, '--revision', 'rev-0001'], { env, encoding: 'utf8' });
      assert.ok(prevOut.includes('[mem restore 预览]'));
      assert.equal(fs.existsSync(targetPath), false);

      // 追加 --confirm 才恢复文件与激活状态
      execFileSync(process.execPath, [CLI_PATH, 'restore', id, '--revision', 'rev-0001', '--confirm'], { env, encoding: 'utf8' });
      assert.equal(fs.existsSync(targetPath), true);
      const dbCheck = openExistingDatabase(dbPath, { readOnly: true });
      try {
        assert.equal(dbCheck.prepare('SELECT status FROM notes WHERE id = ?').get(id).status, 'active');
        assert.equal(dbCheck.prepare('SELECT count(*) as c FROM tombstones').get().c, 0);
      } finally {
        dbCheck.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('8. [C2 + C3] 整库恢复拒绝非空/重叠/越界目标且不碰原文件与WAL；默认备份排除 .claudian/ 与插件 data.json', () => {
    const { root, vaultPath, dataPath } = makeTempEnv('v25-c2c3-');
    try {
      // 写入测试用 .claudian 私有文件及多个插件配置与运行文件
      const claudianFile = path.join(vaultPath, '.claudian', 'sessions', 'private.json');
      fs.mkdirSync(path.dirname(claudianFile), { recursive: true });
      fs.writeFileSync(claudianFile, '{"local":true}', 'utf8');

      const plgGood = path.join(vaultPath, '.obsidian', 'plugins', 'good-plugin');
      const plgOther = path.join(vaultPath, '.obsidian', 'plugins', 'other-plugin');
      fs.mkdirSync(plgGood, { recursive: true });
      fs.mkdirSync(plgOther, { recursive: true });
      fs.writeFileSync(path.join(plgGood, 'manifest.json'), '{"id":"good"}', 'utf8');
      fs.writeFileSync(path.join(plgGood, 'main.js'), '// runtime', 'utf8');
      fs.writeFileSync(path.join(plgGood, 'data.json'), '{"safeOpt":1}', 'utf8');
      fs.writeFileSync(path.join(plgOther, 'manifest.json'), '{"id":"other"}', 'utf8');
      fs.writeFileSync(path.join(plgOther, 'data.json'), '{"privateOpt":true}', 'utf8');

      const bkpRoot = path.join(root, 'Backups');
      const defaultBkp = createConsistentBackup({ vaultPath, dataPath, targetDir: bkpRoot });
      assert.equal(defaultBkp.classification, 'local_private_backup_not_for_external_export');
      const defManifest = JSON.parse(fs.readFileSync(defaultBkp.manifestPath, 'utf8'));
      const relPaths = defManifest.files.map(f => f.rel_path);
      assert.equal(relPaths.some(p => p.startsWith('.claudian/')), false, '默认备份严禁包含 .claudian/');
      assert.equal(relPaths.some(p => p.endsWith('/data.json')), false, '默认备份严禁包含插件 data.json');
      assert.ok(relPaths.includes('.obsidian/plugins/good-plugin/manifest.json'));
      assert.ok(relPaths.includes('.obsidian/plugins/good-plugin/main.js'));

      // 显式批准单个插件 data.json 时只包含被批准插件
      const bkpApprovedRoot = path.join(root, 'BackupsApproved');
      const appBkp = createConsistentBackup({ vaultPath, dataPath, targetDir: bkpApprovedRoot, approvedPluginData: ['good-plugin'] });
      const appPaths = JSON.parse(fs.readFileSync(appBkp.manifestPath, 'utf8')).files.map(f => f.rel_path);
      assert.ok(appPaths.includes('.obsidian/plugins/good-plugin/data.json'));
      assert.equal(appPaths.includes('.obsidian/plugins/other-plugin/data.json'), false);

      // C2: 目标目录已有首页.md 与 state.sqlite-wal 时绝不可覆盖或删除它们
      const isoRoot = path.join(root, 'IsolatedRestore');
      const dirtyVault = path.join(isoRoot, 'Vault');
      const dirtyData = path.join(isoRoot, 'Data');
      fs.mkdirSync(dirtyVault, { recursive: true });
      fs.mkdirSync(path.join(dirtyData, 'runtime'), { recursive: true });
      fs.writeFileSync(path.join(dirtyVault, '首页.md'), '# EXISTING_HOME_MUST_SURVIVE', 'utf8');
      fs.writeFileSync(path.join(dirtyData, 'runtime', 'state.sqlite-wal'), 'EXISTING_WAL', 'utf8');

      assert.throws(() => restoreFromBackup({
        backupDir: defaultBkp.backupDir,
        newVaultPath: dirtyVault,
        newDataPath: path.join(isoRoot, 'FreshData'),
        isolatedRoot: isoRoot
      }), /RESTORE_TARGET_NOT_EMPTY/);
      assert.equal(fs.readFileSync(path.join(dirtyVault, '首页.md'), 'utf8'), '# EXISTING_HOME_MUST_SURVIVE');

      assert.throws(() => restoreFromBackup({
        backupDir: defaultBkp.backupDir,
        newVaultPath: path.join(isoRoot, 'FreshVault'),
        newDataPath: dirtyData,
        isolatedRoot: isoRoot
      }), /RESTORE_TARGET_NOT_EMPTY/);
      assert.equal(fs.readFileSync(path.join(dirtyData, 'runtime', 'state.sqlite-wal'), 'utf8'), 'EXISTING_WAL');

      // 越界 isolatedRoot、嵌套目标与备份源重叠均被拒绝
      assert.throws(() => restoreFromBackup({
        backupDir: defaultBkp.backupDir,
        newVaultPath: path.join(root, 'OutsideV'),
        newDataPath: path.join(isoRoot, 'InsideD'),
        isolatedRoot: isoRoot
      }), /RESTORE_OUTSIDE_ISOLATED_ROOT/);

      assert.throws(() => restoreFromBackup({
        backupDir: defaultBkp.backupDir,
        newVaultPath: path.join(isoRoot, 'Nest'),
        newDataPath: path.join(isoRoot, 'Nest', 'Data'),
        isolatedRoot: isoRoot
      }), /RESTORE_INVALID_TARGET/);

      assert.throws(() => restoreFromBackup({
        backupDir: defaultBkp.backupDir,
        newVaultPath: path.join(defaultBkp.backupDir, 'SubV'),
        newDataPath: path.join(isoRoot, 'CleanD')
      }), /RESTORE_TARGET_OVERLAP/);

      // 篡改源备份 manifest 文件之一，预检必须在写入目标前拦截
      const corruptBkpDir = path.join(root, 'CorruptBackupCopy');
      fs.cpSync(defaultBkp.backupDir, corruptBkpDir, { recursive: true });
      fs.appendFileSync(path.join(corruptBkpDir, 'AgentMemory', '首页.md'), '\ntampered', 'utf8');
      assert.throws(() => restoreFromBackup({
        backupDir: corruptBkpDir,
        newVaultPath: path.join(isoRoot, 'CleanV2'),
        newDataPath: path.join(isoRoot, 'CleanD2'),
        isolatedRoot: isoRoot
      }), /RESTORE_SOURCE_MANIFEST_MISMATCH/);

      // 合规干净目录恢复校验分离核查字段
      const okRest = restoreFromBackup({
        backupDir: defaultBkp.backupDir,
        newVaultPath: path.join(isoRoot, 'OkVault'),
        newDataPath: path.join(isoRoot, 'OkData'),
        isolatedRoot: isoRoot
      });
      assert.equal(okRest.restored, true);
      assert.equal(okRest.verification.manifestPreflight.ok, true);
      assert.equal(okRest.verification.postRestoreFingerprints.ok, true);
      assert.equal(okRest.verification.sqliteIntegrity.ok, true);
      assert.equal(okRest.verification.businessChecks.missingCount, 0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('9. [D1] mem status --vault 校验配对并分列四类笔记、pending 提案与实时有效核对状态', () => {
    const envA = makeTempEnv('v25-d1a-');
    const envB = makeTempEnv('v25-d1b-');
    try {
      const dbA = openDatabase(envA.dbPath);
      const dbB = openDatabase(envB.dbPath);
      const knId = 'KN-019316a8-7c40-7000-8000-d10000000001';
      let propPend;
      let propAcc;
      let knPath;
      try {
        knPath = publishAuditNote({
          db: dbA,
          vaultPath: envA.vaultPath,
          dataPath: envA.dataPath,
          id: knId,
          relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-d1.md'),
          content: makeNoteMarkdown({ id: knId, title: 'D1 分类统计', project: 'D1Ops', body: 'NewD1Step' })
        }).targetPath;
        // 往 envB 也发一篇以便让 envB.notes 非空触发跨库配对拦截
        publishAuditNote({
          db: dbB,
          vaultPath: envB.vaultPath,
          dataPath: envB.dataPath,
          id: 'KN-019316a8-7c40-7000-8000-d10000000099',
          relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-d1-other.md'),
          content: makeNoteMarkdown({ id: 'KN-019316a8-7c40-7000-8000-d10000000099', title: 'OtherVault' })
        });
        // 在 envA 插入 1 条 session 与 1 条 evidence
        dbA.prepare("INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at) VALUES (?, 'session', 'S1', 'D1Ops', 'local_only', ?, 'h1', 'active', datetime('now'))")
          .run('SES-D1-1', path.join(envA.vaultPath, '10_Readable_Sessions', 'SES-D1-1.md'));
        dbA.prepare("INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, status, created_at) VALUES (?, 'evidence', 'E1', 'D1Ops', 'sanitized', ?, 'h2', 'active', datetime('now'))")
          .run('EV-D1-1', path.join(envA.vaultPath, '20_Evidence_Cards', 'EV-D1-1.md'));

        propPend = createProposal({
          queueDir: path.join(envA.vaultPath, '40_Review_Queue'),
          proposalUuid: 'PROP-019316a8-7c40-7000-8000-d10000000002',
          title: 'Pending D1',
          project: 'D1Ops',
          targetId: knId,
          targetNoteRef: `[[${knId}]]`,
          preConditions: ['Old'],
          postConditions: ['NewD1Step']
        });
        propAcc = createProposal({
          queueDir: path.join(envA.vaultPath, '40_Review_Queue'),
          proposalUuid: 'PROP-019316a8-7c40-7000-8000-d10000000003',
          title: 'Accepted D1',
          project: 'D1Ops',
          targetId: knId,
          targetNoteRef: `[[${knId}]]`,
          preConditions: ['Old'],
          postConditions: ['NewD1Step']
        });
        fs.writeFileSync(propAcc.proposalPath, fs.readFileSync(propAcc.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
        reconcileProposal({ db: dbA, proposalPath: propAcc.proposalPath, targetPath: knPath });
      } finally {
        dbA.close();
        dbB.close();
      }

      // 配对校验：错配 Vault 与 Data 必须报错退出
      let mismatchExit = 0;
      let mismatchErr = '';
      try {
        execFileSync(process.execPath, [CLI_PATH, 'status', '--vault', envA.vaultPath, '--data', envB.dataPath, '--json'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        mismatchExit = e.status || 1;
        mismatchErr = (e.stderr || '') + (e.stdout || '');
      }
      assert.notEqual(mismatchExit, 0);
      assert.ok(mismatchErr.includes('ERR_VAULT_DATA_MISMATCH'));

      // 合法配对输出：旧 total=3 保持，同时拆出四类计数与 pending 提案
      const stOk = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'status', '--vault', envA.vaultPath, '--data', envA.dataPath, '--json'], { encoding: 'utf8' }));
      assert.equal(stOk.notes.total, 3);
      assert.equal(stOk.notes.byType.sessions, 1);
      assert.equal(stOk.notes.byType.evidence, 1);
      assert.equal(stOk.notes.byType.knowledge, 1);
      assert.equal(stOk.notes.byType.proposals, 0);
      assert.equal(stOk.proposals.pending, 1);
      assert.equal(stOk.proposals.verified, 1);
    } finally {
      fs.rmSync(envA.root, { recursive: true, force: true });
      fs.rmSync(envB.root, { recursive: true, force: true });
    }
  });

  await t.test('10. [D2 + D4] 改名跨路径 Git 历史精准追溯 + reconcile 内容去重归档无自动 Git 提交 + 结构化 yaml/section/citation 条件检验', () => {
    const { root, vaultPath, dataPath, dbPath, env } = makeTempEnv('v25-d2d4-');
    initGitRepo(vaultPath);
    const db = openDatabase(dbPath);
    try {
      const id = 'KN-019316a8-7c40-7000-8000-d20000000001';
      const origContent = makeNoteMarkdown({
        id,
        title: 'D2D4 验证',
        project: 'D2Ops',
        body: '## 2. 执行步骤\n旧错误命令 BadCmdD4\n<!-- 新成功命令注释不算 -->\n'
      });
      const origPath = publishAuditNote({
        db,
        vaultPath,
        dataPath,
        id,
        relTarget: path.join('30_Knowledge_Notes', 'Playbooks', 'KN-d2-before.md'),
        content: origContent
      }).targetPath;
      settlePublishedGitCommit({ vaultDir: vaultPath, filePath: origPath, commitMessage: 'commit v1 before rename' });

      // 改名并修改为合规内容（去掉 BadCmdD4，新增 ## 3. 新方案、citation、yaml 字段）
      const renamedPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-d2-after.md');
      fs.renameSync(origPath, renamedPath);
      scanAndSyncNotes({ db, vaultDir: vaultPath });
      const v2Content = [
        '---',
        'schema_version: 1',
        `id: "${id}"`,
        'note_type: "playbook"',
        'title: "D2D4 验证"',
        'project: "D2Ops"',
        'privacy: "sanitized"',
        'lifecycle: "active"',
        'evidence_level: "verified"',
        'review_state: "accepted"',
        'as_of: "2026-11-12"',
        'review_after: "2027-06-01"',
        'created_at: "2026-11-12T08:00:00+08:00"',
        '---',
        '## 3. 新方案',
        '依据 [[EV-D4-001]] 执行。',
        ''
      ].join('\n');
      fs.writeFileSync(renamedPath, v2Content, 'utf8');
      settlePublishedGitCommit({ vaultDir: vaultPath, filePath: renamedPath, commitMessage: 'commit v2 after rename' });

      // 验证 D4 结构化前后置条件（yaml:, section:, citation:, 剥离 HTML 注释后验证）
      const condFailOnComment = evaluateProposalConditions({
        targetRaw: origContent,
        preConditions: ['BadCmdD4'],
        postConditions: ['新成功命令注释不算']
      });
      assert.equal(condFailOnComment.passed, false);

      const condPass = evaluateProposalConditions({
        targetRaw: v2Content,
        preConditions: ['BadCmdD4'],
        postConditions: ['yaml: evidence_level = verified', 'section: ## 3. 新方案', 'citation: [[EV-D4-001]]']
      });
      assert.equal(condPass.passed, true);

      // reconcile 内容去重归档，且重复执行不增加冗余修订文件也不产生自动 Git 提交
      const headCountBefore = execFileSync('git', ['rev-list', '--count', 'HEAD'], { cwd: vaultPath, encoding: 'utf8' }).trim();
      const prop = createProposal({
        queueDir: path.join(vaultPath, '40_Review_Queue'),
        proposalUuid: 'PROP-019316a8-7c40-7000-8000-d20000000002',
        title: 'D2D4 提案',
        project: 'D2Ops',
        targetId: id,
        targetNoteRef: '[[KN-d2-after]]',
        preConditions: ['BadCmdD4'],
        postConditions: ['yaml: evidence_level = verified', 'section: ## 3. 新方案', 'citation: [[EV-D4-001]]']
      });
      fs.writeFileSync(prop.proposalPath, fs.readFileSync(prop.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');

      const revDir = path.join(dataPath, 'runtime', 'revisions');
      reconcileProposal({ db, proposalPath: prop.proposalPath, targetPath: renamedPath, revisionsDir: revDir });
      const r2 = reconcileProposal({ db, proposalPath: prop.proposalPath, targetPath: renamedPath, revisionsDir: revDir });
      assert.equal(r2.reconcile_state, 'verified_applied');
      const archivedFiles = fs.readdirSync(path.join(revDir, id)).filter(f => /^rev-\d+\.md$/.test(f));
      assert.equal(archivedFiles.length, 2, 'publish 时存 rev-0001，reconcile 新内容去重仅增存 1 份 rev-0002');
      assert.equal(execFileSync('git', ['rev-list', '--count', 'HEAD'], { cwd: vaultPath, encoding: 'utf8' }).trim(), headCountBefore, 'reconcile 不得触发自动 Git 提交');

      // 删除归档本地文件后通过 Git 历史路径追溯恢复改名前的 rev-0001
      db.close();
      fs.rmSync(path.join(revDir, id), { recursive: true, force: true });
      const prevOut = execFileSync(process.execPath, [CLI_PATH, 'restore', id, '--revision', 'rev-0001'], { env, encoding: 'utf8' });
      assert.ok(prevOut.includes('[mem restore 提示]'));
      const previewGitRev = fs.readFileSync(path.join(dataPath, 'staging', 'restore-preview', `${id}-rev-0001.md`), 'utf8');
      assert.ok(previewGitRev.includes('BadCmdD4'), '改名后查询 Git rev-0001 必须能精准溯源改名前的旧路径内容');
    } finally {
      try { db.close(); } catch {}
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('11. [D3 + D7] 统一写锁处理孤儿遗留 publisher.lock 与活跃锁拒绝回收；doctor 报告 NTFS 硬链接探测分类', () => {
    const { root, vaultPath, dataPath, env } = makeTempEnv('v25-d3d7-');
    try {
      // D3a: 遗留死进程 publisher.lock 阻断普通写锁并在 recover-lock 安全归档
      const legacyLock = path.join(dataPath, 'runtime', 'publisher.lock');
      fs.writeFileSync(legacyLock, JSON.stringify({ pid: 999998, command: 'backup', acquired_at: new Date().toISOString() }), 'utf8');
      assert.throws(() => acquireWriteLock({ dataPath, command: 'publish', timeoutMs: 200 }), /ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY/);

      const rec = recoverStaleWriteLock({ vaultPath, dataPath });
      assert.equal(rec.recovered, true);
      assert.equal(fs.existsSync(legacyLock), false);
      assert.ok(fs.readdirSync(path.join(dataPath, 'runtime', 'stale-locks')).some(f => f.startsWith('publisher.lock')));

      // D3b: 存活进程持有 publisher.lock 时严禁 recover-lock 强制清除
      fs.writeFileSync(legacyLock, JSON.stringify({ pid: process.pid, command: 'backup', acquired_at: new Date().toISOString() }), 'utf8');
      assert.throws(() => recoverStaleWriteLock({ vaultPath, dataPath }), /ERR_WRITE_LOCK_ACTIVE_CANNOT_RECOVER/);
      fs.unlinkSync(legacyLock);

      // D3c: 备份全程使用 write.lock (command=backup) 且绝不再新建 publisher.lock
      const bkpHandle = acquireWriteLock({ dataPath, command: 'backup' });
      try {
        const wlInfo = inspectWriteLockFile(bkpHandle.lockPath);
        assert.equal(wlInfo.payload.command, 'backup');
        assert.equal(fs.existsSync(legacyLock), false);

        const docWhileLock = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'doctor', '--json'], { env, encoding: 'utf8' }));
        assert.equal(docWhileLock.writeLockPresent, true);
        assert.equal(docWhileLock.writeLockCommand, 'backup');
        assert.equal(docWhileLock.linkProbeStatus, 'supported');
      } finally {
        releaseWriteLock(bkpHandle);
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('12. [D6 + DSH Synthetic] 有界头尾读取大体积 Antigravity 会话与 DSH 多帧 .v4.jsonl.zstd 发现一致性', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v25-d6dsh-'));
    try {
      const codexHome = path.join(root, 'codex');
      const agyRoot = path.join(root, 'agy');
      const dshHome = path.join(root, 'dsh');
      fs.mkdirSync(path.join(codexHome, 'sessions'), { recursive: true });
      fs.mkdirSync(dshHome, { recursive: true });

      // 构造 3 个 ~4MB 大体积 Antigravity 主会话、1 个空白行无效会话、1 个 subagent、1 个未闭合会话
      const filler = JSON.stringify({ step_index: 2, type: 'GENERIC', content: 'X'.repeat(4096) });
      for (let i = 1; i <= 3; i++) {
        const logsDir = path.join(agyRoot, `agy-big-00${i}`, '.system_generated', 'logs');
        fs.mkdirSync(logsDir, { recursive: true });
        const head = JSON.stringify({ step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', content: `big ${i}` });
        const bodyChunks = new Array(900).fill(filler).join('\n');
        const tail = JSON.stringify({ step_index: 902, type: 'PLANNER_RESPONSE', content: 'done' });
        fs.writeFileSync(path.join(logsDir, 'transcript.jsonl'), `${head}\n${bodyChunks}\n${tail}\n`, 'utf8');
      }
      const wsOnlyLogs = path.join(agyRoot, 'agy-ws-empty', '.system_generated', 'logs');
      fs.mkdirSync(wsOnlyLogs, { recursive: true });
      fs.writeFileSync(path.join(wsOnlyLogs, 'transcript.jsonl'), '   \n\n  \t \n', 'utf8');

      // DSH 多帧样本：帧1仅头+帧2消息 (主会话) vs 帧1头+skippable帧 (空会话) vs 损坏第二帧 (corrupt)
      const dshMainDir = path.join(dshHome, '--D-Test-Proj--', 'dsh-multi-ok');
      const dshSkipDir = path.join(dshHome, '--D-Test-Proj--', 'dsh-skip-only');
      const dshCorruptDir = path.join(dshHome, '--D-Test-Proj--', 'dsh-corrupt-f2');
      fs.mkdirSync(dshMainDir, { recursive: true });
      fs.mkdirSync(dshSkipDir, { recursive: true });
      fs.mkdirSync(dshCorruptDir, { recursive: true });

      const f1 = zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'session', version: 4, id: 'dsh-multi-ok', cwd: 'D:\\Test\\Proj', delegationDepth: 0 }) + '\n', 'utf8'));
      const f2 = zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'user/message', data: { content: 'frame 2 ok' } }) + '\n', 'utf8'));
      fs.writeFileSync(path.join(dshMainDir, 'session.v4.jsonl.zstd'), Buffer.concat([f1, buildSkippableZstdFrame('meta'), f2]));
      fs.writeFileSync(path.join(dshSkipDir, 'session.v4.jsonl.zstd'), Buffer.concat([f1, buildSkippableZstdFrame('trailing-only')]));
      fs.writeFileSync(path.join(dshCorruptDir, 'session.v4.jsonl.zstd'), Buffer.concat([f1, Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x99])]));

      assert.equal(inspectDshSessionMetadata(path.join(dshMainDir, 'session.v4.jsonl.zstd')).isMainCompleted, true);
      assert.equal(inspectDshSessionMetadata(path.join(dshSkipDir, 'session.v4.jsonl.zstd')).filteredReason, 'empty_session');
      assert.equal(inspectDshSessionMetadata(path.join(dshCorruptDir, 'session.v4.jsonl.zstd')).filteredReason, 'corrupt_session');

      const t0 = performance.now();
      const firstRun = listDiscoverableSessions({ codexHome, antigravityBrainDir: agyRoot, dshHome });
      const coldMs = performance.now() - t0;

      const t1 = performance.now();
      const secondRun = listDiscoverableSessions({ codexHome, antigravityBrainDir: agyRoot, dshHome });
      const warmMs = performance.now() - t1;

      assert.equal(firstRun.length, 4, '3 个大体积 Antigravity 主会话 + 1 个 DSH 多帧主会话');
      assert.deepEqual(secondRun, firstRun, '命中缓存后排序与返回字段必须完全一致');
      assert.ok(warmMs <= coldMs + 20);

      const withFiltered = listDiscoverableSessions({ codexHome, antigravityBrainDir: agyRoot, dshHome, includeFiltered: true });
      assert.equal(withFiltered.length, 7);
      assert.equal(withFiltered.find(s => s.session_id === 'agy-ws-empty')?.filtered_reason, 'empty_session');
      assert.equal(withFiltered.find(s => s.session_id === 'dsh-skip-only')?.filtered_reason, 'empty_session');
      assert.equal(withFiltered.find(s => s.session_id === 'dsh-corrupt-f2')?.filtered_reason, 'corrupt_session');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('13. [Section E] .base 视图 Obsidian 1.15.0 语义/模板对齐与 B01 PLAN 6 面映射', () => {
    // 1. 验证四份内置 .base 模板符合 Obsidian 1.15.0 规范（去外层引号过滤器、无 note. 的 order 列、待处理排序、双页签与溯源列）
    assert.ok(BASES_VIEWS['知识总览.base'].includes('- file.inFolder("30_Knowledge_Notes")'));
    assert.ok(BASES_VIEWS['知识总览.base'].includes('- project'));
    assert.ok(BASES_VIEWS['待处理更新.base'].includes('- note.proposal_status == "pending"'));
    assert.ok(BASES_VIEWS['待处理更新.base'].includes('- note.proposal_status == "accepted"'));
    assert.ok(BASES_VIEWS['待处理更新.base'].includes('sort:\n      - property: file.name'));
    assert.ok(BASES_VIEWS['到期复核.base'].includes('- date(note.review_after) <= today()'));
    assert.ok(BASES_VIEWS['会话与证据溯源.base'].includes('- file.inFolder("10_Readable_Sessions")'));
    assert.ok(BASES_VIEWS['会话与证据溯源.base'].includes('- source_tool'));

    // 2. 用合成笔记夹具验证 4 视图筛选语义与模板排除
    const templateItem = {
      file: { inFolder: (f) => f === '90_Templates' || f === '30_Knowledge_Notes' || f === '40_Review_Queue' },
      note: { lifecycle: 'active', review_state: 'pending', proposal_status: 'pending' }
    };
    assert.equal(evaluateBaseFilter('知识总览', templateItem), false);
    assert.equal(evaluateBaseFilter('待处理更新', templateItem), false);
    assert.equal(evaluateBaseFilter('到期复核', templateItem, '2026-11-12'), false);
    assert.equal(evaluateBaseFilter('会话与证据溯源', templateItem), false);

    const knDue = {
      file: { inFolder: (f) => f === '30_Knowledge_Notes' },
      note: { lifecycle: 'active', review_state: 'accepted', review_after: '2026-11-12' }
    };
    assert.equal(evaluateBaseFilter('知识总览', knDue), true);
    assert.equal(evaluateBaseFilter('到期复核', knDue, '2026-11-12'), true);
    assert.equal(evaluateBaseFilter('到期复核', knDue, '2026-11-11'), false);

    const propPending = { file: { inFolder: (f) => f === '40_Review_Queue' }, note: { proposal_status: 'pending' } };
    const propAccepted = { file: { inFolder: (f) => f === '40_Review_Queue' }, note: { proposal_status: 'accepted' } };
    assert.equal(evaluateBaseFilter('待处理更新:待处理更新提案', propPending), true);
    assert.equal(evaluateBaseFilter('待处理更新:待处理更新提案', propAccepted), false);
    assert.equal(evaluateBaseFilter('待处理更新:已标采纳', propAccepted), true);

    const sesNote = { file: { inFolder: (f) => f === '10_Readable_Sessions' }, note: { note_type: 'session', source_tool: 'codex' } };
    const evNote = { file: { inFolder: (f) => f === '20_Evidence_Cards' }, note: { note_type: 'evidence', source_tool: 'dsh' } };
    assert.equal(evaluateBaseFilter('会话与证据溯源:已整理会话台账', sesNote), true);
    assert.equal(evaluateBaseFilter('会话与证据溯源:已整理会话台账', evNote), false);
    assert.equal(evaluateBaseFilter('会话与证据溯源:原子证据卡台账', evNote), true);

    // 3. 验证 B01 源码汇总面与 PLAN §3.3 六类受保护目标一一对应，且脚本拒绝不替代 OS 权限证据
    assert.equal(PLAN_B01_SIX_SURFACES.length, 6);
    const matrix = runMultiHostIsolationMatrix();
    assert.equal(matrix.planSurfaces.length, 6);
    assert.equal(matrix.scriptRefusalDoesNotProveOsIsolation, true);
    assert.equal(matrix.allHostsStrongIsolated, false);
    assert.ok(matrix.planSurfaceResults.dsh.vault_git_and_revisions);
    assert.equal(matrix.planSurfaceResults.dsh.vault_git_and_revisions.blocked, false);
  });

  await t.test('14. [D7] cli/deploy.mjs 默认干跑预览、限清单同步、保留根入口/人工脚本/未列文件且零差异', () => {
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'oam-deploy-test-'));
    const tmpTarget = path.join(tmpBase, 'deployed-cli');

    const initialDryRun = runDeploy({ repoRoot: REPO_ROOT, targetDir: tmpTarget });
    assert.equal(initialDryRun.mode, 'dry-run');
    assert.ok(initialDryRun.preDiffCount > 0);
    assert.ok(initialDryRun.counts.create > 0);
    assert.equal(initialDryRun.verifiedZeroDiff, null);
    assert.equal(fs.existsSync(tmpTarget), false);

    fs.mkdirSync(tmpTarget, { recursive: true });
    const extraPath = path.join(tmpTarget, 'extra-keep.txt');
    fs.writeFileSync(extraPath, 'keep-existing-file', 'utf8');

    const cliDryRunRaw = execFileSync(
      process.execPath,
      ['cli/deploy.mjs', '--target', tmpTarget, '--json'],
      { cwd: REPO_ROOT, encoding: 'utf8' }
    );
    const cliDryRun = JSON.parse(cliDryRunRaw);
    assert.equal(cliDryRun.mode, 'dry-run');
    assert.equal(fs.existsSync(path.join(tmpTarget, 'package.json')), false);
    assert.equal(fs.readFileSync(extraPath, 'utf8'), 'keep-existing-file');

    const cliApplyRaw = execFileSync(
      process.execPath,
      ['cli/deploy.mjs', '--apply', '--target', tmpTarget, '--json'],
      { cwd: REPO_ROOT, encoding: 'utf8' }
    );
    const cliApply = JSON.parse(cliApplyRaw);
    assert.equal(cliApply.mode, 'apply');
    assert.equal(cliApply.postDiffCount, 0);
    assert.equal(cliApply.verifiedZeroDiff, true);
    assert.ok(cliApply.preservedExtraFiles.includes('extra-keep.txt'));
    assert.equal(fs.readFileSync(extraPath, 'utf8'), 'keep-existing-file');

    const rootMem = fs.readFileSync(path.join(tmpTarget, 'mem.mjs'), 'utf8');
    assert.match(rootMem, /import '\.\/cli\/mem\.mjs';/);
    assert.equal(
      fs.readFileSync(path.join(tmpTarget, 'inspect-raw-local.ps1'), 'utf8'),
      fs.readFileSync(path.join(REPO_ROOT, 'cli', 'inspect-raw-local.ps1'), 'utf8')
    );
    assert.equal(fs.existsSync(path.join(tmpTarget, 'cli', 'deploy.mjs')), true);
    assert.equal(fs.existsSync(path.join(tmpTarget, 'docs')), false);

    const repeatDryRun = runDeploy({ repoRoot: REPO_ROOT, targetDir: tmpTarget, apply: false });
    assert.equal(repeatDryRun.mode, 'dry-run');
    assert.equal(repeatDryRun.preDiffCount, 0);
    assert.equal(repeatDryRun.postDiffCount, 0);
    assert.equal(repeatDryRun.counts.update, 0);
    assert.equal(repeatDryRun.counts.create, 0);
    assert.equal(repeatDryRun.counts.unchanged, repeatDryRun.counts.total);

    assert.throws(
      () => runDeploy({ repoRoot: REPO_ROOT, targetDir: REPO_ROOT, apply: false }),
      /DEPLOY_INVALID_TARGET/
    );
  });

  await t.test('15. [Independent Review Fixes A] 多行 # 条件、CRLF 结算、盘符大小写与日期清理、重复 ID 降级、多文件与 >50% 改名 Git 追溯及 local_only diff 脱敏', () => {
    const roots = [];
    const dbs = [];
    const makeEnv = (prefix) => {
      const env = makeTempEnv(prefix);
      roots.push(env.root);
      initGitRepo(env.vaultPath);
      execFileSync('git', ['config', 'user.name', 'Test'], { cwd: env.vaultPath });
      execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: env.vaultPath });
      return env;
    };
    try {
      // (a) 多行 # 条件不误判为单行 heading
      const doc = '---\ntitle: t\n---\n\n# Header\n# line one\nline two\n';
      assert.equal(evaluateProposalConditions({ targetRaw: doc, postConditions: ['# line one\nline two'] }).passed, true);
      assert.equal(evaluateProposalConditions({ targetRaw: doc, postConditions: ['# Header\nmissing line two'] }).passed, false);

      // (b) CRLF 文件在 core.autocrlf=true 下发布与结算必须为 committed
      const eCrlf = makeEnv('v25-rev-crlf-');
      const crlfPath = path.join(eCrlf.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000c1_crlf.md');
      const crlfBody = '---\r\nschema_version: 1\r\nid: "KN-019316a8-0000-7000-8000-0000000000c1"\r\nnote_type: "playbook"\r\ntitle: "CRLF"\r\nproject: "P"\r\nprivacy: "sanitized"\r\nlifecycle: "active"\r\nevidence_level: "observed"\r\nreview_state: "accepted"\r\nenv:\r\n  os: "windows"\r\ncreated_at: "2026-11-10T10:00:00Z"\r\n---\r\n\r\n# CRLF\r\nBody\r\n';
      fs.writeFileSync(crlfPath, crlfBody, 'utf8');
      const crlfSha = crypto.createHash('sha256').update(crlfBody, 'utf8').digest('hex');
      assert.equal(commitPublishedFile({ vaultDir: eCrlf.vaultPath, filePath: crlfPath, commitMessage: 'add crlf' }).success, true);
      const settled = settlePublishedGitCommit({ vaultDir: eCrlf.vaultPath, filePath: crlfPath, expectedSha256: crlfSha, commitMessage: 'settle crlf' });
      assert.equal(settled.gitState, 'committed');

      // (c) Windows 盘符大小写不变性 + 清空移除的可选日期 + 重复 ID 禁止召回为可行动项
      const eSync = makeEnv('v25-rev-syncdup-');
      const dbSync = openExistingDatabase(eSync.dbPath);
      dbs.push(dbSync);
      const idDup = 'KN-019316a8-0000-7000-8000-0000000000d1';
      const stgDup = stageCandidate({
        stagingDir: path.join(eSync.dataPath, 'staging'),
        outputUuid: idDup,
        content: `---\nschema_version: 1\nid: "${idDup}"\nnote_type: "playbook"\ntitle: "CaseReview"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nas_of: "2026-11-10"\nreview_after: "2099-01-01"\nenv:\n  os: "windows"\ncreated_at: "2026-11-10T10:00:00Z"\n---\n\n# CaseReview\nUniqueMarkerCaseDup\n`,
        validateSchema: true
      });
      const noteDupPath = path.join(eSync.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000d1_CaseReview.md');
      publishFile({
        db: dbSync,
        operationId: 'op-syncdup-1',
        outputUuid: idDup,
        stagingPath: stgDup.stagingPath,
        vaultTargetPath: noteDupPath,
        contentSha256: stgDup.contentSha256,
        revisionsDir: path.join(eSync.dataPath, 'runtime', 'revisions')
      });
      const lowerDrivePath = noteDupPath.replace(/^([A-Za-z]):/, (_, d) => `${d.toLowerCase()}:`);
      dbSync.prepare('UPDATE notes SET path = ? WHERE id = ?').run(lowerDrivePath, idDup);
      assert.equal(scanAndSyncNotes({ db: dbSync, vaultDir: eSync.vaultPath }).renamed.length, 0);

      fs.writeFileSync(
        noteDupPath,
        fs.readFileSync(noteDupPath, 'utf8').replace(/as_of:.*\n/, '').replace(/review_after:.*\n/, ''),
        'utf8'
      );
      scanAndSyncNotes({ db: dbSync, vaultDir: eSync.vaultPath });
      const rowNoDates = dbSync.prepare('SELECT as_of, review_after FROM notes WHERE id = ?').get(idDup);
      assert.equal(rowNoDates.as_of, null);
      assert.equal(rowNoDates.review_after, null);

      const dupCopyPath = path.join(eSync.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000d1_DupCopy.md');
      fs.writeFileSync(dupCopyPath, fs.readFileSync(noteDupPath, 'utf8'), 'utf8');
      const dupSearch = searchKnowledge({ db: dbSync, vaultDir: eSync.vaultPath, query: 'UniqueMarkerCaseDup' });
      assert.ok(dupSearch.items.length >= 1);
      for (const item of dupSearch.items) {
        assert.equal(item.actionable, false);
        assert.equal(item.reason, 'duplicate_id_conflict');
      }
      dbSync.close();

      // (d) 多文件提交 + >50% 重写改名下追溯 Git rev-0001；proposal show 对历史 local_only base_revision 脱敏；delete 不覆盖 rev-0001；restore 保降级锁且落账 committed
      const eHist = makeEnv('v25-rev-hist-');
      const dbHist = openExistingDatabase(eHist.dbPath);
      dbs.push(dbHist);
      const idHist = 'KN-019316a8-0000-7000-8000-0000000000h1';
      const oldPath = path.join(eHist.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000h1_OldTitle.md');
      const rev1Text = `---\nschema_version: 1\nid: "${idHist}"\nnote_type: "playbook"\ntitle: "OldTitle"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\ncreated_at: "2026-11-10T10:00:00Z"\n---\n\n# OldTitle\nV1-Exact-Marker\n`;
      fs.writeFileSync(oldPath, rev1Text, 'utf8');
      execFileSync('git', ['add', '.'], { cwd: eHist.vaultPath });
      execFileSync('git', ['commit', '-m', 'rev1'], { cwd: eHist.vaultPath });

      const rev2Text = rev1Text.replace('privacy: "sanitized"', 'privacy: "local_only"').replace('V1-Exact-Marker', 'PrivateHistMarker99');
      fs.writeFileSync(oldPath, rev2Text, 'utf8');
      fs.writeFileSync(path.join(eHist.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000h9_Other.md'), 'other\n', 'utf8');
      execFileSync('git', ['add', '.'], { cwd: eHist.vaultPath });
      execFileSync('git', ['commit', '-m', 'rev2 multi local_only'], { cwd: eHist.vaultPath });
      const rev2Commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: eHist.vaultPath, encoding: 'utf8' }).trim();
      const rev2Sha = crypto.createHash('sha256').update(rev2Text, 'utf8').digest('hex');

      const newPath = path.join(eHist.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000h1_NewTitle.md');
      const rewritten = Array.from({ length: 40 }, (_, idx) => `Totally rewritten public line ${idx}`).join('\n');
      const rev3Text = `---\nschema_version: 1\nid: "${idHist}"\nnote_type: "playbook"\ntitle: "NewTitle"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\ncreated_at: "2026-11-10T10:00:00Z"\n---\n\n# NewTitle\n${rewritten}\n`;
      fs.unlinkSync(oldPath);
      fs.writeFileSync(newPath, rev3Text, 'utf8');
      execFileSync('git', ['add', '-A'], { cwd: eHist.vaultPath });
      execFileSync('git', ['commit', '-m', 'rev3 rename rewrite sanitized'], { cwd: eHist.vaultPath });
      const rev3Sha = crypto.createHash('sha256').update(rev3Text, 'utf8').digest('hex');

      const nowIso = new Date().toISOString();
      dbHist.prepare(`INSERT INTO notes (id, note_type, title, project, privacy, lifecycle, evidence_level, review_state, path, content_sha256, status, created_at, updated_at) VALUES (?, 'playbook', 'NewTitle', 'P', 'sanitized', 'active', 'observed', 'accepted', ?, ?, 'active', ?, ?)`).run(idHist, newPath, rev3Sha, nowIso, nowIso);
      const propId = 'PROP-019316a8-0000-7000-8000-0000000000p1';
      const propPath = path.join(eHist.vaultPath, '40_Review_Queue', 'PROP-20261110-0000p1_Prop.md');
      const propText = `---\nschema_version: 1\nid: "${propId}"\nnote_type: "update_proposal"\ntitle: "Prop"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\ntarget_id: "${idHist}"\nbase_revision_id: "${rev2Commit}"\nbase_content_sha256: "${rev2Sha}"\nupdate_mode: "replace"\nreview_state: "accepted"\npre_conditions:\n  - "pre"\npost_conditions:\n  - "post"\ncreated_at: "${nowIso}"\n---\n\n# Prop\n`;
      fs.writeFileSync(propPath, propText, 'utf8');
      const propSha = crypto.createHash('sha256').update(propText, 'utf8').digest('hex');
      dbHist.prepare(`INSERT INTO notes (id, note_type, title, project, privacy, lifecycle, evidence_level, review_state, path, content_sha256, status, created_at, updated_at) VALUES (?, 'update_proposal', 'Prop', 'P', 'sanitized', 'active', 'observed', 'accepted', ?, ?, 'active', ?, ?)`).run(propId, propPath, propSha, nowIso, nowIso);

      const propShowJson = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', propId, '--vault', eHist.vaultPath, '--data', eHist.dataPath, '--json'], { encoding: 'utf8' })
      );
      assert.equal(propShowJson.base_revision_diff.redacted, true);
      assert.equal(propShowJson.base_revision_diff.reason, 'base_revision_not_sanitized');
      assert.equal(JSON.stringify(propShowJson).includes('PrivateHistMarker99'), false);

      dbHist.prepare(`UPDATE notes SET privacy = 'local_only' WHERE id = ?`).run(idHist);
      dbHist.close();

      execFileSync(process.execPath, [CLI_PATH, 'delete', idHist, '--confirm', '--vault', eHist.vaultPath, '--data', eHist.dataPath], { encoding: 'utf8' });
      assert.equal(fs.existsSync(path.join(eHist.dataPath, 'runtime', 'revisions', idHist, 'rev-0001.md')), false);
      const restoreOut = execFileSync(process.execPath, [CLI_PATH, 'restore', idHist, '--revision', 'rev-0001', '--confirm', '--vault', eHist.vaultPath, '--data', eHist.dataPath], { encoding: 'utf8' });
      assert.ok(restoreOut.includes('[REDACTED_LOCAL_ONLY]'));
      assert.ok(fs.readFileSync(newPath, 'utf8').includes('V1-Exact-Marker'));

      const dbHistCheck = openExistingDatabase(eHist.dbPath, { readOnly: true });
      dbs.push(dbHistCheck);
      assert.equal(dbHistCheck.prepare('SELECT privacy FROM notes WHERE id = ?').get(idHist).privacy, 'local_only');
      const latestAux = dbHistCheck.prepare('SELECT git_state FROM auxiliary_states ORDER BY updated_at DESC LIMIT 1').get();
      assert.equal(latestAux.git_state, 'committed');
      dbHistCheck.close();
    } finally {
      for (const db of dbs) { try { db.close(); } catch {} }
      for (const r of roots) { try { fs.rmSync(r, { recursive: true, force: true }); } catch {} }
    }
  });

  await t.test('16. [Independent Review Fixes B] CLI --vault/--data 全命令绑定与空 notes 配对、写锁互斥与 Git 单条异常隔离、清单越界防护与就绪别名', () => {
    const roots = [];
    const dbs = [];
    const makeEnv = (prefix) => {
      const env = makeTempEnv(prefix);
      roots.push(env.root);
      initGitRepo(env.vaultPath);
      execFileSync('git', ['config', 'user.name', 'Test'], { cwd: env.vaultPath });
      execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: env.vaultPath });
      return env;
    };
    try {
      const nowIso = new Date().toISOString();

      // (a) CLI --vault/--data 写入目标库（stage-candidate / publish / reconcile / recover-lock / backup）
      const eCli = makeEnv('v25-rev-cliflags-');
      const candUuid = 'KN-019316a8-0000-7000-8000-0000000000c9';
      const candFile = path.join(eCli.root, 'cand.json');
      const candContent = `---\nschema_version: 1\nid: "${candUuid}"\nnote_type: "playbook"\ntitle: "CliFlags"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\ncreated_at: "${nowIso}"\n---\n\n# CliFlags\nBody\n`;
      fs.writeFileSync(candFile, JSON.stringify({ id: candUuid, content: candContent }), 'utf8');
      execFileSync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candFile, '--operation', 'op-cli-flags', '--vault', eCli.vaultPath, '--data', eCli.dataPath], { encoding: 'utf8' });
      execFileSync(process.execPath, [CLI_PATH, 'publish', '--operation', 'op-cli-flags', '--vault', eCli.vaultPath, '--data', eCli.dataPath], { encoding: 'utf8' });
      const dbCli = openExistingDatabase(eCli.dbPath, { readOnly: true });
      dbs.push(dbCli);
      assert.ok(dbCli.prepare('SELECT id FROM notes WHERE id = ?').get(candUuid));
      dbCli.close();
      const bkpCliOut = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'backup', '--vault', eCli.vaultPath, '--data', eCli.dataPath, '--target', path.join(eCli.root, 'Backups'), '--json'], { encoding: 'utf8' })
      );
      assert.equal(bkpCliOut.status, 'complete');
      const rlockCliOut = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'recover-lock', '--vault', eCli.vaultPath, '--data', eCli.dataPath, '--json'], { encoding: 'utf8' })
      );
      assert.equal(rlockCliOut.recovered, true);

      // (b) 空 notes 表下 session_snapshots / publish_intents 配对校验及 benchmark 配对拦截
      const eA = makeEnv('v25-rev-pairA-');
      const eB = makeEnv('v25-rev-pairB-');
      const dbA = openExistingDatabase(eA.dbPath);
      dbs.push(dbA);
      dbA.prepare(`INSERT INTO session_snapshots (snapshot_id, source_tool, session_id, raw_sha256, raw_path, compressed, event_count, prefix_hashes_json, parser_version, sanitizer_version, distiller_version, status, readable_session_path, created_at, updated_at) VALUES ('SNAP-1', 'codex', 's1', 'sha', 'raw', 0, 1, '[]', '1', '1', '1', 'complete', ?, ?, ?)`).run(
        path.join(eB.vaultPath, '10_Readable_Sessions', 'wrong.md'),
        nowIso,
        nowIso
      );
      dbA.close();
      assert.throws(
        () => execFileSync(process.execPath, [CLI_PATH, 'status', '--vault', eA.vaultPath, '--data', eA.dataPath, '--json'], { encoding: 'utf8', stdio: 'pipe' }),
        /VAULT_DATA_MISMATCH/
      );

      const eC = makeEnv('v25-rev-pairC-');
      const dbC = openExistingDatabase(eC.dbPath);
      dbs.push(dbC);
      dbC.prepare(`INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at) VALUES ('op-w', 'KN-W', 'stg', ?, 'sha', 'files_published', ?, ?)`).run(
        path.join(eB.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'wrong.md'),
        nowIso,
        nowIso
      );
      dbC.close();
      assert.throws(
        () => execFileSync(process.execPath, [CLI_PATH, 'status', '--vault', eC.vaultPath, '--data', eC.dataPath, '--json'], { encoding: 'utf8', stdio: 'pipe' }),
        /VAULT_DATA_MISMATCH/
      );

      const emptyQ = path.join(eA.root, 'q.json');
      fs.writeFileSync(emptyQ, '[]', 'utf8');
      assert.throws(
        () => execFileSync(process.execPath, [CLI_PATH, 'benchmark', '--suite', 'pilot', '--vault', eA.vaultPath, '--data', eC.dataPath, '--questions', emptyQ, '--out', path.join(eA.root, 'o.json')], { encoding: 'utf8', stdio: 'pipe' }),
        /VAULT_DATA_MISMATCH/
      );

      // (c) export-egress 写锁冲突 & assertPublisherUnlocked (backup / 半写 / 活进程 PID)
      const eLock = makeEnv('v25-rev-lock-');
      const wLockPath = path.join(eLock.dataPath, 'runtime', 'write.lock');
      const itemsJson = path.join(eLock.root, 'items.json');
      fs.writeFileSync(itemsJson, JSON.stringify([{ id: 'KN-1', content: 'safe' }]), 'utf8');
      fs.writeFileSync(wLockPath, JSON.stringify({ pid: 99999999, command: 'backup', acquired_at: nowIso, lock_token: 'wlk-bkp' }), 'utf8');
      assert.throws(
        () => execFileSync(process.execPath, [CLI_PATH, 'export-egress', '--snapshot', 'SNAP-1', '--approval', 'APPR-1', '--input', itemsJson, '--vault', eLock.vaultPath, '--data', eLock.dataPath], { encoding: 'utf8', stdio: 'pipe' }),
        /ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY/
      );
      assert.throws(() => assertPublisherUnlocked(path.join(eLock.dataPath, 'staging')), /PUBLISHER_LOCKED/);
      fs.writeFileSync(wLockPath, '{ "pid": ', 'utf8');
      assert.throws(() => assertPublisherUnlocked(path.join(eLock.dataPath, 'staging')), /PUBLISHER_LOCKED/);
      const sleeper = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { stdio: 'ignore' });
      try {
        fs.writeFileSync(wLockPath, JSON.stringify({ pid: sleeper.pid, command: 'publish', lock_token: 'wlk-live' }), 'utf8');
        assert.throws(() => assertPublisherUnlocked(path.join(eLock.dataPath, 'staging')), /PUBLISHER_LOCKED/);
      } finally {
        sleeper.kill();
        fs.unlinkSync(wLockPath);
      }

      // (d) recoverStaleWriteLock 单条 Git 异常隔离，不阻断后续队列条目提交
      const eRec = makeEnv('v25-rev-recgit-');
      const dbRec = openExistingDatabase(eRec.dbPath);
      dbs.push(dbRec);
      const outsidePath = path.join(eRec.root, 'outside.md');
      fs.writeFileSync(outsidePath, 'outside', 'utf8');
      const validNotePath = path.join(eRec.vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-0000r2_Valid.md');
      const validBody = '---\nid: "KN-019316a8-0000-7000-8000-0000000000r2"\ntitle: "Valid"\n---\nBody\n';
      fs.writeFileSync(validNotePath, validBody, 'utf8');
      const validSha = crypto.createHash('sha256').update(validBody, 'utf8').digest('hex');
      dbRec.prepare(`INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at) VALUES ('op-bad', 'KN-BAD', 's1', ?, 'sha1', 'files_published', ?, ?)`).run(outsidePath, nowIso, nowIso);
      dbRec.prepare(`INSERT INTO auxiliary_states (operation_id, git_state, index_state, updated_at) VALUES ('op-bad', 'pending', 'stale', ?)`).run(nowIso);
      dbRec.prepare(`INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at) VALUES ('op-ok', 'KN-019316a8-0000-7000-8000-0000000000r2', 's2', ?, ?, 'files_published', ?, ?)`).run(validNotePath, validSha, nowIso, nowIso);
      dbRec.prepare(`INSERT INTO auxiliary_states (operation_id, git_state, index_state, updated_at) VALUES ('op-ok', 'pending', 'stale', ?)`).run(nowIso);
      dbRec.close();
      const recRes = recoverStaleWriteLock({ vaultPath: eRec.vaultPath, dataPath: eRec.dataPath, isPidAliveFn: () => false });
      assert.equal(recRes.retriedGitCommits.length, 2);
      const dbRecCheck = openExistingDatabase(eRec.dbPath, { readOnly: true });
      dbs.push(dbRecCheck);
      assert.equal(dbRecCheck.prepare(`SELECT git_state FROM auxiliary_states WHERE operation_id = 'op-bad'`).get().git_state, 'failed');
      assert.equal(dbRecCheck.prepare(`SELECT git_state FROM auxiliary_states WHERE operation_id = 'op-ok'`).get().git_state, 'committed');
      dbRecCheck.close();

      // (e) restoreFromBackup 源预检与恢复后双重清单路径越界阻断 + collectAcceptanceReadiness 参数别名
      const bkpSec = createConsistentBackup({ vaultPath: eRec.vaultPath, dataPath: eRec.dataPath, targetDir: path.join(eRec.root, 'BkpSec') });
      const escapedFile = path.join(bkpSec.backupDir, 'escaped.md');
      fs.writeFileSync(escapedFile, 'outside', 'utf8');
      const manPath = path.join(bkpSec.backupDir, 'backup-manifest.json');
      const manJson = JSON.parse(fs.readFileSync(manPath, 'utf8'));
      manJson.files.push({ area: 'vault', rel_path: '../escaped.md', sha256: crypto.createHash('sha256').update('outside', 'utf8').digest('hex') });
      fs.writeFileSync(manPath, JSON.stringify(manJson), 'utf8');
      assert.throws(
        () => restoreFromBackup({ backupDir: bkpSec.backupDir, newVaultPath: path.join(eRec.root, 'R1V'), newDataPath: path.join(eRec.root, 'R1D') }),
        /RESTORE_SOURCE_MANIFEST_MISMATCH/
      );
      assert.throws(
        () => restoreFromBackup({ backupDir: bkpSec.backupDir, newVaultPath: path.join(eRec.root, 'R2V'), newDataPath: path.join(eRec.root, 'R2D'), allowIncomplete: true }),
        /escapes target vault directory/
      );

      const ready = collectAcceptanceReadiness({ repoRoot: REPO_ROOT, vaultPath: eRec.vaultPath, dataPath: eRec.dataPath });
      assert.equal(ready.vault.allFourBasesPresent, true);
      assert.throws(() => collectAcceptanceReadiness({ repoRoot: REPO_ROOT }), /vaultDir|vaultPath/);
    } finally {
      for (const db of dbs) { try { db.close(); } catch {} }
      for (const r of roots) { try { fs.rmSync(r, { recursive: true, force: true }); } catch {} }
    }
  });

  await t.test('17. [Panel D-6 Scale] 三端合成规模基准 (Codex .jsonl + 多KB .jsonl.zst / Antigravity / DSH 65+ 会话)：精确 totalCount、全局排序、过滤与缓存失效', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v25-d6-scale-'));
    try {
      const fakeHome = path.join(root, 'home');
      const codexSessions = path.join(fakeHome, '.codex', 'sessions');
      const codexArchived = path.join(fakeHome, '.codex', 'archived_sessions');
      const agyBrain = path.join(fakeHome, '.gemini', 'antigravity', 'brain');
      const dshSessions = path.join(fakeHome, '.dsh', 'sessions');
      const vaultPath = path.join(root, 'AgentMemory');
      const dataPath = path.join(root, 'AgentMemory-Data');
      initRepository({ vaultPath, dataPath });

      fs.mkdirSync(codexSessions, { recursive: true });
      fs.mkdirSync(codexArchived, { recursive: true });
      fs.mkdirSync(agyBrain, { recursive: true });
      fs.mkdirSync(dshSessions, { recursive: true });

      // 构造不可高度重复压缩的负载片段，确保每个 .jsonl.zst 为真实多 KB (~45KB+) 压缩体
      const heavyBlocks = Array.from({ length: 180 }, (_, idx) =>
        JSON.stringify({
          type: 'response_item',
          payload: {
            type: 'message',
            role: idx % 2 === 0 ? 'user' : 'assistant',
            content: [{ type: 'text', text: `msg-${idx}-${crypto.createHash('sha256').update(`seed-${idx}`).digest('hex')}-${crypto.randomBytes(96).toString('hex')}` }]
          }
        })
      ).join('\n');

      const expectedMain = [];
      let secCursor = Math.floor(Date.UTC(2026, 10, 12, 12, 0, 0) / 1000);
      const assignTime = (filePath, meta) => {
        secCursor -= 2;
        const mtime = new Date(secCursor * 1000);
        fs.utimesSync(filePath, mtime, mtime);
        if (meta) {
          expectedMain.push({ ...meta, updated_at: mtime.toISOString() });
        }
      };

      // 1) Codex: 25 个多 KB .jsonl.zst (15 archived + 10 sessions) + 10 个 .jsonl + 6 个被过滤样本
      for (let i = 1; i <= 25; i++) {
        const dir = i <= 15 ? codexArchived : path.join(codexSessions, '2026', '11');
        fs.mkdirSync(dir, { recursive: true });
        const id = `rollout-2026-11-12T10-${String(i).padStart(2, '0')}-00-zst-${String(i).padStart(3, '0')}`;
        const fPath = path.join(dir, `${id}.jsonl.zst`);
        const metaLine = JSON.stringify({
          type: 'session_meta',
          payload: {
            session_id: `meta-zst-${i}`,
            cwd: `D:\\Work\\ScaleProj${i}`,
            source: 'vscode',
            ...(i === 1 ? { pad: 'Z'.repeat(70000) } : {})
          }
        });
        const payloadBuf = Buffer.from(`${metaLine}\n${heavyBlocks}\n`, 'utf8');
        let zstBuf;
        if (i === 2) {
          const f1 = zlib.zstdCompressSync(Buffer.from(`${metaLine}\n`, 'utf8'));
          const f2 = zlib.zstdCompressSync(Buffer.from(`${heavyBlocks}\n`, 'utf8'));
          zstBuf = Buffer.concat([f1, f2]);
        } else {
          zstBuf = zlib.zstdCompressSync(payloadBuf);
        }
        assert.ok(zstBuf.length > 10 * 1024, `Codex scale fixture #${i} should be multi-KB compressed (got ${zstBuf.length})`);
        fs.writeFileSync(fPath, zstBuf);
        assignTime(fPath, { source_tool: 'codex', session_id: id, cwd: `D:\\Work\\ScaleProj${i}` });
      }

      for (let i = 1; i <= 10; i++) {
        const id = `rollout-2026-11-12T09-${String(i).padStart(2, '0')}-00-plain-${String(i).padStart(3, '0')}`;
        const fPath = path.join(codexSessions, `${id}.jsonl`);
        const lines = [
          JSON.stringify({ type: 'session_meta', payload: { session_id: `meta-plain-${i}`, cwd: `D:\\Work\\Plain${i}`, source: 'cli' } }),
          JSON.stringify({ type: 'event_msg', payload: { type: 'user_message', message: `plain-${i}` } })
        ].join('\n') + '\n';
        fs.writeFileSync(fPath, lines, 'utf8');
        assignTime(fPath, { source_tool: 'codex', session_id: id, cwd: `D:\\Work\\Plain${i}` });
      }

      // Codex 被过滤样本 (6 个): 2 subagent + 2 empty (plain/zst) + 1 active unclosed + 1 corrupt zst
      const cdxSub1 = path.join(codexSessions, 'rollout-sub-1.jsonl');
      fs.writeFileSync(cdxSub1, `${JSON.stringify({ type: 'session_meta', payload: { session_id: 'sub-1', source: { subagent: 'review' } } })}\n${JSON.stringify({ type: 'user', content: 'x' })}\n`, 'utf8');
      assignTime(cdxSub1, null);

      const cdxSub2 = path.join(codexArchived, 'rollout-sub-2.jsonl.zst');
      fs.writeFileSync(cdxSub2, zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session_meta', payload: { session_id: 'sub-2', source: 'subagent_worker' } })}\n${JSON.stringify({ type: 'user', content: 'y' })}\n`, 'utf8')));
      assignTime(cdxSub2, null);

      const cdxEmpty1 = path.join(codexSessions, 'rollout-empty-1.jsonl');
      fs.writeFileSync(cdxEmpty1, `${JSON.stringify({ type: 'session_meta', payload: { session_id: 'empty-1', source: 'cli' } })}\n`, 'utf8');
      assignTime(cdxEmpty1, null);

      const cdxEmpty2 = path.join(codexArchived, 'rollout-empty-2.jsonl.zst');
      fs.writeFileSync(cdxEmpty2, zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session_meta', payload: { session_id: 'empty-2', source: 'cli' } })}\n`, 'utf8')));
      assignTime(cdxEmpty2, null);

      const cdxActive = path.join(codexSessions, 'rollout-active-1.jsonl');
      fs.writeFileSync(cdxActive, `${JSON.stringify({ type: 'session_meta', payload: { session_id: 'active-1', source: 'cli' } })}\n{"type":"event_msg","partial":`, 'utf8');
      assignTime(cdxActive, null);

      const cdxCorrupt = path.join(codexArchived, 'rollout-corrupt-1.jsonl.zst');
      fs.writeFileSync(cdxCorrupt, Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x00, 0x99, 0x88]));
      assignTime(cdxCorrupt, null);

      // 2) Antigravity: 15 个已完成主会话 + 3 个被过滤样本
      for (let i = 1; i <= 15; i++) {
        const id = `agy-scale-${String(i).padStart(3, '0')}`;
        const logsDir = path.join(agyBrain, id, '.system_generated', 'logs');
        fs.mkdirSync(logsDir, { recursive: true });
        const trPath = path.join(logsDir, 'transcript.jsonl');
        fs.writeFileSync(
          trPath,
          `${JSON.stringify({ step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', content: `agy-${i}` })}\n${JSON.stringify({ step_index: 2, type: 'PLANNER_RESPONSE', content: 'ok' })}\n`,
          'utf8'
        );
        if (i % 3 === 0) {
          fs.writeFileSync(path.join(logsDir, 'transcript_full.jsonl'), `${JSON.stringify({ step_index: 1, type: 'USER_INPUT', content: 'full' })}\n`, 'utf8');
        }
        assignTime(trPath, { source_tool: 'antigravity', session_id: id });
      }
      const agySub = path.join(agyBrain, 'agy-sub-001', '.system_generated', 'logs', 'transcript.jsonl');
      fs.mkdirSync(path.dirname(agySub), { recursive: true });
      fs.writeFileSync(agySub, `${JSON.stringify({ type: 'SYSTEM_MESSAGE', source: 'SYSTEM_SDK', content: 'sub' })}\n`, 'utf8');
      assignTime(agySub, null);

      const agyEmpty = path.join(agyBrain, 'agy-empty-001', '.system_generated', 'logs', 'transcript.jsonl');
      fs.mkdirSync(path.dirname(agyEmpty), { recursive: true });
      fs.writeFileSync(agyEmpty, '  \n\n', 'utf8');
      assignTime(agyEmpty, null);

      const agyActive = path.join(agyBrain, 'agy-active-001', '.system_generated', 'logs', 'transcript.jsonl');
      fs.mkdirSync(path.dirname(agyActive), { recursive: true });
      fs.writeFileSync(agyActive, `${JSON.stringify({ step_index: 1, type: 'USER_INPUT', content: 'start' })}\n{"step_index":2,"half":`, 'utf8');
      assignTime(agyActive, null);

      // 3) DSH: 15 个多帧 .v4.jsonl.zstd 主会话 + 3 个被过滤样本
      for (let i = 1; i <= 15; i++) {
        const id = `dsh-scale-${String(i).padStart(3, '0')}`;
        const fPath = path.join(dshSessions, `--D-Scale-Proj-${i}--`, id, 'session.v4.jsonl.zstd');
        fs.mkdirSync(path.dirname(fPath), { recursive: true });
        const f1 = zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session', version: 4, id, cwd: `D:\\Scale\\Proj${i}`, delegationDepth: 0 })}\n`, 'utf8'));
        const f2 = zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'user/message', data: { content: `dsh-${i}` } })}\n`, 'utf8'));
        fs.writeFileSync(fPath, Buffer.concat([f1, f2]));
        assignTime(fPath, { source_tool: 'dsh', session_id: id });
      }
      const dshSub = path.join(dshSessions, '--D-Scale--', 'dsh-sub-001', 'session.v4.jsonl.zstd');
      fs.mkdirSync(path.dirname(dshSub), { recursive: true });
      fs.writeFileSync(dshSub, zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session', version: 4, delegationDepth: 1 })}\n${JSON.stringify({ type: 'user/message', data: { content: 'sub' } })}\n`, 'utf8')));
      assignTime(dshSub, null);

      const dshEmpty = path.join(dshSessions, '--D-Scale--', 'dsh-empty-001', 'session.v4.jsonl.zstd');
      fs.mkdirSync(path.dirname(dshEmpty), { recursive: true });
      fs.writeFileSync(dshEmpty, Buffer.concat([
        zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session', version: 4, delegationDepth: 0 })}\n`, 'utf8')),
        buildSkippableZstdFrame('skip-tail')
      ]));
      assignTime(dshEmpty, null);

      const dshCorrupt = path.join(dshSessions, '--D-Scale--', 'dsh-corrupt-001', 'session.v4.jsonl.zstd');
      fs.mkdirSync(path.dirname(dshCorrupt), { recursive: true });
      fs.writeFileSync(dshCorrupt, Buffer.concat([
        zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session', version: 4, delegationDepth: 0 })}\n`, 'utf8')),
        Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x77])
      ]));
      assignTime(dshCorrupt, null);

      // 4) 验证冷/热扫描性能、精确 totalCount (65)、全局 updated_at 降序排序与全部过滤原因 (75)
      const listOpts = {
        codexHome: codexSessions,
        codexArchivedDir: codexArchived,
        antigravityBrainDir: agyBrain,
        dshHome: dshSessions
      };
      const tCold0 = performance.now();
      const coldList = listDiscoverableSessions(listOpts);
      const coldMs = performance.now() - tCold0;

      const tWarm0 = performance.now();
      const warmList = listDiscoverableSessions(listOpts);
      const warmMs = performance.now() - tWarm0;

      assert.equal(coldList.length, 65);
      assert.deepEqual(warmList, coldList);
      assert.ok(warmMs <= coldMs + 20, `warmMs (${warmMs.toFixed(1)}) should not exceed coldMs (${coldMs.toFixed(1)})`);
      assert.ok(coldMs < 5000, `cold scale scan should stay well under 5s (got ${coldMs.toFixed(1)}ms)`);

      const expectedSortedIds = [...expectedMain]
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .map(x => `${x.source_tool}:${x.session_id}`);
      const actualSortedIds = coldList.map(x => `${x.source_tool}:${x.session_id}`);
      assert.deepEqual(actualSortedIds, expectedSortedIds, '跨三端与 .jsonl/.zst 必须严格按 updated_at 全局降序排列');

      const withFiltered = listDiscoverableSessions({ ...listOpts, includeFiltered: true });
      assert.equal(withFiltered.length, 77);
      const reasonById = new Map(withFiltered.map(s => [s.session_id, s.filtered_reason || null]));
      assert.equal(reasonById.get('rollout-sub-1'), 'subagent_session');
      assert.equal(reasonById.get('rollout-sub-2'), 'subagent_session');
      assert.equal(reasonById.get('rollout-empty-1'), 'empty_session');
      assert.equal(reasonById.get('rollout-empty-2'), 'empty_session');
      assert.equal(reasonById.get('rollout-active-1'), 'active_unclosed_session');
      assert.equal(reasonById.get('rollout-corrupt-1'), 'corrupt_session');
      assert.equal(reasonById.get('agy-sub-001'), 'subagent_session');
      assert.equal(reasonById.get('agy-empty-001'), 'empty_session');
      assert.equal(reasonById.get('agy-active-001'), 'active_unclosed_session');
      assert.equal(reasonById.get('dsh-sub-001'), 'delegated_subagent_session');
      assert.equal(reasonById.get('dsh-empty-001'), 'empty_session');
      assert.equal(reasonById.get('dsh-corrupt-001'), 'corrupt_session');

      // 5) 通过 CLI 验证真实默认目录布局下的 --limit 不影响 totalCount，且只读命令零改动 Vault/Data
      const cliEnv = {
        ...process.env,
        USERPROFILE: fakeHome,
        HOME: fakeHome,
        AGENT_MEMORY_VAULT: vaultPath,
        AGENT_MEMORY_DATA: dataPath
      };
      delete cliEnv.AGENT_MEMORY_CODEX_HOME;
      delete cliEnv.AGENT_MEMORY_ANTIGRAVITY_BRAIN_DIR;
      delete cliEnv.AGENT_MEMORY_DSH_HOME;

      const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');
      const dbBefore = fs.readFileSync(dbPath);
      const cliAll = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'list-sessions', '--source', 'all', '--limit', '10', '--json'], { env: cliEnv, encoding: 'utf8' }));
      assert.equal(cliAll.totalCount, 65);
      assert.equal(cliAll.count, 10);
      assert.equal(cliAll.sessions.length, 10);
      assert.deepEqual(
        cliAll.sessions.map(s => `${s.source_tool}:${s.session_id}`),
        expectedSortedIds.slice(0, 10)
      );
      const cliCodex = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'list-sessions', '--source', 'codex', '--limit', '5', '--json'], { env: cliEnv, encoding: 'utf8' }));
      assert.equal(cliCodex.totalCount, 35);
      assert.equal(cliCodex.count, 5);
      assert.equal(Buffer.compare(fs.readFileSync(dbPath), dbBefore), 0, 'list-sessions 绝不可写入或改动 state.sqlite');

      // 6) size/mtime 变更时的缓存失效验证：把最旧一条 Codex .zst 改为 subagent 且更新 mtime 为最新；把最后一条 DSH 改为最新 mtime
      const mutatedCdxPath = path.join(codexSessions, 'rollout-2026-11-12T09-10-00-plain-010.jsonl');
      fs.writeFileSync(mutatedCdxPath, `${JSON.stringify({ type: 'session_meta', payload: { session_id: 'plain-10-now-sub', source: { subagent: 'worker' } } })}\n${JSON.stringify({ type: 'user', content: 'z' })}\n`, 'utf8');
      const newerTime = new Date(Date.UTC(2026, 10, 12, 14, 0, 0));
      fs.utimesSync(mutatedCdxPath, newerTime, newerTime);

      const mutatedDshPath = path.join(dshSessions, '--D-Scale-Proj-15--', 'dsh-scale-015', 'session.v4.jsonl.zstd');
      const newestTime = new Date(Date.UTC(2026, 10, 12, 15, 0, 0));
      fs.utimesSync(mutatedDshPath, newestTime, newestTime);

      const afterInvalidation = listDiscoverableSessions(listOpts);
      assert.equal(afterInvalidation.length, 64, '改为 subagent 后缓存必须失效并使 totalCount 立即降为 64');
      assert.equal(afterInvalidation[0].source_tool, 'dsh');
      assert.equal(afterInvalidation[0].session_id, 'dsh-scale-015', 'mtime 更新后 DSH 会话必须跃升至全局排序首位');

      const zstMutatedPath = path.join(codexArchived, 'rollout-2026-11-12T10-15-00-zst-015.jsonl.zst');
      fs.writeFileSync(zstMutatedPath, zlib.zstdCompressSync(Buffer.from(`${JSON.stringify({ type: 'session_meta', payload: { session_id: 'zst-15-now-empty', source: 'vscode' } })}\n`, 'utf8')));
      const zstNewTime = new Date(Date.UTC(2026, 10, 12, 16, 0, 0));
      fs.utimesSync(zstMutatedPath, zstNewTime, zstNewTime);
      const afterZstInvalidation = listDiscoverableSessions(listOpts);
      assert.equal(afterZstInvalidation.length, 63, 'Codex .zst 变更为空会话后缓存必须失效并降为 63');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('18. [Zstd Prefix Edge Cases & CLI Help] 分块跨边界多字节 CJK/BOM/CRLF、skippable-only/截断异常与 mem --help 敏感度提示', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v25-zstd-help-'));
    try {
      // (a) 跨解压块边界多字节 CJK + UTF-8 BOM + CRLF + 超 64KB 首行
      const bigCjkLine = JSON.stringify({ type: 'session_meta', payload: { note: '中文边界'.repeat(18000) } });
      const line2 = JSON.stringify({ type: 'user', content: '第二行CRLF内容' });
      const line3 = JSON.stringify({ type: 'assistant', content: '第三行无尾换行' });
      const bomPayload = Buffer.concat([
        Buffer.from([0xef, 0xbb, 0xbf]),
        Buffer.from(`${bigCjkLine}\r\n\r\n${line2}\r\n${line3}`, 'utf8')
      ]);
      const cjkZst = path.join(root, 'cjk-bom-crlf.jsonl.zst');
      fs.writeFileSync(cjkZst, zlib.zstdCompressSync(bomPayload));
      const parsed = readZstdPrefixLinesFromFile(cjkZst, 4);
      assert.equal(parsed.lines.length, 3);
      assert.equal(parsed.lines[0], bigCjkLine);
      assert.equal(parsed.lines[1], line2);
      assert.equal(parsed.lines[2], line3);
      assert.equal(parsed.hasMoreFrames, false);

      // (b) 仅含 skippable frame 与截断帧处理（含多帧截断 1..4 字节）
      const skipOnly = path.join(root, 'skip-only.jsonl.zst');
      fs.writeFileSync(skipOnly, buildSkippableZstdFrame('only-skippable'));
      const skipRes = readZstdPrefixLinesFromFile(skipOnly, 4);
      assert.deepEqual(skipRes.lines, []);
      assert.equal(skipRes.hasMoreFrames, false);

      const truncZst = path.join(root, 'trunc.jsonl.zst');
      const fullZ = zlib.zstdCompressSync(Buffer.from('{"type":"user"}\n', 'utf8'));
      fs.writeFileSync(truncZst, fullZ.subarray(0, Math.max(4, fullZ.length - 3)));
      assert.throws(() => readZstdPrefixLinesFromFile(truncZst, 4));

      const f1 = zlib.zstdCompressSync(Buffer.from('{"type":"session_meta","payload":{"session_id":"mf-trunc"}}\n', 'utf8'));
      const f2 = zlib.zstdCompressSync(Buffer.from('{"type":"user","content":"frame2"}\n', 'utf8'));
      for (const cutLen of [1, 2, 3, 4]) {
        const mfTruncPath = path.join(root, `mf-trunc-${cutLen}.jsonl.zst`);
        fs.writeFileSync(mfTruncPath, Buffer.concat([f1, f2.subarray(0, cutLen)]));
        assert.throws(() => readZstdPrefixLinesFromFile(mfTruncPath, 4));
        const meta = inspectCodexSessionMetadata(mfTruncPath);
        assert.equal(meta.corrupt, true);
        assert.equal(meta.filteredReason, 'corrupt_session');
      }

      // (c) 小文件 maxLines=1 hasMoreFrames 精确判断 + 32MB 解压上限不得误判为空会话
      const twoLineSmall = path.join(root, 'two-line-small.jsonl.zst');
      fs.writeFileSync(
        twoLineSmall,
        zlib.zstdCompressSync(Buffer.from('{"type":"session_meta","payload":{"id":"s1"}}\n{"type":"user","content":"u1"}\n', 'utf8'))
      );
      const smallTwoRes = readZstdPrefixLinesFromFile(twoLineSmall, 1);
      assert.equal(smallTwoRes.lines.length, 1);
      assert.equal(smallTwoRes.hasMoreFrames, true, '小文件命满 maxLines=1 后仍有非空行时 hasMoreFrames 必须为 true');

      const oneLineWsSmall = path.join(root, 'one-line-ws-small.jsonl.zst');
      fs.writeFileSync(
        oneLineWsSmall,
        zlib.zstdCompressSync(Buffer.from('{"type":"session_meta","payload":{"id":"s2"}}\n  \r\n\t\n', 'utf8'))
      );
      const smallOneRes = readZstdPrefixLinesFromFile(oneLineWsSmall, 1);
      assert.equal(smallOneRes.lines.length, 1);
      assert.equal(smallOneRes.hasMoreFrames, false, '小文件仅 1 行加尾部空白时 hasMoreFrames 必须为 false');

      const bigCapZst = path.join(root, 'scan-cap-33mb.jsonl.zst');
      const capPayload = `{"type":"session_meta","payload":{"session_id":"cap-main","source":"vscode"}}\n{"type":"response_item","payload":"${'A'.repeat(33 * 1024 * 1024)}"}\n`;
      fs.writeFileSync(bigCapZst, zlib.zstdCompressSync(Buffer.from(capPayload, 'utf8')));
      const capPrefix = readZstdPrefixLinesFromFile(bigCapZst, 4);
      assert.equal(capPrefix.lines.length, 1);
      assert.equal(capPrefix.hasMoreFrames, true, '触及 32MB 解压扫描上限时 hasMoreFrames 必须为 true');
      const capMeta = inspectCodexSessionMetadata(bigCapZst);
      assert.equal(capMeta.isEmpty, false, '超 32MB 单行正文会话不得被误判为空会话');
      assert.equal(capMeta.isMainCompleted, true);

      // (d) 超 100KB 首行与末行纯文本 JSONL（Codex + Antigravity 完整闭合 vs 未闭合）
      const bigPad = 'X'.repeat(110 * 1024);
      const cdxHome = path.join(root, 'cdx-big');
      const cdxSessions = path.join(cdxHome, 'sessions', '2026', '11', '12');
      fs.mkdirSync(cdxSessions, { recursive: true });
      const cdxMainBig = path.join(cdxSessions, 'rollout-2026-11-12T10-00-00-big-main.jsonl');
      fs.writeFileSync(
        cdxMainBig,
        `${JSON.stringify({ type: 'session_meta', payload: { session_id: 'big-main', source: 'vscode', pad: bigPad } })}\n${JSON.stringify({ type: 'user', content: bigPad })}\n`,
        'utf8'
      );
      const cdxActiveBig = path.join(cdxSessions, 'rollout-2026-11-12T10-01-00-big-active.jsonl');
      fs.writeFileSync(
        cdxActiveBig,
        `${JSON.stringify({ type: 'session_meta', payload: { session_id: 'big-active', source: 'vscode', pad: bigPad } })}\n{"type":"user","content":"${bigPad}`,
        'utf8'
      );
      const cdxList = discoverCodexSessions({ codexHome: cdxHome, includeFiltered: true });
      const cdxMainFound = cdxList.find(s => s.session_id.includes('big-main'));
      const cdxActiveFound = cdxList.find(s => s.session_id.includes('big-active'));
      assert.equal(cdxMainFound?.filtered_reason, undefined);
      assert.equal(cdxActiveFound?.filtered_reason, 'active_unclosed_session');

      const agyRoot = path.join(root, 'agy-big');
      const agyMainDir = path.join(agyRoot, 'agy-big-main', '.system_generated', 'logs');
      const agyActiveDir = path.join(agyRoot, 'agy-big-active', '.system_generated', 'logs');
      fs.mkdirSync(agyMainDir, { recursive: true });
      fs.mkdirSync(agyActiveDir, { recursive: true });
      fs.writeFileSync(
        path.join(agyMainDir, 'transcript.jsonl'),
        `${JSON.stringify({ type: 'USER_INPUT', source: 'USER', content: bigPad })}\n${JSON.stringify({ type: 'PLANNER_RESPONSE', content: bigPad })}\n`,
        'utf8'
      );
      fs.writeFileSync(
        path.join(agyActiveDir, 'transcript.jsonl'),
        `${JSON.stringify({ type: 'USER_INPUT', source: 'USER', content: bigPad })}\n{"type":"PLANNER_RESPONSE","content":"${bigPad}`,
        'utf8'
      );
      const agyList = discoverAntigravitySessions({ antigravityBrainDir: agyRoot, includeFiltered: true });
      assert.equal(agyList.find(s => s.session_id === 'agy-big-main')?.filtered_reason, undefined);
      assert.equal(agyList.find(s => s.session_id === 'agy-big-active')?.filtered_reason, 'active_unclosed_session');

      // (e) mem --help 中 mem ingest 必须明确包含 --sensitivity 与 [--approval <id>]
      const helpOut = execFileSync(process.execPath, [CLI_PATH, '--help'], { encoding: 'utf8' });
      const ingestHelpLine = helpOut.split(/\r?\n/).find(l => l.includes('mem ingest'));
      assert.ok(ingestHelpLine, 'mem --help 必须包含 mem ingest 用法行');
      assert.ok(ingestHelpLine.includes('--sensitivity <synthetic|approved_low_sensitivity|confidential>'));
      assert.ok(ingestHelpLine.includes('[--approval <id>]'));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
