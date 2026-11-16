import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { initRepository } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import {
  acquireWriteLock,
  releaseWriteLock,
  recoverStaleWriteLock
} from '../src/storage/write-lock.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';
import { confirmDeleteNote } from '../src/tombstone/tracker.mjs';
import { restoreNote } from '../src/storage/restore-manager.mjs';
import {
  initGitRepo,
  assertVaultGitNoRemote,
  isWhitelistedEngineeringPath,
  validateEngineeringCommitPaths,
  validateExternalExportNotes,
  commitPublishedFile
} from '../src/git/repo-manager.mjs';
import { createConsistentBackup, restoreFromBackup } from '../src/backup/backup-manager.mjs';
import {
  ingestSession,
  resolveProjectFromMap,
  listDiscoverableSessions,
  locateSnapshotEvent
} from '../src/ingest/session-ingestor.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { runMultiHostIsolationMatrix, PROTECTED_SURFACES } from '../src/security/isolation-sentinel.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

function createTempEnv(prefix = 'v25-test-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const vaultPath = path.join(root, 'AgentMemory');
  const dataPath = path.join(root, 'AgentMemory-Data');
  initRepository({
    vaultPath,
    dataPath,
    initialProjects: [
      {
        project: 'SampleProject',
        paths: ['C:\\Work\\sample-project', vaultPath],
        git_roots: ['C:\\Work\\sample-project'],
        workspace_slugs: ['sample-project', '--C-Work-sample-project--']
      }
    ]
  });
  return { root, vaultPath, dataPath, dbPath: path.join(dataPath, 'runtime', 'state.sqlite') };
}

describe('V2.5 终审闭环测试套件: 写锁恢复防撞车、revisions 完整备份、工程白名单、三端接入与三类门禁分离', () => {
  test('1. [第6轮修复1] write.lock 互斥、禁止普通进程删陈旧锁、及 mem recover-lock 持正常 write.lock 防恢复期撞车', () => {
    const { vaultPath, dataPath, dbPath } = createTempEnv('v25-lock-');
    const lockPath = path.join(dataPath, 'runtime', 'write.lock');

    // (a) 正常获取与校验 lock_token 释放
    const lock1 = acquireWriteLock({ dataPath, command: 'publish', hostTool: 'codex' });
    assert.ok(fs.existsSync(lockPath));
    assert.equal(lock1.payload.host_tool, 'codex');
    // 伪造 token 无法释放锁
    assert.equal(releaseWriteLock({ lockPath, lockToken: 'wlk-wrong-token' }), false);
    assert.ok(fs.existsSync(lockPath));
    // 正确 token 成功释放
    assert.equal(lock1.release(), true);
    assert.ok(!fs.existsSync(lockPath));

    // (b) 模拟崩溃遗留陈旧 write.lock (PID 99999999 不存在)
    fs.writeFileSync(
      lockPath,
      JSON.stringify({
        pid: 99999999,
        host_tool: 'dsh',
        command: 'publish',
        acquired_at: new Date().toISOString(),
        hostname: os.hostname(),
        lock_token: 'wlk-stale-dead-pid'
      }),
      'utf8'
    );

    // 普通写进程遇到死进程陈旧锁时，严禁擅自删除 write.lock，必须立即抛出 ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY
    assert.throws(
      () => acquireWriteLock({
        dataPath,
        command: 'stage-candidate',
        isPidAliveFn: () => false
      }),
      (err) => err.code === 'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY'
    );
    assert.ok(fs.existsSync(lockPath), '普通写进程严禁自行删除陈旧 write.lock');

    // (c) 若锁持有进程仍存活，mem recover-lock 严禁强制接管
    assert.throws(
      () => recoverStaleWriteLock({
        vaultPath,
        dataPath,
        isPidAliveFn: () => true
      }),
      (err) => err.code === 'ERR_WRITE_LOCK_ACTIVE_CANNOT_RECOVER'
    );

    // (d) 模拟未完成 R1 linking 意图，并验证 recoverStaleWriteLock 在恢复期间必须持有正常 write.lock，阻止并发写进程插入撞车
    const db = openExistingDatabase(dbPath);
    const stgDir = path.join(dataPath, 'staging');
    const noteId = 'KN-019316a8-lock-7000-8000-000000000001';
    const noteContent = `---
schema_version: 1
id: "${noteId}"
note_type: "playbook"
title: "写锁恢复防撞车验证"
project: "LockProj"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env:
  os: "windows"
created_at: "2026-11-10T10:00:00Z"
---

# 写锁恢复防撞车验证
`;
    const staged = stageCandidate({ stagingDir: stgDir, outputUuid: noteId, content: noteContent, validateSchema: true });
    const targetPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-000001_写锁恢复防撞车验证.md');
    const nowIso = new Date().toISOString();
    db.prepare(`
      INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'linking', ?, ?)
    `).run('op-crash-during-link', noteId, staged.stagingPath, targetPath, staged.contentSha256, nowIso, nowIso);
    db.close();

    let concurrentWriterBlockedDuringRecovery = false;
    const recResult = recoverStaleWriteLock({
      vaultPath,
      dataPath,
      isPidAliveFn: (pid) => pid === process.pid,
      duringRecoveryHook: ({ activeWriteLockPath, activeLockToken }) => {
        // 验证：恢复期间正常 write.lock 必须存在且归属当前恢复进程
        assert.ok(fs.existsSync(activeWriteLockPath), '恢复期间必须持有正常 runtime/write.lock');
        assert.ok(activeLockToken.startsWith('wlk-'));

        // 此时若另一个正常写进程尝试获取 write.lock，必须因锁被恢复者持有而等待超时被拦截
        try {
          acquireWriteLock({
            dataPath,
            command: 'concurrent-writer',
            timeoutMs: 80,
            retryIntervalMs: 20,
            isPidAliveFn: () => true
          });
        } catch (err) {
          if (err.code === 'ERR_WRITE_LOCK_TIMEOUT') {
            concurrentWriterBlockedDuringRecovery = true;
          }
        }
      }
    });

    assert.equal(concurrentWriterBlockedDuringRecovery, true, '恢复者在修改台账/文件期间必须以正常 write.lock 阻塞普通写进程');
    assert.equal(recResult.recovered, true);
    assert.equal(recResult.hadStaleLock, true);
    assert.ok(fs.existsSync(recResult.archivedLockPath), '陈旧锁必须归档至 runtime/stale-locks/');
    assert.equal(recResult.r1Recovery.count, 1);
    assert.ok(fs.existsSync(targetPath), 'R1 未决 linking 作业应被恢复发布至 Vault');
    assert.ok(!fs.existsSync(lockPath), '恢复完成后必须干净释放正常 write.lock');
  });

  test('2. [第6轮修复2] runtime/revisions/ 纳入完整持久化备份清单与灾难恢复验证', () => {
    const { root, vaultPath, dataPath, dbPath } = createTempEnv('v25-rev-bkp-');
    const db = openExistingDatabase(dbPath);
    const stgDir = path.join(dataPath, 'staging');
    const revisionsDir = path.join(dataPath, 'runtime', 'revisions');
    const noteId = 'KN-019316a8-revb-7000-8000-000000000002';
    const noteContent = `---
schema_version: 1
id: "${noteId}"
note_type: "playbook"
title: "Revisions备份恢复验证"
project: "BackupProj"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env:
  os: "windows"
created_at: "2026-11-10T10:00:00Z"
---

# Revisions备份恢复验证
这是保存在 runtime/revisions/ 中的历史版本正文。
`;
    const staged = stageCandidate({ stagingDir: stgDir, outputUuid: noteId, content: noteContent, validateSchema: true });
    const targetPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-000002_Revisions备份恢复验证.md');
    publishFile({
      db,
      operationId: 'op-rev-bkp-1',
      outputUuid: noteId,
      stagingPath: staged.stagingPath,
      vaultTargetPath: targetPath,
      contentSha256: staged.contentSha256,
      revisionsDir
    });

    // 删除该笔记（保留 runtime/revisions/<noteId>/rev-0001.md，且不依赖 .git）
    confirmDeleteNote({ db, noteId, revisionsDir });
    db.close();
    assert.ok(!fs.existsSync(targetPath));
    assert.ok(fs.existsSync(path.join(revisionsDir, noteId, 'rev-0001.md')));

    // 执行 R4 一致性完整备份
    const backupTargetDir = path.join(root, 'Backups');
    const bkp = createConsistentBackup({ vaultPath, dataPath, targetDir: backupTargetDir });
    assert.equal(bkp.status, 'complete');

    const manifest = JSON.parse(fs.readFileSync(bkp.manifestPath, 'utf8'));
    assert.equal(manifest.revisions_included, true);
    const hasRevFileInManifest = manifest.files.some(
      f => f.area === 'data' && f.rel_path === `runtime/revisions/${noteId}/rev-0001.md`
    );
    assert.equal(hasRevFileInManifest, true, 'backup-manifest.json 必须包含 runtime/revisions/ 下的历史快照文件');

    // 恢复到全新目录后，不依赖 Git 仅凭恢复的 runtime/revisions/ 成功执行单篇恢复
    const restoredVault = path.join(root, 'Restored-AgentMemory');
    const restoredData = path.join(root, 'Restored-AgentMemory-Data');
    const restoreRes = restoreFromBackup({
      backupDir: bkp.backupDir,
      newVaultPath: restoredVault,
      newDataPath: restoredData
    });
    assert.equal(restoreRes.restored, true);

    const restoredRevFile = path.join(restoredData, 'runtime', 'revisions', noteId, 'rev-0001.md');
    assert.ok(fs.existsSync(restoredRevFile), '恢复后的 Data 目录必须完整包含 runtime/revisions/ 历史版本');

    const restoredDb = openExistingDatabase(path.join(restoredData, 'runtime', 'state.sqlite'));
    try {
      const noteRow = restoredDb.prepare('SELECT * FROM notes WHERE id = ?').get(noteId);
      const revContent = fs.readFileSync(restoredRevFile, 'utf8');
      const singleRestore = restoreNote({
        db: restoredDb,
        noteId,
        revision: 'rev-0001',
        content: revContent,
        targetVaultPath: noteRow.path,
        stagingDir: path.join(restoredData, 'staging')
      });
      assert.equal(singleRestore.restored, true);
      assert.ok(fs.existsSync(noteRow.path), '从备份恢复的 runtime/revisions/ 应支持完整恢复已删笔记');
    } finally {
      restoredDb.close();
    }
  });

  test('3. [第5轮+第6轮修复3] 三类隐私与 Git 门禁职责分离及工程提交白名单校验', () => {
    const { root, vaultPath } = createTempEnv('v25-git-gates-');

    // 门禁类别 1：工程代码仓库白名单必须放行 package.json, .gitignore, .env.example, lockfiles 与 src/cli/tests/docs
    const engRoot = path.join(root, 'eng-repo');
    fs.mkdirSync(path.join(engRoot, 'src'), { recursive: true });
    fs.mkdirSync(path.join(engRoot, 'docs'), { recursive: true });
    fs.mkdirSync(path.join(engRoot, 'raw'), { recursive: true });
    fs.writeFileSync(path.join(engRoot, 'package.json'), '{"name":"mindloom"}\n', 'utf8');
    fs.writeFileSync(path.join(engRoot, '.gitignore'), 'node_modules/\n', 'utf8');
    fs.writeFileSync(path.join(engRoot, 'package-lock.json'), '{"lockfileVersion":3}\n', 'utf8');
    fs.writeFileSync(path.join(engRoot, 'README.md'), '# Engineering Repo\n', 'utf8');
    fs.writeFileSync(path.join(engRoot, 'docs', 'local-secret.md'), `---\nprivacy: "local_only"\n---\nSecret`, 'utf8');
    fs.writeFileSync(path.join(engRoot, 'raw', 'session.jsonl'), '{}', 'utf8');

    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'package.json')), true);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, '.gitignore')), true);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'package-lock.json')), true);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'pnpm-lock.yaml')), true);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'src', 'init.mjs')), true);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'src', 'egress', 'egress-controller.mjs')), true);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'egress', 'EGR-001.json')), false);
    assert.equal(isWhitelistedEngineeringPath(engRoot, path.join(engRoot, 'raw', 'session.jsonl')), false);

    const engCheckOk = validateEngineeringCommitPaths({
      repoRoot: engRoot,
      filePaths: ['package.json', '.gitignore', 'package-lock.json', 'README.md']
    });
    assert.equal(engCheckOk.valid, true, 'package.json、.gitignore 与锁文件无需笔记 privacy YAML 即可通过工程仓库门禁');

    const engCheckBlocked = validateEngineeringCommitPaths({
      repoRoot: engRoot,
      filePaths: ['package.json', 'docs/local-secret.md', 'raw/session.jsonl']
    });
    assert.equal(engCheckBlocked.valid, false);
    assert.equal(engCheckBlocked.blocked.length, 2, '含 privacy: local_only 的 Markdown 与 raw/ 必须被工程门禁拦截');

    // 门禁类别 2：Vault 本地 .git 允许 local_only 笔记与 首页.md / .base，但严禁配置任何 git remote
    initGitRepo(vaultPath);
    execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: vaultPath });
    execFileSync('git', ['config', 'user.name', 'Test User'], { cwd: vaultPath });

    const localOnlyNotePath = path.join(vaultPath, '30_Knowledge_Notes', 'Preferences', 'KN-20261110-local1_纯本地偏好.md');
    fs.writeFileSync(localOnlyNotePath, `---\nschema_version: 1\nid: "KN-local-1"\nnote_type: "preference"\ntitle: "纯本地偏好"\nproject: "Default"\nprivacy: "local_only"\nlifecycle: "active"\nevidence_level: "user_confirmed"\nreview_state: "accepted"\ncreated_at: "2026-11-10T10:00:00Z"\n---\n本地偏好`, 'utf8');

    const localCommitRes = commitPublishedFile({
      vaultDir: vaultPath,
      filePath: localOnlyNotePath,
      commitMessage: 'feat: commit local_only note to local vault git'
    });
    assert.equal(localCommitRes.success, true, 'Vault 本地 .git 允许提交 local_only 笔记以支持 mem restore');

    // 一旦在 Vault .git 添加 remote，门禁类别 2 立即阻断提交
    execFileSync('git', ['remote', 'add', 'origin', 'https://example.com/forbidden-vault-remote.git'], { cwd: vaultPath });
    assert.throws(
      () => assertVaultGitNoRemote(vaultPath),
      (err) => err.code === 'VAULT_GIT_REMOTE_FORBIDDEN'
    );
    const remoteBlockedRes = commitPublishedFile({
      vaultDir: vaultPath,
      filePath: path.join(vaultPath, '首页.md'),
      commitMessage: 'should fail due to remote'
    });
    assert.equal(remoteBlockedRes.success, false);
    assert.equal(remoteBlockedRes.gitState, 'failed');

    // 门禁类别 3：外部知识导出严格校验笔记 privacy == 'sanitized'，拦截 local_only 与非笔记文件
    const extCheck = validateExternalExportNotes({
      filePaths: [localOnlyNotePath, path.join(vaultPath, '首页.md')]
    });
    assert.equal(extCheck.valid, false);
    assert.equal(extCheck.blocked.length, 2);
  });

  test('4. [第5轮修复] Antigravity transcript_full.jsonl 三态拆分处理与 --project 兼容策略', () => {
    const { root, vaultPath, dataPath, dbPath } = createTempEnv('v25-agy-3way-');
    const db = openExistingDatabase(dbPath);

    try {
      const agyDir = path.join(root, 'agy-session-1');
      fs.mkdirSync(agyDir, { recursive: true });
      const transcriptPath = path.join(agyDir, 'transcript.jsonl');
      const fullPath = path.join(agyDir, 'transcript_full.jsonl');

      const line1 = JSON.stringify({
        step_index: 1,
        type: 'USER_INPUT',
        source: 'USER_EXPLICIT',
        created_at: '2026-11-10T10:00:00Z',
        content: '被截断的摘要...',
        extra_keep: 'keep_me',
        truncated_fields: ['content']
      });
      const line2 = JSON.stringify({
        step_index: 2,
        type: 'PLANNER_RESPONSE',
        source: 'MODEL',
        created_at: '2026-11-10T10:00:05Z',
        content: '第二条也被截断...',
        truncated_fields: ['content']
      });
      fs.writeFileSync(transcriptPath, `${line1}\n${line2}\n`, 'utf8');

      // 情况 1：读取期间伴随文件 transcript_full.jsonl 发生变动 -> 立即中止 (ERR_SOURCE_UNSTABLE)，零入库
      const unstableRes = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: transcriptPath,
        sourceTool: 'antigravity',
        sessionId: 'agy-conv-001',
        stabilityHook: (phase) => {
          if (phase === 'after') {
            fs.writeFileSync(fullPath, '{"step_index":1}\n', 'utf8');
          }
        }
      });
      assert.equal(unstableRes.status, 'skipped_unstable_file');
      assert.equal(unstableRes.errorCode, 'ERR_SOURCE_UNSTABLE');
      fs.unlinkSync(fullPath);

      // 情况 2：静态快照中第 1 条在 transcript_full.jsonl 精确匹配，第 2 条缺失 -> 仅复制第 1 条的 truncated_fields，第 2 条标为 truncation_unresolved
      const fullLine1 = JSON.stringify({
        step_index: 1,
        type: 'USER_INPUT',
        source: 'USER_EXPLICIT',
        created_at: '2026-11-10T10:00:00Z',
        content: '这是从 transcript_full 恢复的完整用户提问内容',
        extra_keep: 'should_not_overwrite_non_truncated_field'
      });
      fs.writeFileSync(fullPath, `${fullLine1}\n`, 'utf8');

      const staticIncompleteRes = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: transcriptPath,
        sourceTool: 'antigravity',
        sessionId: 'agy-conv-001',
        project: 'ExplicitLegacyProject'
      });
      assert.equal(staticIncompleteRes.status, 'ingested');
      assert.equal(staticIncompleteRes.project, 'ExplicitLegacyProject', '显式传入的 --project 必须直接保留，不得映射为 unmapped');
      assert.equal(staticIncompleteRes.coverage.unresolved_truncations, 1);
      assert.ok(staticIncompleteRes.anomalies.some(a => a.event_id === 2 && a.type === 'truncation_unresolved'));

      const readableMd = fs.readFileSync(staticIncompleteRes.readableSessionPath, 'utf8');
      assert.ok(readableMd.includes('这是从 transcript_full 恢复的完整用户提问内容'), '匹配成功的截断字段必须合入可读会话');
      assert.ok(readableMd.includes('[TRUNCATION_UNRESOLVED]'), '未消解截断事件必须显式标记');

      // 情况 3：仅伴随文件 transcript_full.jsonl 后续发生改动，补充/改变了已处理前缀 (1..2) 的实质内容 -> 生成新快照并标为 needs_reaudit
      const fullLine2Added = JSON.stringify({
        step_index: 2,
        type: 'PLANNER_RESPONSE',
        source: 'MODEL',
        created_at: '2026-11-10T10:00:05Z',
        content: '后续补齐的第二条完整回答内容'
      });
      fs.writeFileSync(fullPath, `${fullLine1}\n${fullLine2Added}\n`, 'utf8');

      const companionChangedRes = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: transcriptPath,
        sourceTool: 'antigravity',
        sessionId: 'agy-conv-001',
        project: 'ExplicitLegacyProject'
      });
      assert.equal(companionChangedRes.status, 'needs_reaudit', '伴随文件改动导致已处理前缀 1..K 规范哈希变化时必须标为 needs_reaudit');
      assert.equal(companionChangedRes.reason, 'prefix_hash_mismatch');

      // 验证 project-map.json 自动推导与未知/歧义路径归入 unmapped
      assert.equal(
        resolveProjectFromMap({
          dataDir: dataPath,
          explicitProject: 'auto',
          sessionHints: { cwd: 'C:\\Work\\sample-project\\src' }
        }),
        'SampleProject'
      );
      assert.equal(
        resolveProjectFromMap({
          dataDir: dataPath,
          explicitProject: 'auto',
          sessionHints: { cwd: 'C:\\Unknown\\Workspace' }
        }),
        'unmapped'
      );
    } finally {
      db.close();
    }
  });

  test('5. [第5轮+第6轮闭环] 知识笔记 sources 证据链自动推导 --source 过滤、B01 3×6 受保护面矩阵与三端会话发现定位', () => {
    const { root, vaultPath, dataPath, dbPath } = createTempEnv('v25-3x3-matrix-');
    const db = openExistingDatabase(dbPath);

    try {
      // 1. 准备 Codex、Antigravity、DSH 三端会话目录并验证 listDiscoverableSessions
      const codexDir = path.join(root, 'codex-home');
      const agyBrainDir = path.join(root, 'agy-brain', 'conv-agy-100', '.system_generated', 'logs');
      const dshDir = path.join(root, 'dsh-home', '--D-Document-Deepseek--', 'ses-dsh-100');
      fs.mkdirSync(codexDir, { recursive: true });
      fs.mkdirSync(agyBrainDir, { recursive: true });
      fs.mkdirSync(dshDir, { recursive: true });

      const codexFile = path.join(codexDir, 'ses-codex-100.jsonl');
      const agyFile = path.join(agyBrainDir, 'transcript.jsonl');
      const dshFile = path.join(dshDir, 'session.v4.jsonl.zstd');

      fs.writeFileSync(codexFile, JSON.stringify({ type: 'user', content: 'Codex 排查 Redis 6379 连接超时' }) + '\n', 'utf8');
      fs.writeFileSync(agyFile, JSON.stringify({ step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-10T11:00:00Z', content: 'Antigravity 审核 V2.5 写锁恢复协议' }) + '\n', 'utf8');
      fs.writeFileSync(dshFile, zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'assistant', content: 'DSH 验证 Redis 6379 线程池配置' }) + '\n', 'utf8')));

      const discoveredAll = listDiscoverableSessions({
        sourceTool: 'all',
        codexHome: codexDir,
        antigravityBrainDir: path.join(root, 'agy-brain'),
        dshHome: path.join(root, 'dsh-home')
      });
      assert.equal(discoveredAll.length, 3, '应自动发现 codex / antigravity / dsh 三端会话 (含 DSH .jsonl.zstd)');
      const discoveredDsh = discoveredAll.find(s => s.source_tool === 'dsh');
      assert.equal(discoveredDsh.session_id, 'ses-dsh-100');
      assert.equal(discoveredDsh.workspace_slug, '--D-Document-Deepseek--');

      // 2. 分别导入三端会话
      const ingCodex = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: codexFile,
        sourceTool: 'codex',
        sessionId: 'ses-codex-100',
        project: 'TriAgentProj'
      });
      const ingAgy = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: agyFile,
        sourceTool: 'antigravity',
        sessionId: 'conv-agy-100',
        project: 'TriAgentProj'
      });
      const ingDsh = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: dshFile,
        sourceTool: 'dsh',
        sessionId: 'ses-dsh-100',
        project: 'TriAgentProj'
      });

      const codexSesBase = path.basename(ingCodex.readableSessionPath);
      const agySesBase = path.basename(ingAgy.readableSessionPath);
      const dshSesBase = path.basename(ingDsh.readableSessionPath);

      // 验证三端 #^event-000001 跨快照精确定位
      for (const base of [codexSesBase, agySesBase, dshSesBase]) {
        const loc = locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir: dataPath,
          sourceLink: `[[10_Readable_Sessions/${base}#^event-000001]]`
        });
        assert.equal(loc.found, true);
      }

      // 3. 创建两张原子证据卡 (EV-codex 与 EV-dsh) 及一篇同时引用两者的 Playbook 知识笔记（不写冗余 source_tool）
      const stgDir = path.join(dataPath, 'staging');
      const evCodexId = 'EV-019316a8-cdx1-7000-8000-000000000101';
      const evDshId = 'EV-019316a8-dsh1-7000-8000-000000000102';
      const knMultiId = 'KN-019316a8-mult-7000-8000-000000000103';

      const evCodexFile = 'EV-20261110-000101_Codex超时证据.md';
      const evDshFile = 'EV-20261110-000102_DSH线程池证据.md';

      const stgEv1 = stageCandidate({
        stagingDir: stgDir,
        outputUuid: evCodexId,
        validateSchema: true,
        content: `---
schema_version: 1
id: "${evCodexId}"
note_type: "evidence"
title: "Codex超时证据"
project: "TriAgentProj"
privacy: "sanitized"
source_tool: "codex"
evidence_level: "observed"
sources:
  - "[[10_Readable_Sessions/${codexSesBase}#^event-000001]]"
created_at: "2026-11-10T11:10:00Z"
---
Codex 证据`
      });
      publishFile({
        db,
        operationId: 'op-ev-cdx',
        outputUuid: evCodexId,
        stagingPath: stgEv1.stagingPath,
        vaultTargetPath: path.join(vaultPath, '20_Evidence_Cards', evCodexFile),
        contentSha256: stgEv1.contentSha256
      });

      const stgEv2 = stageCandidate({
        stagingDir: stgDir,
        outputUuid: evDshId,
        validateSchema: true,
        content: `---
schema_version: 1
id: "${evDshId}"
note_type: "evidence"
title: "DSH线程池证据"
project: "TriAgentProj"
privacy: "sanitized"
source_tool: "dsh"
evidence_level: "observed"
sources:
  - "[[10_Readable_Sessions/${dshSesBase}#^event-000001]]"
created_at: "2026-11-10T11:11:00Z"
---
DSH 证据`
      });
      publishFile({
        db,
        operationId: 'op-ev-dsh',
        outputUuid: evDshId,
        stagingPath: stgEv2.stagingPath,
        vaultTargetPath: path.join(vaultPath, '20_Evidence_Cards', evDshFile),
        contentSha256: stgEv2.contentSha256
      });

      const stgKn = stageCandidate({
        stagingDir: stgDir,
        outputUuid: knMultiId,
        validateSchema: true,
        content: `---
schema_version: 1
id: "${knMultiId}"
note_type: "playbook"
title: "Redis 6379 跨端联合排障手册"
project: "TriAgentProj"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env:
  os: "windows"
sources:
  - "[[20_Evidence_Cards/${evCodexFile}]]"
  - "[[20_Evidence_Cards/${evDshFile}]]"
created_at: "2026-11-10T11:15:00Z"
---

# Redis 6379 跨端联合排障手册
结合 Codex 与 DSH 证据定位连接池耗尽问题。`
      });
      publishFile({
        db,
        operationId: 'op-kn-multi',
        outputUuid: knMultiId,
        stagingPath: stgKn.stagingPath,
        vaultTargetPath: path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-000103_Redis跨端联合排障手册.md'),
        contentSha256: stgKn.contentSha256
      });

      // 验证 --source codex 与 --source dsh 均能通过证据链推导命中该知识笔记，而 --source antigravity 不命中
      const hitCodex = searchKnowledge({
        db,
        vaultDir: vaultPath,
        query: 'Redis 6379',
        sourceTool: 'codex'
      });
      assert.equal(hitCodex.items.length, 1);
      assert.equal(hitCodex.items[0].id, knMultiId);
      assert.deepEqual(hitCodex.items[0].derived_source_tools.sort(), ['codex', 'dsh']);

      const hitDsh = searchKnowledge({
        db,
        vaultDir: vaultPath,
        query: 'Redis 6379',
        sourceTool: 'dsh'
      });
      assert.equal(hitDsh.items.length, 1);
      assert.equal(hitDsh.items[0].id, knMultiId);

      const hitAgy = searchKnowledge({
        db,
        vaultDir: vaultPath,
        query: 'Redis 6379',
        sourceTool: 'antigravity'
      });
      assert.equal(hitAgy.items.length, 0, '--source antigravity 应过滤掉仅引用 codex+dsh 证据的笔记');

      // 4. 验证 B01 三端宿主 × 6 类受保护面 (含 runtime/revisions/ 与 AgentMemory/.git/) 哨兵矩阵
      assert.equal(PROTECTED_SURFACES.length, 6);
      assert.ok(PROTECTED_SURFACES.includes('revisions'));
      assert.ok(PROTECTED_SURFACES.includes('vault_git_and_local_only'));

      const matrixDegraded = runMultiHostIsolationMatrix();
      assert.equal(matrixDegraded.allHostsStrongIsolated, false);
      assert.equal(matrixDegraded.hostReports.codex.mode, 'degraded_low_sensitivity_only');
      assert.equal(matrixDegraded.hostReports.antigravity.mode, 'degraded_low_sensitivity_only');
      assert.equal(matrixDegraded.hostReports.dsh.mode, 'degraded_low_sensitivity_only');

      const matrixStrong = runMultiHostIsolationMatrix({
        surfaceProbeFn: () => ({
          direct_file_read: true,
          general_shell_read: true,
          standalone_script_read: true
        })
      });
      assert.equal(matrixStrong.allHostsStrongIsolated, true);

      // 5. CLI mem list-sessions & mem recover-lock 端到端调用验证
      const cliEnv = {
        ...process.env,
        AGENT_MEMORY_VAULT: vaultPath,
        AGENT_MEMORY_DATA: dataPath,
        AGENT_MEMORY_CODEX_HOME: codexDir,
        AGENT_MEMORY_ANTIGRAVITY_BRAIN_DIR: path.join(root, 'agy-brain'),
        AGENT_MEMORY_DSH_HOME: path.join(root, 'dsh-home')
      };
      const listOut = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'list-sessions', '--json'], { env: cliEnv, encoding: 'utf8' })
      );
      assert.equal(listOut.count, 3);

      const recOut = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'recover-lock'], { env: cliEnv, encoding: 'utf8' })
      );
      assert.equal(recOut.recovered, true);
    } finally {
      db.close();
    }
  });
});
