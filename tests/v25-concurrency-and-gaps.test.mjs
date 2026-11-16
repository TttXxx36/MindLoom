import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { initRepository } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { initGitRepo, isWhitelistedEngineeringPath, isWhitelistedVaultPath } from '../src/git/repo-manager.mjs';
import { acquireWriteLock, recoverStaleWriteLock } from '../src/storage/write-lock.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';
import { acquirePublisherLock, createConsistentBackup, releasePublisherLock, restoreFromBackup } from '../src/backup/backup-manager.mjs';
import { buildSyntheticPilotCorpus } from '../src/benchmark/pilot-suite.synthetic.mjs';
import { runBenchmarkSuite } from '../src/benchmark/runner.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { collectAcceptanceReadiness } from '../src/verify/client-acceptance.mjs';
import { restoreNote } from '../src/storage/restore-manager.mjs';
import { scanAndSyncNotes } from '../src/tombstone/tracker.mjs';
import { ingestSession, listDiscoverableSessions } from '../src/ingest/session-ingestor.mjs';
import { detectResidualSecrets } from '../src/security/sanitizer.mjs';

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve('cli/mem.mjs');

function createEnv(prefix = 'v25-gap-') {
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
  return {
    root,
    vaultPath,
    dataPath,
    dbPath: path.join(dataPath, 'runtime', 'state.sqlite'),
    env: {
      ...process.env,
      AGENT_MEMORY_VAULT: vaultPath,
      AGENT_MEMORY_DATA: dataPath
    }
  };
}

function makeValidPlaybookContent(id, title, body = '测试正文') {
  return `---
schema_version: 1
id: "${id}"
note_type: "playbook"
title: "${title}"
project: "ConcProj"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env:
  os: "windows"
created_at: "2026-11-11T10:00:00+08:00"
---

# ${title}
${body}
`;
}

describe('V2.5 并发、半写锁恢复、--source auto、降级预览防护、D01 三端语料与 Gate 1 补全验证', () => {
  test('1. [A03] 三独立子进程并发 stage-candidate + publish 争夺 write.lock：零丢稿、零重复记账、零串味提交', async () => {
    const { root, vaultPath, dataPath, dbPath, env } = createEnv('v25-mp3-');
    try {
      initGitRepo(vaultPath);
      execFileSync('git', ['config', 'user.name', 'MP3'], { cwd: vaultPath });
      execFileSync('git', ['config', 'user.email', 'mp3@example.com'], { cwd: vaultPath });
      execFileSync('git', ['add', '首页.md'], { cwd: vaultPath });
      execFileSync('git', ['commit', '-m', 'init'], { cwd: vaultPath });

      // 准备 3 个不同 UUID 但刻意共享同一末 6 位与同标题的候选，同时压测 write.lock + R7 短文件名碰撞消歧
      const specs = [
        { id: 'KN-019316a8-0001-7000-8000-111111abcdef', op: 'op-mp-1', title: '三进程并发同题碰撞' },
        { id: 'KN-019316a8-0002-7000-8000-222222abcdef', op: 'op-mp-2', title: '三进程并发同题碰撞' },
        { id: 'KN-019316a8-0003-7000-8000-333333abcdef', op: 'op-mp-3', title: '三进程并发同题碰撞' }
      ];
      const candFiles = specs.map((s, idx) => {
        const f = path.join(root, `cand-${idx}.json`);
        fs.writeFileSync(
          f,
          JSON.stringify({ id: s.id, operation_id: s.op, content: makeValidPlaybookContent(s.id, s.title, `进程 ${idx + 1} 内容`) }),
          'utf8'
        );
        return { ...s, file: f };
      });

      // 3 个独立子进程同时 stage-candidate
      await Promise.all(
        candFiles.map(c => execFileAsync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', c.file], { env }))
      );
      // 3 个独立子进程同时 publish
      const pubResults = await Promise.all(
        candFiles.map(c => execFileAsync(process.execPath, [CLI_PATH, 'publish', '--operation', c.op], { env }))
      );
      assert.equal(pubResults.length, 3);
      for (const r of pubResults) {
        assert.ok(r.stdout.includes('[mem publish 成功]'));
      }

      const db = openExistingDatabase(dbPath, { readOnly: true });
      try {
        const rows = db.prepare('SELECT id, path FROM notes').all();
        assert.equal(rows.length, 3, '3 篇笔记必须全部入库且无重复或覆盖');
        const uniquePaths = new Set(rows.map(r => path.resolve(r.path)));
        assert.equal(uniquePaths.size, 3, 'R7 消歧后 3 篇物理文件路径必须全部唯一');
        for (const r of rows) {
          assert.ok(fs.existsSync(r.path), `已发布文件必须存在: ${r.path}`);
        }
      } finally {
        db.close();
      }

      // 验证 staging 已清空、write.lock 已释放、Vault Git 最近 3 次提交每次仅含 1 篇目标文件
      assert.equal(fs.readdirSync(path.join(dataPath, 'staging')).filter(f => f.startsWith('stg-')).length, 0);
      assert.equal(fs.existsSync(path.join(dataPath, 'runtime', 'write.lock')), false);
      const logHashes = execFileSync('git', ['log', '-n', '3', '--format=%H'], { cwd: vaultPath, encoding: 'utf8' })
        .trim()
        .split(/\r?\n/)
        .filter(Boolean);
      assert.equal(logHashes.length, 3);
      for (const h of logHashes) {
        const filesInCommit = execFileSync('git', ['show', '--name-only', '--format=', h], { cwd: vaultPath, encoding: 'utf8' })
          .trim()
          .split(/\r?\n/)
          .filter(Boolean);
        assert.equal(filesInCommit.length, 1, '每次提交仅允许包含单个发布文件');
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('2. [A03] 双并发等待者遇死锁不删锁、半写锁 (0字节/截断JSON) 识别与 mem recover-lock 恢复', async () => {
    const { root, vaultPath, dataPath, dbPath, env } = createEnv('v25-half-');
    try {
      const lockPath = path.join(dataPath, 'runtime', 'write.lock');

      // (a) 写入死 PID 陈旧锁，两个真实子进程并发尝试 stage-candidate：两者都必须报错停写且绝不删除 write.lock
      fs.writeFileSync(
        lockPath,
        JSON.stringify({
          pid: 99999991,
          host_tool: 'dsh',
          command: 'publish',
          acquired_at: new Date().toISOString(),
          hostname: os.hostname(),
          lock_token: 'wlk-dead-99999991'
        }),
        'utf8'
      );

      const candA = path.join(root, 'cand-a.json');
      const candB = path.join(root, 'cand-b.json');
      const idA = 'KN-019316a8-dead-7000-8000-0000000000a1';
      const idB = 'KN-019316a8-dead-7000-8000-0000000000b2';
      fs.writeFileSync(candA, JSON.stringify({ id: idA, operation_id: 'op-a', content: makeValidPlaybookContent(idA, '并发遇死锁A') }), 'utf8');
      fs.writeFileSync(candB, JSON.stringify({ id: idB, operation_id: 'op-b', content: makeValidPlaybookContent(idB, '并发遇死锁B') }), 'utf8');

      const [resA, resB] = await Promise.allSettled([
        execFileAsync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candA], { env }),
        execFileAsync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candB], { env })
      ]);
      assert.equal(resA.status, 'rejected');
      assert.equal(resB.status, 'rejected');
      assert.ok((resA.reason.stderr || '').includes('ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY'));
      assert.ok((resB.reason.stderr || '').includes('ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY'));
      assert.ok(fs.existsSync(lockPath), '并发等待进程均严禁自行删锁');

      // 执行 mem recover-lock 归档旧锁后，后续并发写正常成功
      const recCli = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'recover-lock'], { env, encoding: 'utf8' }));
      assert.equal(recCli.recovered, true);
      assert.equal(recCli.hadStaleLock, true);
      assert.equal(fs.existsSync(lockPath), false);

      await Promise.all([
        execFileAsync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candA], { env }),
        execFileAsync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candB], { env })
      ]);

      // (b) 半写锁测试：0 字节空锁与截断 JSON 锁均应在宽限期后报 ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY 且可被 recoverStaleWriteLock 归档恢复
      for (const brokenPayload of ['', '{"pid": 1234']) {
        fs.writeFileSync(lockPath, brokenPayload, 'utf8');
        assert.throws(
          () => acquireWriteLock({ dataPath, command: 'publish', timeoutMs: 1000, retryIntervalMs: 30 }),
          (err) => err.code === 'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY'
        );
        assert.ok(fs.existsSync(lockPath), '半写锁亦严禁由普通进程直接删除');

        const recHalf = recoverStaleWriteLock({ vaultPath, dataPath });
        assert.equal(recHalf.recovered, true);
        assert.equal(recHalf.hadStaleLock, true);
        assert.ok(fs.existsSync(recHalf.archivedLockPath));
        assert.equal(fs.existsSync(lockPath), false);
      }

      // (c) 验证 recoverStaleWriteLock 恢复 R1 linking 笔记时同时生成 runtime/revisions/ 快照
      const db = openExistingDatabase(dbPath);
      const r1Id = 'KN-019316a8-r1rv-7000-8000-0000000000c3';
      const stg = stageCandidate({ stagingDir: path.join(dataPath, 'staging'), outputUuid: r1Id, content: makeValidPlaybookContent(r1Id, 'R1恢复含Revisions') });
      const dst = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261111-0000c3_R1恢复含Revisions.md');
      db.prepare(`
        INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
        VALUES ('op-r1-rev', ?, ?, ?, ?, 'linking', datetime('now'), datetime('now'))
      `).run(r1Id, stg.stagingPath, dst, stg.contentSha256);
      fs.linkSync(stg.stagingPath, dst);
      db.close();

      const recR1 = recoverStaleWriteLock({ vaultPath, dataPath });
      assert.equal(recR1.r1Recovery.count, 1);
      assert.ok(fs.existsSync(path.join(dataPath, 'runtime', 'revisions', r1Id, 'rev-0001.md')));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('3. [B05] 发布进程与 mem backup 并发竞争 write.lock 保持 R4 一致性', async () => {
    const { root, vaultPath, dataPath, env } = createEnv('v25-pub-bkp-');
    try {
      const backupTarget = path.join(root, 'ExternalBackup');
      const id = 'KN-019316a8-bkp1-7000-8000-0000000000d4';
      const candFile = path.join(root, 'cand-bkp.json');
      fs.writeFileSync(candFile, JSON.stringify({ id, operation_id: 'op-bkp-race', content: makeValidPlaybookContent(id, '备份并发验证') }), 'utf8');
      execFileSync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candFile], { env });

      const [pubRes, bkpRes] = await Promise.all([
        execFileAsync(process.execPath, [CLI_PATH, 'publish', '--operation', 'op-bkp-race'], { env }),
        execFileAsync(process.execPath, [CLI_PATH, 'backup', '--target', backupTarget, '--json'], { env })
      ]);

      assert.ok(pubRes.stdout.includes('[mem publish 成功]'));
      const bkpJson = JSON.parse(bkpRes.stdout);
      assert.equal(bkpJson.status, 'complete');
      assert.equal(bkpJson.changedFiles.length, 0);

      const restRes = restoreFromBackup({
        backupDir: bkpJson.backupDir,
        newVaultPath: path.join(root, 'Restored-Vault'),
        newDataPath: path.join(root, 'Restored-Data')
      });
      assert.equal(restRes.verification.sqliteIntegrityOk, true);
      assert.equal(restRes.verification.checksumMismatches.length, 0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('4. CLI mem ingest --source auto 与 --source-file 自动推断 + mem doctor 源目录与恢复项诊断', () => {
    const { root, vaultPath, dataPath, env } = createEnv('v25-auto-src-');
    try {
      const codexHome = path.join(root, 'codex-sessions');
      const agyBrain = path.join(root, 'agy-brain');
      const dshHome = path.join(root, 'dsh-sessions');
      fs.mkdirSync(codexHome, { recursive: true });
      fs.mkdirSync(path.join(agyBrain, 'agy-auto-01', '.system_generated', 'logs'), { recursive: true });
      fs.mkdirSync(path.join(dshHome, '--C-Work-sample-project--', 'dsh-auto-01'), { recursive: true });

      const cdxFile = path.join(codexHome, 'rollout-2026-11-11T10-00-00-cdx-auto-01.jsonl');
      fs.writeFileSync(cdxFile, JSON.stringify({ type: 'session_meta', payload: { session_id: 'cdx-auto-01', cwd: 'C:\\Work\\sample-project', source: 'cli' } }) + '\n' + JSON.stringify({ type: 'user', content: 'codex auto' }) + '\n', 'utf8');

      const agyFile = path.join(agyBrain, 'agy-auto-01', '.system_generated', 'logs', 'transcript.jsonl');
      fs.writeFileSync(agyFile, JSON.stringify({ step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-11T10:00:00Z', content: 'agy auto' }) + '\n', 'utf8');

      const dshFile = path.join(dshHome, '--C-Work-sample-project--', 'dsh-auto-01', 'session.v4.jsonl.zstd');
      fs.writeFileSync(
        dshFile,
        Buffer.concat([
          zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'session', version: 4, id: 'dsh-auto-01' }) + '\n', 'utf8')),
          zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'user/message', data: { content: 'dsh auto' } }) + '\n', 'utf8'))
        ])
      );

      const cliEnv = {
        ...env,
        AGENT_MEMORY_CODEX_HOME: codexHome,
        AGENT_MEMORY_ANTIGRAVITY_BRAIN_DIR: agyBrain,
        AGENT_MEMORY_DSH_HOME: dshHome
      };

      // --source auto 自动发现并导入 DSH 与 Antigravity 会话
      const dshIng = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'ingest', '--source', 'auto', '--session', 'dsh-auto-01', '--sensitivity', 'synthetic'], { env: cliEnv, encoding: 'utf8' })
      );
      assert.equal(dshIng.status, 'ingested');
      assert.equal(dshIng.project, 'SampleProject');
      assert.ok(path.basename(dshIng.readableSessionPath).includes('-dsh-'));

      // --source auto 配合 --source-file 正确推断 antigravity
      const agyIng = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'ingest', '--source', 'auto', '--session', 'agy-auto-01', '--source-file', agyFile, '--sensitivity', 'synthetic'], { env: cliEnv, encoding: 'utf8' })
      );
      assert.equal(agyIng.status, 'ingested');
      assert.ok(path.basename(agyIng.readableSessionPath).includes('-antigravity-'));

      // mem doctor --json 正确输出三端源目录可达性与恢复项
      const docJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'doctor', '--json'], { env: cliEnv, encoding: 'utf8' }));
      assert.equal(docJson.ok, true);
      assert.equal(docJson.sourceRoots.codex.readable, true);
      assert.equal(docJson.sourceRoots.antigravity.readable, true);
      assert.equal(docJson.sourceRoots.dsh.readable, true);
      assert.equal(docJson.recoveringLockPresent, false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('5. mem restore 降级与缺失 privacy 防护：sanitized 历史后改标 local_only 严禁泄露预览', () => {
    const { root, vaultPath, dataPath, dbPath, env } = createEnv('v25-downgrade-');
    try {
      const db = openExistingDatabase(dbPath);
      const id = 'KN-019316a8-dgrd-7000-8000-0000000000e5';
      const initialContent = makeValidPlaybookContent(id, '降级敏感测试', '旧版看似脱敏的正文 secretToken12345');
      const stg = stageCandidate({ stagingDir: path.join(dataPath, 'staging'), outputUuid: id, content: initialContent });
      const targetPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261111-0000e5_降级敏感测试.md');
      publishFile({
        db,
        operationId: 'op-dgrd',
        outputUuid: id,
        stagingPath: stg.stagingPath,
        vaultTargetPath: targetPath,
        contentSha256: stg.contentSha256,
        revisionsDir: path.join(dataPath, 'runtime', 'revisions'),
        metadata: { note_type: 'playbook', title: '降级敏感测试', project: 'ConcProj', privacy: 'sanitized' }
      });

      // 用户后续将笔记降级为 local_only（无论磁盘还是 SQLite 台账）
      const downgradedMd = initialContent.replace('privacy: "sanitized"', 'privacy: "local_only"');
      fs.writeFileSync(targetPath, downgradedMd, 'utf8');
      db.prepare("UPDATE notes SET privacy = 'local_only' WHERE id = ?").run(id);
      db.close();

      // 提取最初为 sanitized 的 rev-0001 时，必须因为当前为 local_only 而被红牌脱敏！
      const restOut = execFileSync(process.execPath, [CLI_PATH, 'restore', id, '--revision', 'rev-0001'], { env, encoding: 'utf8' });
      assert.ok(restOut.includes('[REDACTED_LOCAL_ONLY]'));
      assert.equal(restOut.includes('降级敏感测试'), false);
      const previewFile = path.join(dataPath, 'staging', 'restore-preview', `${id}-rev-0001.md`);
      const previewText = fs.readFileSync(previewFile, 'utf8');
      assert.ok(previewText.includes('[REDACTED:'));
      assert.equal(previewText.includes('旧版看似脱敏的正文'), false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('6. [D01 & Gate 1] 探索语料三端全覆盖验证、tests/fixtures 白名单放行与验收就绪探针', () => {
    const { root, vaultPath, dataPath } = createEnv('v25-d01-gate1-');
    try {
      const benchRoot = path.join(root, 'bench');
      const corpusVault = path.join(benchRoot, 'AgentMemory');
      const corpusData = path.join(benchRoot, 'AgentMemory-Data');
      buildSyntheticPilotCorpus({ vaultDir: corpusVault, dataDir: corpusData });

      const db = openExistingDatabase(path.join(corpusData, 'runtime', 'state.sqlite'), { readOnly: true });
      try {
        // 分别按 codex / antigravity / dsh 过滤均应命中对应来源的试点笔记
        assert.ok(searchKnowledge({ db, vaultDir: corpusVault, query: '容器端口绑定失败', sourceTool: 'codex' }).items.length >= 1);
        assert.ok(searchKnowledge({ db, vaultDir: corpusVault, query: 'IP', project: 'ObsidianOps', sourceTool: 'antigravity' }).items.length >= 1);
        assert.ok(searchKnowledge({ db, vaultDir: corpusVault, query: '401', project: 'WebInfra', sourceTool: 'dsh' }).items.length >= 1);
      } finally {
        db.close();
      }

      const bmReport = runBenchmarkSuite({ suite: 'pilot', corpusDir: path.join(root, 'bench-run') });
      assert.deepEqual(bmReport.corpusSourceCoverage, ['antigravity', 'codex', 'dsh']);

      // Gate 1: 允许 tests/fixtures/*.jsonl(.zstd)，拦截非夹具位置的 .jsonl/.sqlite/.lock
      const fakeRepo = path.join(root, 'repo');
      assert.equal(isWhitelistedEngineeringPath(fakeRepo, path.join(fakeRepo, 'tests', 'fixtures', 'synth.jsonl')), true);
      assert.equal(isWhitelistedEngineeringPath(fakeRepo, path.join(fakeRepo, 'tests', 'fixtures', 'synth.jsonl.zstd')), true);
      assert.equal(isWhitelistedEngineeringPath(fakeRepo, path.join(fakeRepo, 'docs', 'leak.jsonl')), false);
      assert.equal(isWhitelistedEngineeringPath(fakeRepo, path.join(fakeRepo, 'tests', 'fixtures', 'bad.sqlite')), false);

      // 使用纯净的 Gate 1 临时工程仓验证 collectAcceptanceReadiness（同时确保 Vault 零 remote Git 通过检查）
      fs.mkdirSync(path.join(fakeRepo, 'src'), { recursive: true });
      fs.mkdirSync(path.join(fakeRepo, 'docs'), { recursive: true });
      fs.writeFileSync(path.join(fakeRepo, 'package.json'), '{"name":"clean-repo"}\n', 'utf8');
      fs.writeFileSync(path.join(fakeRepo, 'src', 'index.mjs'), 'export default 1;\n', 'utf8');
      fs.writeFileSync(path.join(fakeRepo, 'docs', 'spec.md'), '# Spec\n', 'utf8');
      execFileSync('git', ['init'], { cwd: fakeRepo });
      execFileSync('git', ['config', 'user.name', 'Test'], { cwd: fakeRepo });
      execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: fakeRepo });
      execFileSync('git', ['add', '.'], { cwd: fakeRepo });
      execFileSync('git', ['commit', '-m', 'init'], { cwd: fakeRepo });

      initGitRepo(vaultPath);
      const readiness = collectAcceptanceReadiness({
        repoRoot: fakeRepo,
        vaultDir: vaultPath,
        dataDir: dataPath
      });
      assert.equal(readiness.vault.allFourBasesPresent, true);
      assert.equal(readiness.vault.communityPluginsEmpty, true);
      assert.equal(readiness.vault.vaultGitZeroRemote, true);
      assert.equal(readiness.data.dbClean, true);
      assert.equal(readiness.data.rawToolDirsReady, true);
      assert.equal(readiness.data.revisionsDirPresent, true);
      assert.equal(readiness.data.projectMapValid, true);
      assert.equal(readiness.engineeringGate1.valid, true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('7. scanAndSyncNotes 覆盖四目录不误标会话/证据 missing，且执行单向隐私降级锁防 delete/restore 泄漏', () => {
    const { root, vaultPath, dataPath, dbPath, env } = createEnv('v25-sync-priv-');
    try {
      const codexHome = path.join(root, 'cdx');
      fs.mkdirSync(codexHome, { recursive: true });
      const srcFile = path.join(codexHome, 'rollout-2026-11-11T10-00-00-sync01.jsonl');
      fs.writeFileSync(srcFile, JSON.stringify({ type: 'user', content: 'sync test' }) + '\n', 'utf8');
      const cliEnv = { ...env, AGENT_MEMORY_CODEX_HOME: codexHome };
      const ingOut = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'ingest', '--source', 'codex', '--session', 'rollout-2026-11-11T10-00-00-sync01', '--sensitivity', 'synthetic'], { env: cliEnv, encoding: 'utf8' }));
      assert.equal(ingOut.status, 'ingested');

      // 发布证据卡 + sanitized 笔记（后改标 local_only）+ local_only 笔记（后被篡改为 sanitized）
      const evId = 'EV-019316a8-sync-7000-8000-000000000101';
      const knDownId = 'KN-019316a8-sync-7000-8000-000000000102';
      const knTamperId = 'KN-019316a8-sync-7000-8000-000000000103';

      const db = openExistingDatabase(dbPath);
      const sesBase = path.basename(ingOut.readableSessionPath);
      const evStg = stageCandidate({
        stagingDir: path.join(dataPath, 'staging'),
        outputUuid: evId,
        validateSchema: true,
        content: `---\nschema_version: 1\nid: "${evId}"\nnote_type: "evidence"\ntitle: "证据同步测试"\nproject: "ConcProj"\nprivacy: "sanitized"\nsource_tool: "codex"\nevidence_level: "observed"\nsources:\n  - "[[10_Readable_Sessions/${sesBase}#^event-000001]]"\ncreated_at: "2026-11-11T10:00:00+08:00"\n---\n证据\n`
      });
      publishFile({ db, operationId: 'op-sync-ev', outputUuid: evId, stagingPath: evStg.stagingPath, vaultTargetPath: path.join(vaultPath, '20_Evidence_Cards', 'EV-sync.md'), contentSha256: evStg.contentSha256 });

      const downPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261111-000102_磁盘降级测试秘密标题.md');
      const downOrig = makeValidPlaybookContent(knDownId, '磁盘降级测试秘密标题', '旧版本敏感内容');
      const downStg = stageCandidate({ stagingDir: path.join(dataPath, 'staging'), outputUuid: knDownId, content: downOrig });
      publishFile({
        db,
        operationId: 'op-sync-down',
        outputUuid: knDownId,
        stagingPath: downStg.stagingPath,
        vaultTargetPath: downPath,
        contentSha256: downStg.contentSha256,
        revisionsDir: path.join(dataPath, 'runtime', 'revisions')
      });

      const tamperPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261111-000103_防反向提权.md');
      const tamperOrig = makeValidPlaybookContent(knTamperId, '防反向提权', '机密正文').replace('privacy: "sanitized"', 'privacy: "local_only"');
      const tamperStg = stageCandidate({ stagingDir: path.join(dataPath, 'staging'), outputUuid: knTamperId, content: tamperOrig });
      publishFile({ db, operationId: 'op-sync-tamper', outputUuid: knTamperId, stagingPath: tamperStg.stagingPath, vaultTargetPath: tamperPath, contentSha256: tamperStg.contentSha256 });

      // 磁盘上：1) 将 sanitized 降级为 local_only；2) 企图把 local_only 篡改为 sanitized
      fs.writeFileSync(downPath, downOrig.replace('privacy: "sanitized"', 'privacy: "local_only"'), 'utf8');
      fs.writeFileSync(tamperPath, tamperOrig.replace('privacy: "local_only"', 'privacy: "sanitized"'), 'utf8');

      const syncReport = scanAndSyncNotes({ db, vaultDir: vaultPath });
      assert.equal(syncReport.missing.length, 0, '10_Readable_Sessions 与 20_Evidence_Cards 绝不可被误标为 missing');
      assert.equal(db.prepare("SELECT status FROM notes WHERE note_type = 'session'").get().status, 'active');
      assert.equal(db.prepare('SELECT status FROM notes WHERE id = ?').get(evId).status, 'active');
      assert.equal(db.prepare('SELECT privacy FROM notes WHERE id = ?').get(knDownId).privacy, 'local_only', '磁盘降级必须单向同步到 SQLite');
      assert.equal(db.prepare('SELECT privacy FROM notes WHERE id = ?').get(knTamperId).privacy, 'local_only', '绝不可从磁盘反向将 local_only 提权为 sanitized');
      db.close();

      // mem delete 预览即使在未先 reconcile 的情况也不可泄漏刚被磁盘降级的笔记标题/路径
      const delPreview = execFileSync(process.execPath, [CLI_PATH, 'delete', knDownId], { env, encoding: 'utf8' });
      assert.ok(delPreview.includes('[REDACTED_LOCAL_ONLY]'));
      assert.equal(delPreview.includes('磁盘降级测试秘密标题'), false);

      // 删除后恢复最初为 sanitized 的 rev-0001，同样必须保持脱敏拦截
      execFileSync(process.execPath, [CLI_PATH, 'delete', knDownId, '--confirm'], { env, encoding: 'utf8' });
      const restOut = execFileSync(process.execPath, [CLI_PATH, 'restore', knDownId, '--revision', 'rev-0001'], { env, encoding: 'utf8' });
      assert.ok(restOut.includes('[REDACTED_LOCAL_ONLY]'));
      assert.equal(restOut.includes('磁盘降级测试秘密标题'), false);
      const previewText = fs.readFileSync(path.join(dataPath, 'staging', 'restore-preview', `${knDownId}-rev-0001.md`), 'utf8');
      assert.ok(previewText.includes('[REDACTED:'));
      assert.equal(previewText.includes('旧版本敏感内容'), false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('8. restoreNote 防无 Frontmatter 磁盘绕过与 --revision 路径穿越 + mem publish / recover-lock Exit B 脱敏', () => {
    const { root, vaultPath, dataPath, dbPath, env } = createEnv('v25-exitb-sec-');
    try {
      const db = openExistingDatabase(dbPath);
      const stagingDir = path.join(dataPath, 'staging');
      const noFmId = 'KN-019316a8-nofm-7000-8000-000000000201';
      const noFmPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-nofm.md');
      fs.writeFileSync(noFmPath, '磁盘文件缺失 frontmatter，不得按 sanitized 放行', 'utf8');

      // 无 frontmatter 的磁盘文件 + --revision 路径穿越参数
      const rNoFm = restoreNote({
        db,
        noteId: noFmId,
        revision: '../../escape-attempt',
        content: makeValidPlaybookContent(noFmId, '无FM绕过测试', '不应该泄漏的内容'),
        targetVaultPath: noFmPath,
        stagingDir
      });
      assert.equal(rNoFm.redacted, true, '缺失 frontmatter/privacy 的磁盘文件必须触发脱敏');
      assert.ok(path.resolve(rNoFm.previewPath).startsWith(path.resolve(path.join(stagingDir, 'restore-preview'))));
      assert.equal(fs.existsSync(path.join(stagingDir, 'escape-attempt.md')), false);

      // mem publish 对 local_only 笔记必须隐藏含标题的路径
      const localId = 'KN-019316a8-locp-7000-8000-000000000202';
      const secretTitle = '绝对私密发布标题9988';
      const localMd = makeValidPlaybookContent(localId, secretTitle, '私密正文').replace('privacy: "sanitized"', 'privacy: "local_only"');
      const candPath = path.join(root, 'cand-local.json');
      fs.writeFileSync(candPath, JSON.stringify({ id: localId, operation_id: 'op-loc-pub', content: localMd }), 'utf8');
      execFileSync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candPath], { env, encoding: 'utf8' });
      const pubOut = execFileSync(process.execPath, [CLI_PATH, 'publish', '--operation', 'op-loc-pub'], { env, encoding: 'utf8' });
      assert.ok(pubOut.includes('[REDACTED_LOCAL_ONLY]'));
      assert.equal(pubOut.includes(secretTitle), false);

      // 模拟崩溃残留死 PID write.recovering.lock + 死 PID write.lock + local_only 的 R1 linking 意图
      const r1LocalId = 'KN-019316a8-r1lc-7000-8000-000000000203';
      const r1SecretTitle = 'R1崩溃恢复绝密标题7766';
      const r1LocalMd = makeValidPlaybookContent(r1LocalId, r1SecretTitle, 'R1私密正文').replace('privacy: "sanitized"', 'privacy: "local_only"');
      const r1Stg = stageCandidate({ stagingDir, outputUuid: r1LocalId, content: r1LocalMd });
      const r1Target = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', `KN-20261111-000203_${r1SecretTitle}.md`);
      db.prepare(`
        INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
        VALUES ('op-r1-local', ?, ?, ?, ?, 'linking', datetime('now'), datetime('now'))
      `).run(r1LocalId, r1Stg.stagingPath, r1Target, r1Stg.contentSha256);
      fs.linkSync(r1Stg.stagingPath, r1Target);
      db.close();

      fs.writeFileSync(path.join(dataPath, 'runtime', 'write.lock'), JSON.stringify({ pid: 99999992, command: 'publish', lock_token: 'wlk-dead' }), 'utf8');
      fs.writeFileSync(path.join(dataPath, 'runtime', 'write.recovering.lock'), JSON.stringify({ pid: 99999993, command: 'recover-lock' }), 'utf8');

      // 存活 PID 的 write.recovering.lock 仍必须拦截，死 PID 应自动归档接管且 Exit B 不得泄漏 local_only 标题
      const recOut = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'recover-lock'], { env, encoding: 'utf8' }));
      assert.equal(recOut.recovered, true);
      assert.equal(recOut.r1Recovery.count, 1);
      assert.equal(recOut.r1Recovery.details[0].targetPath, '[REDACTED_LOCAL_ONLY]');
      assert.equal(JSON.stringify(recOut).includes(r1SecretTitle), false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('9. Adapter 损坏/空多帧过滤、Codex UUID(session_meta_id) 导入入库 Git、与 benchmark 预建索引修复', () => {
    const { root, vaultPath, dataPath, env } = createEnv('v25-adp-gaps-');
    try {
      initGitRepo(vaultPath);
      execFileSync('git', ['config', 'user.name', 'GapTest'], { cwd: vaultPath });
      execFileSync('git', ['config', 'user.email', 'gap@example.com'], { cwd: vaultPath });
      execFileSync('git', ['add', '首页.md'], { cwd: vaultPath });
      execFileSync('git', ['commit', '-m', 'init'], { cwd: vaultPath });

      const codexHome = path.join(root, 'cdx');
      const dshHome = path.join(root, 'dsh');
      fs.mkdirSync(codexHome, { recursive: true });
      fs.mkdirSync(path.join(dshHome, '--C-Work-sample-project--', 'dsh-stub-skip'), { recursive: true });
      fs.mkdirSync(path.join(dshHome, '--C-Work-sample-project--', 'dsh-corrupt'), { recursive: true });

      const uuidOnly = '019e77b8-4db7-7a71-bbef-0e22891d86f0';
      const cdxMain = path.join(codexHome, `rollout-2026-11-11T10-00-00-${uuidOnly}.jsonl`);
      fs.writeFileSync(
        cdxMain,
        [
          JSON.stringify({ type: 'session_meta', payload: { id: uuidOnly, cwd: 'C:\\Work\\sample-project', source: 'cli' } }),
          JSON.stringify({ type: 'event_msg', payload: { type: 'user_message', message: '用 UUID 直接导入' } })
        ].join('\n') + '\n',
        'utf8'
      );
      // 损坏的 .jsonl.zst 与 1-行+skippable帧 的 DSH 空会话
      fs.writeFileSync(path.join(codexHome, 'rollout-corrupt.jsonl.zst'), Buffer.from('not-zstd-bytes'));
      const skipHdr = Buffer.alloc(8);
      skipHdr.writeUInt32LE(0x184d2a50, 0);
      skipHdr.writeUInt32LE(4, 4);
      fs.writeFileSync(
        path.join(dshHome, '--C-Work-sample-project--', 'dsh-stub-skip', 'session.v4.jsonl.zstd'),
        Buffer.concat([zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'session', version: 4, id: 'dsh-stub-skip' }) + '\n', 'utf8')), skipHdr, Buffer.from('skip')])
      );
      fs.writeFileSync(
        path.join(dshHome, '--C-Work-sample-project--', 'dsh-corrupt', 'session.v4.jsonl.zstd'),
        Buffer.from('bad-dsh-zstd')
      );

      const discoveredDefault = listDiscoverableSessions({
        sourceTool: 'all',
        codexHome,
        antigravityBrainDir: path.join(root, 'empty-agy'),
        dshHome
      });
      assert.equal(discoveredDefault.length, 1, '损坏的 .zst/.zstd 与含 skippable 尾帧的单行 DSH 空会话必须默认过滤');
      assert.equal(discoveredDefault[0].session_meta_id, uuidOnly);

      const discoveredAll = listDiscoverableSessions({
        sourceTool: 'all',
        codexHome,
        antigravityBrainDir: path.join(root, 'empty-agy'),
        dshHome,
        includeFiltered: true
      });
      assert.equal(discoveredAll.filter(s => s.filtered_reason === 'corrupt_session').length, 2);
      assert.equal(discoveredAll.filter(s => s.filtered_reason === 'empty_session').length, 1);

      // 允许直接传 session_meta_id UUID 执行 mem ingest，并自动提交至 Vault .git
      const cliEnv = {
        ...env,
        AGENT_MEMORY_CODEX_HOME: codexHome,
        AGENT_MEMORY_ANTIGRAVITY_BRAIN_DIR: path.join(root, 'empty-agy'),
        AGENT_MEMORY_DSH_HOME: dshHome
      };
      const ingRes = JSON.parse(
        execFileSync(process.execPath, [CLI_PATH, 'ingest', '--source', 'codex', '--session', uuidOnly, '--sensitivity', 'synthetic'], { env: cliEnv, encoding: 'utf8' })
      );
      assert.equal(ingRes.status, 'ingested');
      assert.equal(ingRes.project, 'SampleProject');
      assert.equal(ingRes.gitState, 'committed');

      // 验证 runner.mjs 在 runtime/index 目录已存在（空目录）时仍会构建 lexical-index.json
      const bmVault = path.join(root, 'bm-corpus', 'AgentMemory');
      const bmData = path.join(root, 'bm-corpus', 'AgentMemory-Data');
      buildSyntheticPilotCorpus({ vaultDir: bmVault, dataDir: bmData });
      fs.unlinkSync(path.join(bmData, 'runtime', 'index', 'lexical-index.json'));
      runBenchmarkSuite({ suite: 'pilot', vaultDir: bmVault, dataDir: bmData });
      assert.ok(fs.existsSync(path.join(bmData, 'runtime', 'index', 'lexical-index.json')), '即使 runtime/index/ 目录已存在，benchmark 也必须补建 lexical-index.json');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('10. Antigravity subagent 过滤、ingest raw/ 路径脱敏、与 Vault 插件凭据在 Git/备份/恢复中的边界防护', () => {
    const { root, vaultPath, dataPath, dbPath } = createEnv('v25-agy-plugin-');
    try {
      // 10a. Antigravity subagent 会话 (SYSTEM_MESSAGE + SYSTEM/SYSTEM_SDK) 默认被 listDiscoverableSessions 过滤，
      // 非 SYSTEM 来源的 SYSTEM_MESSAGE（如讨论 <Identity> 的普通测试会话）绝不误杀
      const agyBrain = path.join(root, 'agy-brain');
      const mainLogDir = path.join(agyBrain, 'agy-main-01', '.system_generated', 'logs');
      const nonSysMsgDir = path.join(agyBrain, 'agy-main-nonsys-04', '.system_generated', 'logs');
      const subSdkDir = path.join(agyBrain, 'agy-sub-sdk-02', '.system_generated', 'logs');
      const subWorkerDir = path.join(agyBrain, 'agy-sub-worker-03', '.system_generated', 'logs');
      fs.mkdirSync(mainLogDir, { recursive: true });
      fs.mkdirSync(nonSysMsgDir, { recursive: true });
      fs.mkdirSync(subSdkDir, { recursive: true });
      fs.mkdirSync(subWorkerDir, { recursive: true });

      const mainTr = path.join(mainLogDir, 'transcript.jsonl');
      fs.writeFileSync(
        mainTr,
        [
          JSON.stringify({ step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-10T10:00:00Z', content: '主会话提问，提到 D:\\Obs\\AgentMemory-Data\\raw\\codex\\demo.jsonl 路径' }),
          JSON.stringify({ step_index: 2, type: 'PLANNER_RESPONSE', source: 'MODEL', created_at: '2026-11-10T10:00:05Z', content: '回答完成' })
        ].join('\n') + '\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(nonSysMsgDir, 'transcript.jsonl'),
        [
          JSON.stringify({ step_index: 1, type: 'SYSTEM_MESSAGE', source: 'USER', created_at: '2026-11-10T10:00:10Z', content: '讨论 <Identity> 标签解析逻辑' }),
          JSON.stringify({ step_index: 2, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-10T10:00:11Z', content: '继续' })
        ].join('\n') + '\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(subSdkDir, 'transcript.jsonl'),
        JSON.stringify({ step_index: 1, type: 'SYSTEM_MESSAGE', source: 'SYSTEM_SDK', created_at: '2026-11-10T10:01:00Z', content: 'The following is a <SYSTEM_MESSAGE>...' }) + '\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(subWorkerDir, 'transcript.jsonl'),
        JSON.stringify({ step_index: 1, type: 'SYSTEM_MESSAGE', source: 'SYSTEM', created_at: '2026-11-10T10:02:00Z', content: '<Identity>You are a coding worker</Identity>' }) + '\n',
        'utf8'
      );

      const defaultList = listDiscoverableSessions({
        sourceTool: 'antigravity',
        codexHome: path.join(root, 'empty-cdx'),
        antigravityBrainDir: agyBrain,
        dshHome: path.join(root, 'empty-dsh')
      });
      assert.equal(defaultList.length, 2);
      assert.ok(defaultList.some(s => s.session_id === 'agy-main-01'));
      assert.ok(defaultList.some(s => s.session_id === 'agy-main-nonsys-04'));

      const allList = listDiscoverableSessions({
        sourceTool: 'antigravity',
        codexHome: path.join(root, 'empty-cdx'),
        antigravityBrainDir: agyBrain,
        dshHome: path.join(root, 'empty-dsh'),
        includeFiltered: true
      });
      assert.equal(allList.filter(s => s.filtered_reason === 'subagent_session').length, 2);

      // 10b. ingestSession 必须清洗正文中引用的 raw/ 路径，保证产物通过 detectResidualSecrets；并发布一条知识笔记供恢复检索自检
      const db = openExistingDatabase(dbPath);
      try {
        const ing = ingestSession({
          db,
          vaultDir: vaultPath,
          dataDir: dataPath,
          sourcePath: mainTr,
          sourceTool: 'antigravity',
          sessionId: 'agy-main-01',
          project: 'ObsidianAgentMemory',
          sensitivity: 'approved_low_sensitivity'
        });
        assert.equal(ing.status, 'ingested');
        const mdText = fs.readFileSync(ing.readableSessionPath, 'utf8');
        assert.ok(mdText.includes('[REDACTED_RAW_PATH]'));
        assert.equal(detectResidualSecrets(mdText).clean, true);

        const knId = 'KN-019316a8-plg1-7000-8000-000000000901';
        const knStg = stageCandidate({
          stagingDir: path.join(dataPath, 'staging'),
          outputUuid: knId,
          content: makeValidPlaybookContent(knId, '插件边界备份恢复测试', '插件隔离与备份自检内容')
        });
        publishFile({
          db,
          operationId: 'op-plg-kn',
          outputUuid: knId,
          stagingPath: knStg.stagingPath,
          vaultTargetPath: path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-20261111-000901_插件边界备份恢复测试.md'),
          contentSha256: knStg.contentSha256,
          revisionsDir: path.join(dataPath, 'runtime', 'revisions')
        });
      } finally {
        db.close();
      }

      // 10c. Vault Git 白名单 + .gitignore 拦截 .obsidian/plugins/* / .obsidian/cache/* / .claudian/*，防止 obsidian-git 误提交 credentials.json
      assert.equal(isWhitelistedVaultPath(vaultPath, path.join(vaultPath, '.obsidian', 'core-plugins.json')), true);
      assert.equal(isWhitelistedVaultPath(vaultPath, path.join(vaultPath, '.obsidian', 'plugins', 'chinese-plugin-market', 'credentials.json')), false);
      assert.equal(isWhitelistedVaultPath(vaultPath, path.join(vaultPath, '.obsidian', 'plugins', 'obsidian-git', 'obsidian_askpass.sh')), false);
      assert.equal(isWhitelistedVaultPath(vaultPath, path.join(vaultPath, '.obsidian', 'cache', 'index.json')), false);

      initGitRepo(vaultPath);
      execFileSync('git', ['config', 'user.name', 'PluginGuardTest'], { cwd: vaultPath });
      execFileSync('git', ['config', 'user.email', 'guard@example.com'], { cwd: vaultPath });

      // 10d. mem backup 保留用户插件主文件与 data.json，但排除 credentials.json / obsidian_askpass.sh / *-cache.json / discovery-index.json / plugin cache 目录 / .git/*.lock
      const marketDir = path.join(vaultPath, '.obsidian', 'plugins', 'chinese-plugin-market');
      const gitPluginDir = path.join(vaultPath, '.obsidian', 'plugins', 'obsidian-git');
      const aneDir = path.join(vaultPath, '.obsidian', 'plugins', 'atomic-notes-extractor');
      const claudianDir = path.join(vaultPath, '.claudian');
      fs.mkdirSync(path.join(marketDir, 'cache'), { recursive: true });
      fs.mkdirSync(gitPluginDir, { recursive: true });
      fs.mkdirSync(aneDir, { recursive: true });
      fs.mkdirSync(claudianDir, { recursive: true });
      fs.writeFileSync(path.join(marketDir, 'manifest.json'), '{"id":"chinese-plugin-market"}\n', 'utf8');
      fs.writeFileSync(path.join(marketDir, 'data.json'), '{"ok":true}\n', 'utf8');
      fs.writeFileSync(path.join(marketDir, 'credentials.json'), '{"user":"demo"}\n', 'utf8');
      fs.writeFileSync(path.join(marketDir, 'plugin-list-cache.json'), '{"cached":true}\n', 'utf8');
      fs.writeFileSync(path.join(marketDir, 'trending-history.json'), '{"trend":[]}\n', 'utf8');
      fs.writeFileSync(path.join(marketDir, 'cache', 'temp.bin'), 'cache', 'utf8');
      fs.writeFileSync(path.join(gitPluginDir, 'manifest.json'), '{"id":"obsidian-git"}\n', 'utf8');
      fs.writeFileSync(path.join(gitPluginDir, 'obsidian_askpass.sh'), '#!/bin/sh\n', 'utf8');
      fs.writeFileSync(path.join(aneDir, 'manifest.json'), '{"id":"atomic-notes-extractor"}\n', 'utf8');
      fs.writeFileSync(path.join(aneDir, 'data.json'), '{"settingsVersion":1}\n', 'utf8');
      fs.writeFileSync(path.join(aneDir, 'discovery-index.json'), '{"notes":{}}\n', 'utf8');
      fs.writeFileSync(path.join(claudianDir, 'claudian-settings.json'), '{"locale":"zh"}\n', 'utf8');
      fs.writeFileSync(path.join(vaultPath, '.git', 'HEAD.lock'), 'lock', 'utf8');

      // .gitignore 必须阻止 git status / obsidian-git 将 .obsidian/plugins/* 与 .claudian/* 纳入未跟踪队列
      const porcelain = execFileSync('git', ['status', '--porcelain'], { cwd: vaultPath, encoding: 'utf8' });
      assert.equal(porcelain.includes('.obsidian/plugins/'), false);
      assert.equal(porcelain.includes('.claudian/'), false);

      // 当 publisher.lock 已存在时，createConsistentBackup 抛错且不泄漏 db 句柄
      const bkpTarget = path.join(root, 'Backups');
      acquirePublisherLock(dataPath);
      assert.throws(() => createConsistentBackup({ vaultPath, dataPath, targetDir: bkpTarget }), /EEXIST/);
      releasePublisherLock(dataPath);

      const bkp = createConsistentBackup({ vaultPath, dataPath, targetDir: bkpTarget });
      assert.equal(bkp.status, 'complete');
      assert.equal(bkp.classification, 'local_private_backup_not_for_external_export');
      const bkpVault = path.join(bkp.backupDir, 'AgentMemory');
      assert.ok(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'manifest.json')));
      assert.ok(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'obsidian-git', 'manifest.json')));
      // C3 独立复审：默认排除 .claudian/ 与插件 data.json 配置，仅保留插件运行文件白名单
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'data.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'atomic-notes-extractor', 'data.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.claudian', 'claudian-settings.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'credentials.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'plugin-list-cache.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'trending-history.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'cache', 'temp.bin')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'obsidian-git', 'obsidian_askpass.sh')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.obsidian', 'plugins', 'atomic-notes-extractor', 'discovery-index.json')), false);
      assert.equal(fs.existsSync(path.join(bkpVault, '.git', 'HEAD.lock')), false);

      // 显式逐项批准某个插件配置时，仅纳入该批准项，其余未批准配置与 .claudian 仍保持排除
      const bkpApproved = createConsistentBackup({
        vaultPath,
        dataPath,
        targetDir: bkpTarget,
        approvedPluginData: ['atomic-notes-extractor']
      });
      const bkpApprovedVault = path.join(bkpApproved.backupDir, 'AgentMemory');
      assert.ok(fs.existsSync(path.join(bkpApprovedVault, '.obsidian', 'plugins', 'atomic-notes-extractor', 'data.json')));
      assert.equal(fs.existsSync(path.join(bkpApprovedVault, '.obsidian', 'plugins', 'chinese-plugin-market', 'data.json')), false);
      assert.equal(fs.existsSync(path.join(bkpApprovedVault, '.claudian', 'claudian-settings.json')), false);

      // 10e. 含保留插件的完整备份必须可端到端 restoreFromBackup 并通过检索自检
      const restVault = path.join(root, 'RestoredVault');
      const restData = path.join(root, 'RestoredData');
      const rest = restoreFromBackup({
        backupDir: bkp.backupDir,
        newVaultPath: restVault,
        newDataPath: restData,
        selfCheckQuery: '插件边界备份恢复测试'
      });
      assert.equal(rest.restored, true);
      assert.equal(rest.verification.sqliteIntegrityOk, true);
      assert.equal(rest.verification.checksumMismatches.length, 0);
      assert.equal(rest.verification.missingCount, 0);
      assert.equal(rest.verification.selfCheckHits, 1);
      assert.ok(fs.existsSync(path.join(restVault, '.obsidian', 'plugins', 'obsidian-git', 'manifest.json')));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
