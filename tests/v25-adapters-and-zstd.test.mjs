import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { initRepository } from '../src/init.mjs';
import { openExistingDatabase } from '../src/db/sqlite.mjs';
import { decompressZstdAllFrames, decompressFirstZstdFrame } from '../src/ingest/zstd-utils.mjs';
import {
  ingestSession,
  listDiscoverableSessions,
  locateSnapshotEvent
} from '../src/ingest/session-ingestor.mjs';
import { publishFile, stageCandidate } from '../src/storage/atomic-publisher.mjs';
import { resolveTargetFilePath } from '../src/storage/path-sanitizer.mjs';
import { parseMarkdownFrontmatter } from '../src/schema/frontmatter.mjs';
import { DEFAULT_INSPECT_SCRIPT_PATH } from '../src/security/isolation-sentinel.mjs';
import { createSessionSanitizer, detectResidualSecrets } from '../src/security/sanitizer.mjs';
import { createProposal, reconcileProposal, checkProposalReconcileState } from '../src/reconcile/engine.mjs';
import { inspectCodexSessionMetadata } from '../src/ingest/adapters/codex-adapter.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

function makeTempEnv(prefix = 'v25-adp-') {
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
    dbPath: path.join(dataPath, 'runtime', 'state.sqlite')
  };
}

function buildSkippableFrame(payloadStr) {
  const payload = Buffer.from(payloadStr, 'utf8');
  const header = Buffer.alloc(8);
  header.writeUInt32LE(0x184d2a50, 0);
  header.writeUInt32LE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

test('V2.5 Adapters, Multi-Frame Zstd, Per-Tool Raw Isolation & CLI Contracts', async (t) => {
  await t.test('1. Multi-frame Zstd 解压支持串联帧、可跳过帧及截断损坏帧报错', () => {
    const f1 = zlib.zstdCompressSync(Buffer.from('{"type":"session","version":4}\n', 'utf8'));
    const skip = buildSkippableFrame('dsh-skip');
    const f2 = zlib.zstdCompressSync(Buffer.from('{"type":"user/message","data":{"content":"hello"}}\n', 'utf8'));
    const f3 = zlib.zstdCompressSync(Buffer.from('{"type":"assistant/message","data":{"message":{"content":"world"}}}\n', 'utf8'));
    const multi = Buffer.concat([f1, skip, f2, f3]);

    // 验证标准 node:zlib.zstdDecompressSync 在串联帧上会截断在第一帧（回归证明），而 decompressZstdAllFrames 解出全部 3 帧
    const singleFrameOnly = zlib.zstdDecompressSync(f1);
    assert.equal(singleFrameOnly.toString('utf8').split(/\r?\n/).filter(Boolean).length, 1);

    const firstMeta = decompressFirstZstdFrame(multi);
    assert.equal(firstMeta.hasMoreFrames, true);
    assert.ok(firstMeta.buffer.toString('utf8').includes('"version":4'));

    const allBuf = decompressZstdAllFrames(multi);
    const lines = allBuf.toString('utf8').split(/\r?\n/).filter(Boolean);
    assert.equal(lines.length, 3);
    assert.ok(lines[2].includes('"world"'));

    // 截断第二帧必须报错
    const corruptMulti = Buffer.concat([f1, f2.subarray(0, Math.max(4, f2.length - 3))]);
    assert.throws(() => decompressZstdAllFrames(corruptMulti), /Truncated zstd|unexpected end of file|Invalid zstd/);
  });

  await t.test('2. Codex Adapter: 过滤 subagent/空/活跃未闭合会话并完整解析真实嵌套事件与 raw/codex 隔离', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-cdx-');
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const codexHome = path.join(root, 'codex-sessions');
    fs.mkdirSync(codexHome, { recursive: true });

    // (a) 正常已完成主会话 (.jsonl.zst)
    const mainZst = path.join(codexHome, 'rollout-2026-11-10T10-00-00-main-001.jsonl.zst');
    const mainLines = [
      JSON.stringify({
        timestamp: '2026-11-10T10:00:00Z',
        type: 'session_meta',
        payload: { session_id: 'main-001', cwd: 'C:\\Work\\sample-project', source: 'vscode' }
      }),
      JSON.stringify({
        timestamp: '2026-11-10T10:00:01Z',
        type: 'response_item',
        payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text: '排查 Codex 写锁并发' }] }
      }),
      JSON.stringify({
        timestamp: '2026-11-10T10:00:02Z',
        type: 'response_item',
        payload: { type: 'function_call', name: 'pwsh', arguments: '{"cmd":"mem doctor"}' }
      }),
      JSON.stringify({
        timestamp: '2026-11-10T10:00:03Z',
        type: 'event_msg',
        payload: { type: 'task_complete', last_agent_message: 'doctor 状态正常' }
      }),
      JSON.stringify({ timestamp: '2026-11-10T10:00:04Z', type: 'compacted', payload: {} })
    ];
    fs.writeFileSync(mainZst, zlib.zstdCompressSync(Buffer.from(mainLines.join('\n') + '\n', 'utf8')));

    // (b) subagent 会话（应默认过滤）
    const subFile = path.join(codexHome, 'rollout-2026-11-10T10-01-00-sub-002.jsonl');
    fs.writeFileSync(
      subFile,
      [
        JSON.stringify({ type: 'session_meta', payload: { session_id: 'sub-002', source: { subagent: { other: 'guardian' } } } }),
        JSON.stringify({ type: 'response_item', payload: { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'guardian check' }] } })
      ].join('\n') + '\n',
      'utf8'
    );

    // (c) 仅 session_meta 的空会话（应默认过滤）
    const emptyMetaFile = path.join(codexHome, 'rollout-2026-11-10T10-02-00-empty-003.jsonl');
    fs.writeFileSync(
      emptyMetaFile,
      JSON.stringify({ type: 'session_meta', payload: { session_id: 'empty-003', source: 'vscode' } }) + '\n',
      'utf8'
    );

    // (d) 末行未闭合的活跃会话（应默认过滤）
    const activeFile = path.join(codexHome, 'rollout-2026-11-10T10-03-00-active-004.jsonl');
    fs.writeFileSync(
      activeFile,
      JSON.stringify({ type: 'session_meta', payload: { session_id: 'active-004', source: 'vscode' } }) + '\n{"type":"event_msg","partial":',
      'utf8'
    );

    const discovered = listDiscoverableSessions({ sourceTool: 'codex', codexHome });
    assert.equal(discovered.length, 1);
    assert.equal(discovered[0].session_id, 'rollout-2026-11-10T10-00-00-main-001');

    const withFiltered = listDiscoverableSessions({ sourceTool: 'codex', codexHome, includeFiltered: true });
    assert.equal(withFiltered.length, 4);

    const db = openExistingDatabase(dbPath);
    try {
      const ing = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: mainZst,
        sourceTool: 'codex',
        sessionId: 'main-001',
        title: 'Codex真实结构验证'
      });
      assert.equal(ing.status, 'ingested');
      assert.equal(ing.project, 'SampleProject', '未传 --project 时应自动从 session_meta.payload.cwd 映射 project-map.json');
      assert.equal(ing.coverage.unknown_events, 0, 'Codex 原生事件类型绝不可误报 unknown_event');
      assert.equal(ing.coverage.parse_error_events, 0);

      const baseName = path.basename(ing.readableSessionPath);
      assert.match(baseName, /^SES-\d{8}-codex-[0-9a-f]{6}_/, '可读会话文件名必须包含 source_tool 标识 (§4.1)');

      const rawFiles = fs.readdirSync(path.join(dataPath, 'raw', 'codex'));
      assert.equal(rawFiles.length, 1, 'Codex 原始快照必须隔离存放于 raw/codex/ (§2)');

      const manifest = JSON.parse(fs.readFileSync(ing.manifestPath, 'utf8'));
      assert.equal(manifest.decompressed_line_map[1].provenance.source_tool, 'codex');
      assert.equal(manifest.decompressed_line_map[1].provenance.primary_line, 2);

      const md = fs.readFileSync(ing.readableSessionPath, 'utf8');
      assert.ok(md.includes('排查 Codex 写锁并发'));
      assert.ok(md.includes('[pwsh]'));
      assert.ok(md.includes('doctor 状态正常'));
    } finally {
      db.close();
    }
  });

  await t.test('3. DSH Adapter: 多帧 .jsonl.zstd 全帧解析、delegationDepth 过滤、workspace_slug 入 YAML 与 raw/dsh 隔离', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-dsh-');
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const dshHome = path.join(root, 'dsh-sessions');
    const mainDir = path.join(dshHome, '--C-Work-sample-project--', 'session-main-dsh-001');
    const subDir = path.join(dshHome, '--C-Work--', 'session-sub-dsh-002');
    const stubDir = path.join(dshHome, '--C-Windows-Temp--', 'session-stub-dsh-003');
    fs.mkdirSync(mainDir, { recursive: true });
    fs.mkdirSync(subDir, { recursive: true });
    fs.mkdirSync(stubDir, { recursive: true });

    const dshMainPath = path.join(mainDir, 'session.v4.jsonl.zstd');
    const frames = [
      { type: 'session', version: 4, id: 'session-main-dsh-001', createdAt: 1794300000000, cwd: 'C:\\Work\\sample-project', delegationDepth: 0 },
      { type: 'user/message', seq: 1, time: 1794300001000, data: { content: '检查多帧 Zstd 解压逻辑', source: 'tui', role: 'user' } },
      { type: 'tool/call', seq: 2, time: 1794300002000, data: { callId: 'c1', name: 'pwsh', arguments: '{"cmd":"npm test"}' } },
      { type: 'assistant/message', seq: 3, time: 1794300003000, data: { message: { role: 'assistant', content: [{ type: 'text', text: 'DSH 多帧第 4 帧完整回复' }] } } }
    ].map(obj => zlib.zstdCompressSync(Buffer.from(JSON.stringify(obj) + '\n', 'utf8')));
    fs.writeFileSync(dshMainPath, Buffer.concat(frames));

    // 子代理与空头会话
    fs.writeFileSync(
      path.join(subDir, 'session.v4.jsonl.zstd'),
      Buffer.concat([
        zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'session', version: 4, id: 'session-sub-dsh-002', delegationDepth: 1 }) + '\n', 'utf8')),
        zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'user/message', data: { content: 'subtask' } }) + '\n', 'utf8'))
      ])
    );
    fs.writeFileSync(
      path.join(stubDir, 'session.v4.jsonl.zstd'),
      zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'session', version: 4, id: 'session-stub-dsh-003', delegationDepth: 0 }) + '\n', 'utf8'))
    );

    const discovered = listDiscoverableSessions({ sourceTool: 'dsh', dshHome });
    assert.equal(discovered.length, 1);
    assert.equal(discovered[0].session_id, 'session-main-dsh-001');
    assert.equal(discovered[0].workspace_slug, '--C-Work-sample-project--');

    const db = openExistingDatabase(dbPath);
    try {
      const ing = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: dshMainPath,
        sourceTool: 'dsh',
        sessionId: 'session-main-dsh-001',
        title: 'DSH多帧验证'
      });
      assert.equal(ing.status, 'ingested');
      assert.equal(ing.project, 'SampleProject');
      assert.equal(ing.coverage.total_events, 4, '必须解压并渲染全部 4 个串联 Zstd 帧');
      assert.equal(ing.coverage.unknown_events, 0);

      const md = fs.readFileSync(ing.readableSessionPath, 'utf8');
      const fm = parseMarkdownFrontmatter(md).frontmatter;
      assert.equal(fm.workspace_slug, '--C-Work-sample-project--');
      assert.ok(md.includes('DSH 多帧第 4 帧完整回复'));
      assert.match(path.basename(ing.readableSessionPath), /^SES-\d{8}-dsh-[0-9a-f]{6}_/);
      assert.equal(fs.readdirSync(path.join(dataPath, 'raw', 'dsh')).length, 1);

      const sessionBase = path.basename(ing.readableSessionPath, '.md');
      const loc4 = locateSnapshotEvent({
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourceLink: `[[10_Readable_Sessions/${sessionBase}#^event-000004]]`
      });
      assert.equal(loc4.found, true);
      assert.equal(loc4.eventId, 4);
      assert.ok(loc4.rawEventSanitized.includes('DSH 多帧第 4 帧完整回复'));
    } finally {
      db.close();
    }
  });

  await t.test('4. Antigravity Adapter: 末行未闭合触发 ERR_SOURCE_UNSTABLE、ID校验、backfilled_truncations 与 provenance', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-agy-tail-');
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const agyDir = path.join(root, 'agy-logs');
    fs.mkdirSync(agyDir, { recursive: true });
    const trPath = path.join(agyDir, 'transcript.jsonl');
    const fullPath = path.join(agyDir, 'transcript_full.jsonl');

    const db = openExistingDatabase(dbPath);
    try {
      // 4a. 末行 JSON 未闭合（实时写入中）-> 立即中止 ERR_SOURCE_UNSTABLE
      fs.writeFileSync(
        trPath,
        JSON.stringify({ step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-10T10:00:00Z', content: 'ok' }) +
          '\n{"step_index":2,"type":"PLANNER_RESPONSE","content":"half',
        'utf8'
      );
      const unstableTail = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: trPath,
        sourceTool: 'antigravity',
        sessionId: 'agy-tail-001'
      });
      assert.equal(unstableTail.status, 'skipped_unstable_file');
      assert.equal(unstableTail.errorCode, 'ERR_SOURCE_UNSTABLE');

      // 4b. 稳定快照：事件 1 校验通过并回填，事件 2 id 冲突不可回填
      fs.writeFileSync(
        trPath,
        [
          JSON.stringify({ id: 'evt-1', step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-10T10:00:00Z', content: '截断...', truncated_fields: ['content'] }),
          JSON.stringify({ id: 'evt-2', step_index: 2, type: 'GENERIC', source: 'SYSTEM', created_at: '2026-11-10T10:00:01Z', content: '截断2...', truncated_fields: ['content'] })
        ].join('\n') + '\n',
        'utf8'
      );
      fs.writeFileSync(
        fullPath,
        [
          JSON.stringify({ id: 'evt-1', step_index: 1, type: 'USER_INPUT', source: 'USER_EXPLICIT', created_at: '2026-11-10T10:00:00Z', content: '已核验身份回填完整内容' }),
          JSON.stringify({ id: 'evt-DIFFERENT', step_index: 2, type: 'GENERIC', source: 'SYSTEM', created_at: '2026-11-10T10:00:01Z', content: '冲突ID绝不可覆盖' })
        ].join('\n') + '\n',
        'utf8'
      );

      const res = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir: dataPath,
        sourcePath: trPath,
        sourceTool: 'antigravity',
        sessionId: 'agy-tail-001'
      });
      assert.equal(res.status, 'ingested');
      assert.equal(res.project, 'unmapped', '未传 --project 且无匹配工作区时必须落入 unmapped');
      assert.equal(res.coverage.backfilled_truncations, 1);
      assert.equal(res.coverage.unresolved_truncations, 1);
      assert.equal(res.coverage.unknown_events, 0);

      const manifest = JSON.parse(fs.readFileSync(res.manifestPath, 'utf8'));
      assert.deepEqual(manifest.decompressed_line_map[0].provenance, {
        source_tool: 'antigravity',
        source_role: 'backfill',
        primary_line: 1,
        backfill_line: 1,
        step_index: 1,
        backfilled_fields: ['content']
      });
      assert.equal(fs.readdirSync(path.join(dataPath, 'raw', 'antigravity')).length, 2);
      const fm = parseMarkdownFrontmatter(fs.readFileSync(res.readableSessionPath, 'utf8')).frontmatter;
      assert.equal(fm.coverage.backfilled_truncations, 1);
      assert.equal(fm.coverage.unresolved_truncations, 1);
    } finally {
      db.close();
    }
  });

  await t.test('5. CLI list-sessions --limit、mem status 三端与 unmapped 统计、R7 SES-碰撞消歧与 inspect-raw-local 退出码', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-cli-ext-');
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    // 5a. 验证 R7 短文件名碰撞在 SES-<date>-<source_tool>-<suffix> 上正确保留 source_tool 并扩展 12 位 UUID
    const sesDir = path.join(vaultPath, '10_Readable_Sessions');
    const uuid1 = 'SES-019316a8-1111-7000-8000-111111abcdef';
    const uuid2 = 'SES-019316a8-2222-7000-8000-222222abcdef';
    const p1 = resolveTargetFilePath({ targetDir: sesDir, prefix: 'SES', dateStr: '20261110', sourceTool: 'dsh', uuid: uuid1, title: '会话碰撞测试' });
    assert.equal(path.basename(p1.targetPath), 'SES-20261110-dsh-abcdef_会话碰撞测试.md');
    const db = openExistingDatabase(dbPath);
    const stg1 = stageCandidate({ stagingDir: path.join(dataPath, 'staging'), outputUuid: uuid1, content: `---\nid: "${uuid1}"\n---\nA` });
    publishFile({ db, operationId: 'op-ses-1', outputUuid: uuid1, stagingPath: stg1.stagingPath, vaultTargetPath: p1.targetPath, contentSha256: stg1.contentSha256 });
    const stg2 = stageCandidate({ stagingDir: path.join(dataPath, 'staging'), outputUuid: uuid2, content: `---\nid: "${uuid2}"\n---\nB` });
    const pub2 = publishFile({ db, operationId: 'op-ses-2', outputUuid: uuid2, stagingPath: stg2.stagingPath, vaultTargetPath: p1.targetPath, contentSha256: stg2.contentSha256 });
    assert.equal(pub2.collided, true);
    assert.equal(path.basename(pub2.vaultTargetPath), 'SES-20261110-dsh-222222abcdef_会话碰撞测试.md');

    // 5b. 准备 2 个 Codex 会话测试 list-sessions --limit 1 及 unmapped 状态统计
    const codexHome = path.join(root, 'cdx');
    fs.mkdirSync(codexHome, { recursive: true });
    const fA = path.join(codexHome, 'ses-a.jsonl');
    const fB = path.join(codexHome, 'ses-b.jsonl');
    fs.writeFileSync(fA, JSON.stringify({ type: 'user', content: 'A' }) + '\n', 'utf8');
    fs.writeFileSync(fB, JSON.stringify({ type: 'user', content: 'B' }) + '\n', 'utf8');

    ingestSession({ db, vaultDir: vaultPath, dataDir: dataPath, sourcePath: fA, sourceTool: 'codex', sessionId: 'ses-a' });
    db.close();

    const env = {
      ...process.env,
      AGENT_MEMORY_VAULT: vaultPath,
      AGENT_MEMORY_DATA: dataPath,
      AGENT_MEMORY_CODEX_HOME: codexHome,
      AGENT_MEMORY_ANTIGRAVITY_BRAIN_DIR: path.join(root, 'empty-agy'),
      AGENT_MEMORY_DSH_HOME: path.join(root, 'empty-dsh')
    };

    const listOut = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, 'list-sessions', '--source', 'codex', '--limit', '1', '--json'], { env, encoding: 'utf8' })
    );
    assert.equal(listOut.totalCount, 2);
    assert.equal(listOut.count, 1);
    assert.equal(listOut.sessions.length, 1);

    const fWithCwd = path.join(codexHome, 'rollout-2026-11-11T11-00-00-cwd01.jsonl');
    fs.writeFileSync(
      fWithCwd,
      JSON.stringify({ type: 'session_meta', payload: { session_id: 'cwd01', cwd: 'C:\\Work\\sample-project', source: 'cli' } }) +
        '\n' +
        JSON.stringify({ type: 'user', content: 'cwd check' }) +
        '\n',
      'utf8'
    );
    const listTextOut = execFileSync(process.execPath, [CLI_PATH, 'list-sessions', '--source', 'codex', '--limit', '3'], { env, encoding: 'utf8' });
    assert.ok(listTextOut.includes('cwd: C:\\Work\\sample-project'), 'list-sessions 文本输出应显示 cwd 元数据');

    const statusOut = execFileSync(process.execPath, [CLI_PATH, 'status'], { env, encoding: 'utf8' });
    assert.ok(statusOut.includes('项目待确认 unmapped: 1 篇'));
    assert.ok(statusOut.includes('codex=1, antigravity=0, dsh=0'));

    // 5c. 验证 inspect-raw-local.ps1 非交互调用稳定返回 EXIT 43，且脚本门禁顺序为：非交互拦截(43) -> 路径越界拦截(44) -> 人工 YES 确认 -> 存在校验(45)
    let nonInterExit = 0;
    try {
      execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', DEFAULT_INSPECT_SCRIPT_PATH, '-SnapshotFile', 'test.jsonl', '-DataDir', dataPath], {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (e) {
      nonInterExit = e.status;
    }
    assert.equal(nonInterExit, 43);

    const psCheck = fs.readFileSync(DEFAULT_INSPECT_SCRIPT_PATH, 'utf8');
    assert.ok(psCheck.includes('-ErrorAction Continue'));
    const idxAgentGate = psCheck.indexOf('exit 43');
    const idxBoundaryGate = psCheck.indexOf('exit 44');
    const idxReadHost = psCheck.indexOf('Read-Host');
    const idxNotFoundGate = psCheck.indexOf('exit 45');
    assert.ok(idxAgentGate > 0 && idxBoundaryGate > idxAgentGate && idxReadHost > idxBoundaryGate && idxNotFoundGate > idxReadHost);
    const parseErrCount = execFileSync(
      'pwsh',
      ['-NoProfile', '-NonInteractive', '-Command', `$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('${DEFAULT_INSPECT_SCRIPT_PATH.replace(/'/g, "''")}', [ref]$null, [ref]$e); $e.Count`],
      { encoding: 'utf8' }
    ).trim();
    assert.equal(parseErrCount, '0', 'inspect-raw-local.ps1 PowerShell AST 语法解析必须零报错');
  });

  await t.test('6. 深度回归: 7MB大负载防栈溢出脱敏、Codex超4KB末行/多帧ZST/新事件类型、只读immutable回退与多帧inspect-raw-local', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v25-deep-reg-');
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    // 6a. Sanitizer 应对 7MB base64、sk-、Bearer 大负载不抛 RangeError 且正确拦截
    const sanitizer = createSessionSanitizer();
    const bigBase64 = 'data:image/png;base64,' + 'AbCd+EfG/HiJkLmNoPqRsTuVwXyZ0123456789+/'.repeat(180000);
    const outB64 = sanitizer.sanitize(bigBase64);
    assert.equal(outB64.text.length, bigBase64.length);

    const bigSk = ['sk', 'A'.repeat(250000)].join('-');
    const outSk = sanitizer.sanitize(`key=${bigSk}`);
    assert.ok(outSk.text.includes('[TOKEN_1]') || outSk.text.includes('[SECRET_1]'));
    assert.equal(outSk.text.includes(bigSk), false);
    assert.equal(detectResidualSecrets(outSk.text).clean, true);

    const bigBearer = ['Bearer', 'Z'.repeat(250000)].join(' ');
    const outBearer = sanitizer.sanitize(bigBearer);
    assert.equal(outBearer.text.includes('ZZZZZZZZZZ'), false);
    assert.equal(detectResidualSecrets(outBearer.text).clean, true);

    // 6b. Codex Adapter: >4KB 末行不被误判为 active_unclosed_session; >64KB 首行不丢; 多帧 zst 1行首帧不被误判空; 新事件 unknown_events=0
    const codexHome = path.join(root, 'cdx-edge');
    fs.mkdirSync(codexHome, { recursive: true });

    const longTailFile = path.join(codexHome, 'rollout-2026-11-10T12-00-00-longtail.jsonl');
    const bigLine1 = JSON.stringify({ type: 'session_meta', payload: { session_id: 'longtail', cwd: 'C:\\Work\\sample-project', source: 'vscode', base_instructions: 'X'.repeat(70000) } });
    const bigLastLine = JSON.stringify({ type: 'event_msg', payload: { type: 'task_complete', last_agent_message: 'Y'.repeat(6000) } });
    fs.writeFileSync(
      longTailFile,
      [
        bigLine1,
        JSON.stringify({ type: 'inter_agent_communication_metadata', payload: { trigger_turn: true } }),
        JSON.stringify({ type: 'retained_context', payload: { type: 'questions', turn_id: 't1' } }),
        bigLastLine
      ].join('\n') + '\n',
      'utf8'
    );
    const longMeta = inspectCodexSessionMetadata(longTailFile);
    assert.equal(longMeta.isMainCompleted, true, '末行超过 4KB 且已闭合的 Codex 会话绝不可误判为 active_unclosed_session');
    assert.equal(longMeta.cwd, 'C:\\Work\\sample-project', '超过 64KB 的 session_meta 首行也应完整解析 cwd');

    const multiZstFile = path.join(codexHome, 'rollout-2026-11-10T12-01-00-multizst.jsonl.zst');
    const f1 = zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'session_meta', payload: { session_id: 'multizst', source: 'cli' } }) + '\n', 'utf8'));
    const f2 = zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'event_msg', payload: { type: 'user_message', message: 'hello multi zst' } }) + '\n', 'utf8'));
    fs.writeFileSync(multiZstFile, Buffer.concat([f1, f2]));
    const multiMeta = inspectCodexSessionMetadata(multiZstFile);
    assert.equal(multiMeta.isMainCompleted, true, '第 1 帧仅含 session_meta 的多帧 .jsonl.zst 绝不可误判为空会话');

    const db = openExistingDatabase(dbPath);
    const ingLong = ingestSession({ db, vaultDir: vaultPath, dataDir: dataPath, sourcePath: longTailFile, sourceTool: 'codex', sessionId: 'longtail' });
    assert.equal(ingLong.coverage.unknown_events, 0);

    // 6c. 只读 immutable=1 打开 & 只读 DB 下 checkProposalReconcileState 不崩 SQLITE_READONLY
    const knId = 'KN-019316a8-read-7000-8000-000000000099';
    const knPath = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks', 'KN-ro.md');
    fs.writeFileSync(knPath, `---\nschema_version: 1\nid: "${knId}"\nnote_type: "playbook"\ntitle: "只读核对"\nproject: "P"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv: "windows"\ncreated_at: "2026-11-10T12:00:00Z"\n---\nnew step\n`, 'utf8');
    const prop = createProposal({
      queueDir: path.join(vaultPath, '40_Review_Queue'),
      proposalUuid: 'PROP-019316a8-read-7000-8000-000000000099',
      title: '只读核对提案',
      project: 'P',
      targetId: knId,
      targetNoteRef: '[[KN-ro]]',
      preConditions: ['old step'],
      postConditions: ['new step']
    });
    fs.writeFileSync(prop.proposalPath, fs.readFileSync(prop.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
    reconcileProposal({ db, proposalPath: prop.proposalPath, targetPath: knPath });
    db.close();

    // 修改目标笔记触发 version_changed，随后用 readOnly 数据库执行 checkProposalReconcileState 不得抛错
    fs.appendFileSync(knPath, '\n<!-- changed -->\n', 'utf8');
    const roDb = openExistingDatabase(dbPath, { readOnly: true });
    const roCheck = checkProposalReconcileState({ db: roDb, proposalPath: prop.proposalPath, targetPath: knPath });
    assert.equal(roCheck.reconcile_state, 'unverified');
    assert.equal(roCheck.reason, 'version_changed');
    roDb.close();

    // 6d. inspect-raw-local.ps1 的 $jsOneLiner 支持多帧串联 .jsonl.zstd 解压
    const ps1Text = fs.readFileSync(DEFAULT_INSPECT_SCRIPT_PATH, 'utf8');
    const matchOneLiner = ps1Text.match(/\$jsOneLiner\s*=\s*'([^']+)'/);
    assert.ok(matchOneLiner);
    const dshMultiZstd = path.join(root, 'multi-frame.jsonl.zstd');
    const df1 = zlib.zstdCompressSync(Buffer.from('{"type":"session","version":4}\n', 'utf8'));
    const df2 = zlib.zstdCompressSync(Buffer.from('{"type":"user/message","data":{"content":"frame2"}}\n', 'utf8'));
    fs.writeFileSync(dshMultiZstd, Buffer.concat([df1, buildSkippableFrame('skip'), df2]));
    const psDecomp = execFileSync(process.execPath, ['-e', matchOneLiner[1], dshMultiZstd], { encoding: 'utf8' });
    assert.ok(psDecomp.includes('frame2'), 'inspect-raw-local.ps1 必须完整解压多帧 .jsonl.zstd');

    // 6e. CLI mem doctor --json, mem status --json, mem benchmark --suite pilot --isolated --json
    const cliEnv = { ...process.env, AGENT_MEMORY_VAULT: vaultPath, AGENT_MEMORY_DATA: dataPath };
    const docJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'doctor', '--json'], { env: cliEnv, encoding: 'utf8' }));
    assert.equal(docJson.ok, true);
    const stJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'status', '--json'], { env: cliEnv, encoding: 'utf8' }));
    assert.equal(stJson.snapshots.codex, 1);
    const bmJson = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'benchmark', '--suite', 'pilot', '--isolated', '--json'], { env: cliEnv, encoding: 'utf8' }));
    assert.equal(bmJson.dailyDefaultMode, 'literal');
  });
});
