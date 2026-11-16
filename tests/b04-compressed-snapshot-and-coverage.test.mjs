import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import { ingestSession, locateSnapshotEvent } from '../src/ingest/session-ingestor.mjs';

test('B04: 压缩快照定位 (.jsonl.zst) 与覆盖异常报告', async (t) => {
  const baseDir = path.resolve('.tmp/test-b04-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const srcDir = path.join(baseDir, 'sources');
  const srcAttDir = path.join(baseDir, 'src-attachments');

  fs.mkdirSync(srcDir, { recursive: true });
  fs.mkdirSync(srcAttDir, { recursive: true });
  initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  const db = openDatabase(path.join(dataDir, 'runtime', 'state.sqlite'));

  t.after(() => {
    try {
      db.close();
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  await t.test('1. 正常 .jsonl.zst 压缩快照解析、覆盖清单异常报告与 #^event-NNNNNN 编号绝不重排', () => {
    // 准备一个存在附件，另一个附件刻意缺失
    fs.writeFileSync(path.join(srcAttDir, 'present-log.txt'), 'stack trace ok', 'utf8');

    const lines = [
      JSON.stringify({ type: 'user', content: '请检查 Zstd 压缩日志中的异常事件' }),
      JSON.stringify({ type: 'tool_result', output: 'X'.repeat(350) }), // 超过 maxEventChars 100 -> omitted
      JSON.stringify({ type: 'custom_telemetry_v9', payload: { metric: 123 } }), // 未知事件类型
      '{ broken-json-line-without-closing-brace', // 解析失败行
      JSON.stringify({ type: 'tool_result', content: '附件检查', attachments: ['present-log.txt', 'missing-dump.png'] }), // 1 存在 + 1 缺失附件
      JSON.stringify({ type: 'assistant', content: '结论：问题源于 401 时钟偏移，已确认修复。' })
    ];

    const rawJsonlBuf = Buffer.from(lines.join('\n') + '\n', 'utf8');
    const compressedBuf = zlib.zstdCompressSync(rawJsonlBuf);
    const zstPath = path.join(srcDir, 'sess-b04-001.jsonl.zst');
    fs.writeFileSync(zstPath, compressedBuf);

    const res = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: zstPath,
      sourceTool: 'claude-code',
      sessionId: 'sess-b04-001',
      project: 'DataSync',
      title: 'Zstd压缩快照异常验证',
      sensitivity: 'synthetic',
      sourceAttachmentsDir: srcAttDir,
      maxEventChars: 100
    });

    assert.equal(res.status, 'ingested');
    assert.equal(res.coverage.total_events, 6);
    assert.equal(res.coverage.omitted_events, 1);
    assert.equal(res.coverage.unknown_events, 1);
    assert.equal(res.coverage.parse_error_events, 1);
    assert.equal(res.coverage.attachments_count, 1);
    assert.equal(res.coverage.missing_attachments_count, 1);

    // 验证异常明细完整写入可读会话覆盖清单，且事件编号 1..6 绝不重排
    const md = fs.readFileSync(res.readableSessionPath, 'utf8');
    assert.ok(md.includes('## 会话覆盖清单'));
    assert.ok(md.includes('unknown_event'));
    assert.ok(md.includes('parse_error'));
    assert.ok(md.includes('missing_attachment'));
    assert.ok(md.includes('missing-dump.png'));
    for (let i = 1; i <= 6; i++) {
      const anchor = `^event-${String(i).padStart(6, '0')}`;
      assert.ok(md.includes(anchor), `必须保留原始锚点 ${anchor}`);
    }

    // 验证 #^event-000006 精确跳转到压缩快照内第 6 个原始事件
    const sessionBase = path.basename(res.readableSessionPath, '.md');
    const loc6 = locateSnapshotEvent({
      vaultDir,
      dataDir,
      sourceLink: `[[10_Readable_Sessions/${sessionBase}#^event-000006]]`
    });
    assert.equal(loc6.found, true);
    assert.equal(loc6.compressed, true);
    assert.equal(loc6.eventId, 6);
    assert.equal(loc6.anchor, '^event-000006');
    assert.ok(loc6.rawEventSanitized.includes('401 时钟偏移'));
    assert.ok(loc6.readableExcerpt.includes('401 时钟偏移'));
  });

  await t.test('2. 截断或损坏的 .jsonl.zst 压缩包在覆盖异常中明确报告且不崩栈泄露路径', () => {
    const validZst = zlib.zstdCompressSync(Buffer.from('{"type":"user","content":"hello"}\n{"type":"assistant","content":"world"}\n', 'utf8'));
    const truncatedZst = validZst.subarray(0, Math.max(4, Math.floor(validZst.length / 2)));
    const badPath = path.join(srcDir, 'sess-b04-corrupt.jsonl.zst');
    fs.writeFileSync(badPath, truncatedZst);

    const res = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: badPath,
      sourceTool: 'claude-code',
      sessionId: 'sess-b04-corrupt',
      sensitivity: 'synthetic'
    });

    assert.equal(res.status, 'corrupt_snapshot');
    assert.equal(res.reason, 'corrupt_compressed_snapshot');
    assert.equal(res.coverage.parse_error_events, 1);
    assert.ok(res.anomalies.some(a => a.type === 'corrupt_compressed_snapshot'));
  });
});
