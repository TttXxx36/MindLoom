import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import {
  createNonSecretSentinel,
  runIsolationSentinelCheck,
  assertSensitivityAllowed,
  DEFAULT_INSPECT_SCRIPT_PATH
} from '../src/security/isolation-sentinel.mjs';
import { ingestSession } from '../src/ingest/session-ingestor.mjs';

test('B01: R3 强隔离三路哨兵测试与降级路径限制', async (t) => {
  const baseDir = path.resolve('.tmp/test-b01-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const rawDir = path.join(dataDir, 'raw');

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

  const { sentinelPath, sentinelToken } = createNonSecretSentinel({ rawDir });

  await t.test('1. 独立脚本 inspect-raw-local.ps1 拒绝非交互/Agent 自动化调用与越权路径', () => {
    // 1a. 非交互脚本调用必须退出码非零 (EXIT 43) 且不得输出哨兵内容
    let exitCode = 0;
    let output = '';
    try {
      output = execFileSync(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-File', DEFAULT_INSPECT_SCRIPT_PATH, '-SnapshotFile', sentinelPath, '-DataDir', dataDir],
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
    } catch (err) {
      exitCode = err.status || 1;
      output = (err.stdout || '') + (err.stderr || '');
    }
    assert.notEqual(exitCode, 0, '非交互脚本调用必须被拒绝');
    assert.equal(output.includes(sentinelToken), false, '脚本拒绝时不得输出哨兵口令');

    // 1b. 尝试路径穿越读取 raw/ 之外文件同样被阻断
    const outsideFile = path.join(vaultDir, '首页.md');
    let traversalExit = 0;
    try {
      execFileSync(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-File', DEFAULT_INSPECT_SCRIPT_PATH, '-SnapshotFile', outsideFile, '-DataDir', dataDir, '-HumanConfirmed'],
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
    } catch (err) {
      traversalExit = err.status || 1;
    }
    assert.notEqual(traversalExit, 0);
  });

  await t.test('2. 软护栏不等于强隔离：真实未受限环境下三路探测器诚实报告降级模式并阻断保密原文', () => {
    // 在本未受限工作区环境中，脚本被拒但 direct_file_read 与 general_shell_read 仍可读出哨兵
    const report = runIsolationSentinelCheck({
      rawDir,
      dataDir,
      sentinelPath,
      sentinelToken
    });

    assert.equal(report.vectors.standalone_script_read.blocked, true, '独立脚本非交互调用应被阻断');
    assert.equal(report.vectors.direct_file_read.blocked, false, '当前未隔离环境可直接读文件');
    assert.equal(report.vectors.general_shell_read.blocked, false, '当前未隔离环境可通过 Shell 读文件');
    assert.equal(report.strongIsolationEstablished, false, '严禁在文件/Shell 可读时宣称已通过强隔离');
    assert.equal(report.mode, 'degraded_low_sensitivity_only');

    // 验证降级模式下拒绝处理 confidential 原文
    assert.throws(() => {
      assertSensitivityAllowed({ sensitivity: 'confidential', isolationReport: report });
    }, /R3_ISOLATION_GATE_BLOCKED/);

    // 但允许处理明确获准的合成/低敏样本
    assert.doesNotThrow(() => {
      assertSensitivityAllowed({ sensitivity: 'synthetic', isolationReport: report });
      assertSensitivityAllowed({ sensitivity: 'approved_low_sensitivity', isolationReport: report });
    });

    // 验证 ingestSession 同样在降级状态下硬阻断 confidential 会话
    const confSource = path.join(baseDir, 'conf-session.jsonl');
    fs.writeFileSync(confSource, JSON.stringify({ type: 'user', content: '保密原件' }) + '\n', 'utf8');
    assert.throws(() => {
      ingestSession({
        db,
        vaultDir,
        dataDir,
        sourcePath: confSource,
        sessionId: 'sess-conf-001',
        sensitivity: 'confidential',
        isolationReport: report
      });
    }, /R3_ISOLATION_GATE_BLOCKED/);
  });

  await t.test('3. 受限隔离环境模拟：仅当三路（直接读+通用Shell+独立脚本）全部被阻断时才放行强隔离', () => {
    const denyErr = () => {
      const e = new Error('EACCES: permission denied by host capability policy');
      e.code = 'EACCES';
      throw e;
    };

    const strongReport = runIsolationSentinelCheck({
      rawDir,
      dataDir,
      sentinelPath,
      sentinelToken,
      directReader: denyErr,
      shellReader: denyErr,
      scriptReader: denyErr
    });

    assert.equal(strongReport.vectors.direct_file_read.blocked, true);
    assert.equal(strongReport.vectors.general_shell_read.blocked, true);
    assert.equal(strongReport.vectors.standalone_script_read.blocked, true);
    assert.equal(strongReport.strongIsolationEstablished, true);
    assert.equal(strongReport.mode, 'strong_isolated');

    assert.doesNotThrow(() => {
      assertSensitivityAllowed({ sensitivity: 'confidential', isolationReport: strongReport });
    });
  });
});
