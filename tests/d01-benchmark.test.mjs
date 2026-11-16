import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { runBenchmarkSuite } from '../src/benchmark/runner.mjs';
import { PILOT_QUESTIONS } from '../src/benchmark/pilot-suite.synthetic.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

test('D01: 12-15 题阶段 D 探索评测可复现性、完整指标披露与 Mode 0 默认保持', async (t) => {
  const baseDir = path.resolve('.tmp/test-d01-' + Date.now());
  const corpusDir = path.join(baseDir, 'pilot-corpus');
  const outPath = path.join(baseDir, 'pilot-report.json');

  t.after(() => {
    try {
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  await t.test('1. 固定 14 题合成中文集跑通 Mode 0/1/2 对比、预热后 3 轮计时与失败回退', () => {
    assert.ok(PILOT_QUESTIONS.length >= 12 && PILOT_QUESTIONS.length <= 15, '阶段 D 题集规模必须为 12-15 题');

    const report = runBenchmarkSuite({
      suite: 'pilot',
      corpusDir,
      outputPath: outPath
    });

    assert.equal(report.suite, 'pilot');
    assert.equal(report.dailyDefaultMode, 'literal', '日常默认必须保持 Mode 0');
    assert.ok(fs.existsSync(report.reportPath));

    const m0 = report.modes['Mode 0 (literal)'];
    const m1 = report.modes['Mode 1 (hybrid)'];
    const m2 = report.modes['Mode 2 (rerank)'];
    const m2fb = report.modes['Mode 2 (fallback_drill)'];
    const m2fbTimeout = report.modes['Mode 2 (fallback_drill_timeout)'];

    for (const m of [m0, m1, m2]) {
      assert.equal(m.questionCounts.total, 14);
      assert.equal(m.runTimingsMs.length, 3, '必须在预热后执行 3 轮重复计时');
      assert.ok(m.warmupMs >= 0);
      assert.ok(m.avgLatencyMs >= 0);
      assert.ok(m.p50LatencyMs >= 0);
      assert.equal(m.hitAt1, 1, `${m.mode} Hit@1 应命中固定试点集`);
      assert.equal(m.hitAt5, 1, `${m.mode} Hit@5 应命中固定试点集`);
      assert.equal(m.mrrAt5, 1, `${m.mode} MRR@5 应达到预期`);
      assert.equal(m.noAnswerAccuracy, 1, `${m.mode} 无答案/local_only 拒答率必须 100%`);
      assert.equal(m.staleOrConflictMisuseCount, 0, `${m.mode} 过期/冲突误用数必须为 0`);
    }

    assert.equal(m0.egressBytes, 0);
    assert.equal(m0.estimatedCostCny, 0);
    assert.ok(m2fb.fallbackCount > 0, '失败回退演练 A 必须验证未批准时回退至 Mode 0');
    assert.equal(m2fb.externalInvokeCount, 0);
    assert.ok(m2fb.fallbackReasons.includes('missing_egress_approval_fallback_to_mode0'));
    assert.ok(m2fbTimeout.fallbackCount > 0, '失败回退演练 B 必须实际进入模拟超时函数并安全回退至 Mode 0');
    assert.ok(m2fbTimeout.externalInvokeCount > 0);
    assert.ok(m2fbTimeout.fallbackReasons.some(r => r.includes('external_rerank_error_fallback_to_mode0:simulated_api_timeout')));
  });

  await t.test('2. CLI mem benchmark --suite pilot --isolated 完整可复现执行', () => {
    const cliOutPath = path.join(baseDir, 'cli-pilot-report.json');
    const stdout = execFileSync(
      process.execPath,
      [CLI_PATH, 'benchmark', '--suite', 'pilot', '--isolated', '--out', cliOutPath],
      { encoding: 'utf8' }
    );
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.dailyDefaultMode, 'literal');
    assert.equal(parsed.modes['Mode 0 (literal)'].staleOrConflictMisuseCount, 0);
    assert.ok(fs.existsSync(cliOutPath));
  });
});
