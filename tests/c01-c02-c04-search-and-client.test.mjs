import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';
import { createProposal, reconcileProposal } from '../src/reconcile/engine.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { ingestSession } from '../src/ingest/session-ingestor.mjs';
import { runClientAcceptanceChecks } from '../src/verify/client-acceptance.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

test('C01/C02/C04: 短词与精确命令召回、双通道与双版本联动、及 Antigravity 端独立验收', async (t) => {
  const baseDir = path.resolve('.tmp/test-c01-c04-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const srcDir = path.join(baseDir, 'sources');

  fs.mkdirSync(srcDir, { recursive: true });
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

  const stagingDir = path.join(dataDir, 'staging');
  const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');

  // 准备导入一个合成会话，生成可读会话与锚点供 C04 引用定位测试
  const srcSession = path.join(srcDir, 'c04-sess.jsonl');
  fs.writeFileSync(
    srcSession,
    [
      JSON.stringify({ type: 'user', content: '服务启动报错 401 且端口占用' }),
      JSON.stringify({ type: 'tool_use', command: 'docker compose up -d --port=8080' }),
      JSON.stringify({ type: 'assistant', content: '确认 IP 10.0.0.5 上返回 401，需校对时钟后启动。' })
    ].join('\n') + '\n',
    'utf8'
  );
  const ingestRes = ingestSession({
    db,
    vaultDir,
    dataDir,
    sourcePath: srcSession,
    sourceTool: 'codex',
    sessionId: 'sess-c-001',
    project: 'AlphaProj',
    title: 'Alpha 启动与 401 排查会话',
    sensitivity: 'synthetic'
  });
  const sessionBase = path.basename(ingestRes.readableSessionPath, '.md');
  const citationLink = `[[10_Readable_Sessions/${sessionBase}#^event-000003]]`;

  // 发布 4 篇知识笔记覆盖 C01 (短词/标点/跨项目隔离) 与 C02 (到期/未审/冲突/双版本失配)
  function publishTestNote({ id, title, project, lifecycle = 'active', reviewState = 'accepted', reviewAfter = null, body }) {
    const filePath = path.join(notesDir, `${id}.md`);
    const reviewLine = reviewAfter ? `review_after: "${reviewAfter}"\n` : '';
    const content = `---
schema_version: 1
id: "${id}"
note_type: "playbook"
title: "${title}"
project: "${project}"
privacy: "sanitized"
lifecycle: "${lifecycle}"
evidence_level: "user_confirmed"
review_state: "${reviewState}"
${reviewLine}env: "windows"
sources:
  - "${citationLink}"
created_at: "2026-11-10T12:00:00+08:00"
---
${body}
`;
    const staged = stageCandidate({ stagingDir, outputUuid: id, content });
    publishFile({
      db,
      operationId: `op-${id}`,
      outputUuid: id,
      stagingPath: staged.stagingPath,
      vaultTargetPath: filePath,
      contentSha256: staged.contentSha256,
      metadata: { note_type: 'playbook', title, project, privacy: 'sanitized', lifecycle, review_state: reviewState, review_after: reviewAfter }
    });
    return filePath;
  }

  const alphaActiveId = 'KN-019316a8-7c40-7000-8000-c01000000001';
  const alphaPath = publishTestNote({
    id: alphaActiveId,
    title: 'Alpha 服务启动与 401 排障',
    project: 'AlphaProj',
    reviewAfter: '2026-12-31',
    body: '执行 docker compose up -d --port=8080 启动服务；若 IP 10.0.0.5 返回 401，请同步 NTP。'
  });

  const betaOtherProjId = 'KN-019316a8-7c40-7000-8000-c01000000002';
  publishTestNote({
    id: betaOtherProjId,
    title: 'Beta 服务启动与 401 排障',
    project: 'BetaProj',
    reviewAfter: '2026-12-31',
    body: 'BetaProj 专用启动命令 --port=9090，处理 401 与 IP 映射。'
  });

  const expiredId = 'KN-019316a8-7c40-7000-8000-c02000000003';
  publishTestNote({
    id: expiredId,
    title: '已过期状态 IP 检查',
    project: 'AlphaProj',
    reviewAfter: '2026-11-10', // 北京时间不晚于今日即到期
    body: 'IP 检查旧记录'
  });

  const conflictTargetId = 'KN-019316a8-7c40-7000-8000-c02000000004';
  const conflictTargetPath = publishTestNote({
    id: conflictTargetId,
    title: '冲突测试启动命令',
    project: 'AlphaProj',
    body: '旧启动命令 old-start --legacy'
  });

  await t.test('C01: 短词（启动/IP/401）与带标点命令参数精确召回，且 --project 严防跨项目误用', () => {
    for (const q of ['启动', 'IP', '401', '--port=8080', 'docker compose up -d --port=8080']) {
      const resAlpha = searchKnowledge({ db, vaultDir, query: q, project: 'AlphaProj', todayStr: '2026-11-10' });
      assert.ok(resAlpha.items.some(i => i.id === alphaActiveId && i.actionable === true), `查询 "${q}" 应命中 AlphaProj`);
      assert.equal(resAlpha.items.some(i => i.project === 'BetaProj'), false, `查询 "${q}" 限定 AlphaProj 时绝不能跨项目返回 BetaProj`);
    }
  });

  await t.test('C02: 到期、未核对冲突、及双版本失配均归入 actionable: false；无答案明确拒答；CLI 无法伪造清除', () => {
    // 1. 到期条目归入 Channel 2
    const expRes = searchKnowledge({ db, vaultDir, query: '已过期状态 IP', project: 'AlphaProj', todayStr: '2026-11-10' });
    assert.equal(expRes.items.length, 1);
    assert.equal(expRes.items[0].actionable, false);
    assert.ok(expRes.items[0].reason.includes('review_expired'));

    // 2. 创建冲突提案 -> pending 即阻塞 -> accepted 但前置未移除仍阻塞 -> 通过前后置核对后放行 -> 再单独改提案或回退目标均退回 unverified (version_changed)
    const prop = createProposal({
      queueDir: path.join(vaultDir, '40_Review_Queue'),
      proposalUuid: 'PROP-019316a8-7c40-7000-8000-c02000000099',
      title: '替换旧启动命令',
      project: 'AlphaProj',
      targetId: conflictTargetId,
      targetNoteRef: `[[${conflictTargetId}]]`,
      proposalKind: 'conflict',
      preConditions: ['old-start --legacy'],
      postConditions: ['new-start --strict']
    });

    let resConf = searchKnowledge({ db, vaultDir, query: '冲突测试启动命令', project: 'AlphaProj', todayStr: '2026-11-10' });
    assert.equal(resConf.items[0].actionable, false);

    // 标为 accepted 并修正目标笔记通过 reconcile
    fs.writeFileSync(prop.proposalPath, fs.readFileSync(prop.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
    fs.writeFileSync(conflictTargetPath, fs.readFileSync(conflictTargetPath, 'utf8').replace('old-start --legacy', 'new-start --strict'), 'utf8');
    const recOk = reconcileProposal({ db, proposalPath: prop.proposalPath, targetPath: conflictTargetPath });
    assert.equal(recOk.reconcile_state, 'verified_applied');

    resConf = searchKnowledge({ db, vaultDir, query: '冲突测试启动命令', project: 'AlphaProj', todayStr: '2026-11-10' });
    assert.equal(resConf.items[0].actionable, true);

    // 分支 A: 仅改提案文件 -> 退回 unverified (version_changed) -> actionable: false
    fs.appendFileSync(prop.proposalPath, '\n<!-- 单独改提案 -->\n', 'utf8');
    resConf = searchKnowledge({ db, vaultDir, query: '冲突测试启动命令', project: 'AlphaProj', todayStr: '2026-11-10' });
    assert.equal(resConf.items[0].actionable, false);
    assert.ok(resConf.items[0].reason.includes('version_changed'));

    // 重新 reconcile 通过后再测分支 B: 修改目标文件回退
    reconcileProposal({ db, proposalPath: prop.proposalPath, targetPath: conflictTargetPath });
    fs.appendFileSync(conflictTargetPath, '\n<!-- 回退修改目标 -->\n', 'utf8');
    resConf = searchKnowledge({ db, vaultDir, query: '冲突测试启动命令', project: 'AlphaProj', todayStr: '2026-11-10' });
    assert.equal(resConf.items[0].actionable, false);
    assert.ok(resConf.items[0].reason.includes('version_changed'));

    // 3. 无答案时明确拒答不编造
    const emptyRes = searchKnowledge({ db, vaultDir, query: '不存在的量子纠缠配置项xyz', todayStr: '2026-11-10' });
    assert.equal(emptyRes.noAnswer, true);
    assert.equal(emptyRes.items.length, 0);

    // 4. Agent 传参无法自行清除冲突
    let exitCode = 0;
    try {
      execFileSync(process.execPath, [CLI_PATH, 'search', '冲突测试启动命令', '--confirm-proposal'], {
        env: { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir },
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (e) {
      exitCode = e.status || 1;
    }
    assert.notEqual(exitCode, 0);
  });

  await t.test('C04: Antigravity 端独立跑通触发、检索、引用定位与脱敏错误报告（严禁代验 Codex）', () => {
    const report = runClientAcceptanceChecks({
      clientName: 'antigravity',
      vaultDir,
      dataDir,
      query: 'Alpha 服务启动',
      expectedId: alphaActiveId,
      citationLink
    });

    assert.equal(report.passed, true);
    assert.equal(report.checks.triggerOk, true);
    assert.equal(report.checks.searchHitOk, true);
    assert.equal(report.checks.citationOk, true);
    assert.equal(report.checks.errorReportSanitized, true);
    assert.ok(report.codexIndependentVerificationStatus.includes('PENDING_INDEPENDENT_CODEX_RUN'));

    // 确认严禁由 Antigravity 代验 Codex
    assert.throws(() => {
      runClientAcceptanceChecks({
        clientName: 'codex',
        vaultDir,
        dataDir,
        query: 'Alpha'
      });
    }, /严禁相互代验/);
  });
});
