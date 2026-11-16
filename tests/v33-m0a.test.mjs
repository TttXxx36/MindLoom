import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import { stageCandidate, publishFile } from '../src/storage/atomic-publisher.mjs';
import { findMarkdownFiles } from '../src/storage/path-sanitizer.mjs';
import { createProposal, reconcileProposal } from '../src/reconcile/engine.mjs';
import { ingestSession, locateSnapshotEvent } from '../src/ingest/session-ingestor.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { issueTrustedEgressApproval } from '../src/security/trusted-approvals.mjs';
import { runBenchmarkSuite } from '../src/benchmark/runner.mjs';
import { buildSyntheticPilotCorpus, PILOT_QUESTIONS } from '../src/benchmark/pilot-suite.synthetic.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

function makeTempEnv(prefix) {
  const root = path.resolve(`.tmp/${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`);
  const vaultPath = path.join(root, 'AgentMemory');
  const dataPath = path.join(root, 'AgentMemory-Data');
  initRepository({ vaultPath, dataPath });
  const dbPath = path.join(dataPath, 'runtime', 'state.sqlite');
  const env = { ...process.env, AGENT_MEMORY_VAULT: vaultPath, AGENT_MEMORY_DATA: dataPath };
  return { root, vaultPath, dataPath, dbPath, env };
}

function publishKnowledgeNote({ db, vaultPath, dataPath, id, relPath, title, project = 'M0AProj', privacy = 'sanitized', lifecycle = 'active', reviewState = 'accepted', reviewAfter = '2026-12-31', sources = [], body }) {
  const stagingDir = path.join(dataPath, 'staging');
  const targetPath = path.join(vaultPath, relPath);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  const sourcesYaml = sources.length > 0 ? `sources:\n${sources.map(s => `  - "${s}"`).join('\n')}\n` : '';
  const reviewAfterYaml = reviewAfter ? `review_after: "${reviewAfter}"\n` : '';
  const content = `---
schema_version: 1
id: "${id}"
note_type: "playbook"
title: "${title}"
project: "${project}"
privacy: "${privacy}"
lifecycle: "${lifecycle}"
evidence_level: "user_confirmed"
review_state: "${reviewState}"
${reviewAfterYaml}env: "windows"
${sourcesYaml}created_at: "2026-11-10T12:00:00+08:00"
---
${body}
`;
  const staged = stageCandidate({ stagingDir, outputUuid: id, content });
  publishFile({
    db,
    operationId: `op-${id}-${Math.random().toString(16).slice(2, 6)}`,
    outputUuid: id,
    stagingPath: staged.stagingPath,
    vaultTargetPath: targetPath,
    contentSha256: staged.contentSha256,
    revisionsDir: path.join(dataPath, 'runtime', 'revisions'),
    metadata: {
      note_type: 'playbook',
      title,
      project,
      privacy,
      lifecycle,
      evidence_level: 'user_confirmed',
      review_state: reviewState,
      review_after: reviewAfter
    }
  });
  return targetPath;
}

test('V3.3-0 (M0A): 递归扫描一致性与防越界、真实 Mode 0 回退、评测双指标与隔离验证', async (t) => {
  await t.test('V3.3-T01: 递归扫描、跨命令 UUID 冲突先报不覆盖、locateSnapshotEvent 路径/UUID 零降级与符号链接防逃逸', () => {
    const { root, vaultPath, dataPath: dataDir, dbPath, env } = makeTempEnv('v33-t01');
    const db = openDatabase(dbPath);
    try {
      // 1. 嵌套 30_Knowledge_Notes/sub 与 40_Review_Queue/sub/PROP-*.md 跨命令一致性 (reconcile / proposal show / status)
      const targetId = 'KN-019316a8-7c40-7000-8000-330100000001';
      const targetPath = publishKnowledgeNote({
        db,
        vaultPath,
        dataPath: dataDir,
        id: targetId,
        relPath: path.join('30_Knowledge_Notes', 'Playbooks', 'nested', 'KN-nested.md'),
        title: '嵌套目录笔记',
        body: '新版正确步骤 --strict'
      });

      const nestedQueueDir = path.join(vaultPath, '40_Review_Queue', 'sub', 'deep');
      const propId = 'PROP-019316a8-7c40-7000-8000-330100000091';
      const propRes = createProposal({
        queueDir: nestedQueueDir,
        proposalUuid: propId,
        title: '嵌套提案测试',
        project: 'M0AProj',
        targetId,
        targetNoteRef: `[[${targetId}]]`,
        proposalKind: 'conflict',
        preConditions: ['旧版错误步骤'],
        postConditions: ['新版正确步骤 --strict']
      });
      fs.writeFileSync(
        propRes.proposalPath,
        fs.readFileSync(propRes.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'),
        'utf8'
      );

      // 在 90_Templates/ 下放入同后缀模板，必须被排除
      const tplDir = path.join(vaultPath, '40_Review_Queue', '90_Templates');
      fs.mkdirSync(tplDir, { recursive: true });
      fs.writeFileSync(
        path.join(tplDir, 'PROP-template-ignore.md'),
        `---\nid: "${propId}"\nnote_type: "proposal"\nproposal_status: "pending"\n---\n模板不应造成冲突\n`,
        'utf8'
      );

      const recOut = execFileSync(process.execPath, [CLI_PATH, 'reconcile'], { env, encoding: 'utf8' });
      assert.ok(recOut.includes(propId), 'reconcile 必须扫描到嵌套提案并核对');

      const showOut = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', propId], { env, encoding: 'utf8' }));
      assert.equal(showOut.id, propId);
      assert.equal(showOut.reconcile_state, 'verified_applied');

      const statusOut = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'status', '--json'], { env, encoding: 'utf8' }));
      assert.equal(statusOut.proposals.verified, 1);
      assert.equal(statusOut.proposals.conflictCount, 0);

      // 移动提案到另一子目录后三命令依然一致
      const movedQueueDir = path.join(vaultPath, '40_Review_Queue', 'moved');
      fs.mkdirSync(movedQueueDir, { recursive: true });
      const movedPropPath = path.join(movedQueueDir, path.basename(propRes.proposalPath));
      fs.renameSync(propRes.proposalPath, movedPropPath);
      const showMoved = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', propId], { env, encoding: 'utf8' }));
      assert.equal(showMoved.reconcile_state, 'verified_applied');

      // 2. 歧义/重复 UUID 冲突：先报冲突，不能由第一个或最后一个文件覆盖核对状态
      const dupPropId = 'PROP-019316a8-7c40-7000-8000-330100000092';
      const dupDirA = path.join(vaultPath, '40_Review_Queue', 'dupA');
      const dupDirB = path.join(vaultPath, '40_Review_Queue', 'dupB');
      const dupA = createProposal({
        queueDir: dupDirA,
        proposalUuid: dupPropId,
        title: '冲突副本A',
        project: 'M0AProj',
        targetId,
        targetNoteRef: `[[${targetId}]]`,
        proposalKind: 'conflict',
        preConditions: ['旧版错误步骤'],
        postConditions: ['新版正确步骤 --strict']
      });
      fs.writeFileSync(dupA.proposalPath, fs.readFileSync(dupA.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
      const dupB = createProposal({
        queueDir: dupDirB,
        proposalUuid: dupPropId,
        title: '冲突副本B',
        project: 'M0AProj',
        targetId,
        targetNoteRef: `[[${targetId}]]`,
        proposalKind: 'conflict',
        preConditions: ['新版正确步骤 --strict'],
        postConditions: ['不可能满足的条件']
      });
      fs.writeFileSync(dupB.proposalPath, fs.readFileSync(dupB.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');

      // 2a. proposal show 必须先报冲突退出非零
      let showConflictExit = 0;
      let showConflictErr = '';
      try {
        execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', dupPropId], { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        showConflictExit = e.status || 1;
        showConflictErr = (e.stderr || '') + (e.stdout || '');
      }
      assert.notEqual(showConflictExit, 0);
      assert.ok(showConflictErr.includes('ERR_AMBIGUOUS_PROPOSAL_ID'));

      // 2b. reconcile 必须先报冲突，且不能让第一个或最后一个文件写入 reconcile_states
      const recDupOut = execFileSync(process.execPath, [CLI_PATH, 'reconcile'], { env, encoding: 'utf8' });
      assert.ok(recDupOut.includes('提案 ID 冲突') && recDupOut.includes(dupPropId));
      assert.equal(db.prepare('SELECT 1 FROM reconcile_states WHERE proposal_id = ?').get(dupPropId), undefined);

      // 2c. status 必须给出一致冲突结果，不计入 verified
      const statusDup = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'status', '--json'], { env, encoding: 'utf8' }));
      assert.equal(statusDup.proposals.conflictCount, 1);
      assert.equal(statusDup.proposals.verified, 1, '冲突提案绝不能被首/尾文件刷成 verified');
      const conflictItem = statusDup.proposals.details.find(d => d.proposal_id === dupPropId);
      assert.equal(conflictItem.reconcile_state, 'unverified');
      assert.equal(conflictItem.reason, 'duplicate_proposal_id_conflict');

      // 2d. 对已核对生效的 propId 新增重复冲突文件：reconcile 不覆盖状态、proposal show 报错、status 扣减 verified、检索降入 Channel 2
      const preConflictRow = db.prepare('SELECT reconcile_state, updated_at FROM reconcile_states WHERE proposal_id = ?').get(propId);
      assert.equal(preConflictRow.reconcile_state, 'verified_applied');
      const movedConflictDir = path.join(vaultPath, '40_Review_Queue', 'dup-after-verified');
      fs.mkdirSync(movedConflictDir, { recursive: true });
      fs.writeFileSync(
        path.join(movedConflictDir, 'PROP-dup-after-verified.md'),
        fs.readFileSync(movedPropPath, 'utf8').replace('proposal_status: "accepted"', 'proposal_status: "pending"'),
        'utf8'
      );
      const recAfterDup = execFileSync(process.execPath, [CLI_PATH, 'reconcile'], { env, encoding: 'utf8' });
      assert.ok(recAfterDup.includes(propId) && recAfterDup.includes('提案 ID 冲突'));
      const postConflictRow = db.prepare('SELECT reconcile_state, updated_at FROM reconcile_states WHERE proposal_id = ?').get(propId);
      assert.equal(postConflictRow.reconcile_state, 'verified_applied', 'reconcile 不得由首/尾文件覆写 reconcile_states');
      assert.equal(postConflictRow.updated_at, preConflictRow.updated_at);
      const statusAfterDup = JSON.parse(execFileSync(process.execPath, [CLI_PATH, 'status', '--json'], { env, encoding: 'utf8' }));
      assert.equal(statusAfterDup.proposals.conflictCount, 2);
      assert.equal(statusAfterDup.proposals.verified, 0);
      assert.throws(() => {
        execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', propId], { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      });
      const searchAfterConflict = searchKnowledge({ db, vaultDir: vaultPath, query: '新版正确步骤 --strict', mode: 'literal', todayStr: '2026-11-10' });
      assert.equal(searchAfterConflict.items[0].actionable, false);
      assert.equal(searchAfterConflict.items[0].reason, 'duplicate_proposal_id_conflict');

      // 3. locateSnapshotEvent 嵌套定位、路径/UUID 零降级与越界/符号链接防护
      const srcDir = path.join(root, 'sources');
      fs.mkdirSync(srcDir, { recursive: true });
      const rawSes1 = path.join(srcDir, 's1.jsonl.zst');
      fs.writeFileSync(rawSes1, zlib.zstdCompressSync(Buffer.from(JSON.stringify({ type: 'user', content: '嵌套会话定位事件内容 A' }) + '\n', 'utf8')));
      const ing1 = ingestSession({
        db,
        vaultDir: vaultPath,
        dataDir,
        sourcePath: rawSes1,
        sourceTool: 'codex',
        sessionId: 'ses-t01-nested-a',
        project: 'M0AProj',
        title: '嵌套会话A',
        sensitivity: 'synthetic'
      });
      assert.equal(ing1.status, 'ingested');
      const sesUuid1 = fs.readFileSync(ing1.readableSessionPath, 'utf8').match(/^id:\s*"?(SES-[^"\s]+)"?/m)[1];
      const sesBase1 = path.basename(ing1.readableSessionPath);
      const sesSubA = path.join(vaultPath, '10_Readable_Sessions', 'subA');
      fs.mkdirSync(sesSubA, { recursive: true });
      const movedSesPath1 = path.join(sesSubA, sesBase1);
      fs.renameSync(ing1.readableSessionPath, movedSesPath1);

      // 3a. 明确相对路径与 UUID 均可定位嵌套会话
      const locByRel = locateSnapshotEvent({
        vaultDir: vaultPath,
        dataDir,
        sourceLink: `[[10_Readable_Sessions/subA/${sesBase1}#^event-000001]]`
      });
      assert.ok(locByRel.rawEventSanitized.includes('嵌套会话定位事件内容 A'));

      const locByUuid = locateSnapshotEvent({
        vaultDir: vaultPath,
        dataDir,
        sourceLink: `[[${sesUuid1}#^event-000001]]`
      });
      assert.equal(locByUuid.snapshotId, locByRel.snapshotId);

      // 3a-2. 日期前缀文件名（如 SES-20261110-abcdef）不应被误判为 UUID 而跳过前缀匹配
      const sesPrefixNoExt = sesBase1.split('_')[0];
      const locByDatePrefix = locateSnapshotEvent({
        vaultDir: vaultPath,
        dataDir,
        sourceLink: `[[${sesPrefixNoExt}#^event-000001]]`
      });
      assert.equal(locByDatePrefix.snapshotId, locByRel.snapshotId);

      // 3b. 明确相对路径未找到（即使另一目录存在同名文件）或 UUID 未找到时，绝不降级成另一目录同名匹配
      const sesSubB = path.join(vaultPath, '10_Readable_Sessions', 'subB');
      fs.mkdirSync(sesSubB, { recursive: true });
      fs.writeFileSync(
        path.join(sesSubB, 'same-name.md'),
        fs.readFileSync(movedSesPath1, 'utf8').replace(sesUuid1, 'SES-019316a8-7c40-7000-8000-330100000088'),
        'utf8'
      );
      fs.writeFileSync(
        path.join(sesSubA, 'same-name.md'),
        fs.readFileSync(movedSesPath1, 'utf8').replace(sesUuid1, 'SES-019316a8-7c40-7000-8000-330100000089'),
        'utf8'
      );

      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[10_Readable_Sessions/missing_dir/same-name.md#^event-000001]]'
        });
      }, /未找到对应的可读会话文件/);

      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[10_Readable_Sessions/same-name.md#^event-000001]]'
        });
      }, /未找到对应的可读会话文件/);

      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[SES-019316a8-7c40-7000-8000-999999999999#^event-000001]]'
        });
      }, /未找到 UUID 对应的可读会话文件/);

      // 3c. 同名裸文件名跨子目录歧义报错，而明确相对路径可消歧
      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[same-name#^event-000001]]'
        });
      }, /ERR_AMBIGUOUS_SESSION_FILE/);

      const locSubB = locateSnapshotEvent({
        vaultDir: vaultPath,
        dataDir,
        sourceLink: '[[10_Readable_Sessions/subB/same-name#^event-000001]]'
      });
      assert.equal(locSubB.readableSessionRelPath, '10_Readable_Sessions/subB/same-name.md');

      // 3d. 越界访问拦截（保持受控定位用途，绝不读取非会话目录或越出 Vault）
      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[../30_Knowledge_Notes/Playbooks/nested/KN-nested#^event-000001]]'
        });
      }, /ERR_SESSION_PATH_OUTSIDE_SCOPE/);
      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[20_Evidence_Cards/EV-anything#^event-000001]]'
        });
      }, /ERR_SESSION_PATH_OUTSIDE_SCOPE/);
      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[50_Bases_Views/知识总览#^event-000001]]'
        });
      }, /ERR_SESSION_PATH_OUTSIDE_SCOPE/);

      // 4. 目录符号链接/Junction（含悬空链接）默认不跟随且不越界
      const outsideDir = path.join(root, 'outside-secret-dir');
      fs.mkdirSync(outsideDir, { recursive: true });
      const outsideFile = path.join(outsideDir, 'SES-outside.md');
      fs.writeFileSync(outsideFile, fs.readFileSync(movedSesPath1, 'utf8').replace(sesUuid1, 'SES-019316a8-7c40-7000-8000-330100000777'), 'utf8');

      const linkInSessions = path.join(vaultPath, '10_Readable_Sessions', 'symlink_outside');
      const linkInQueue = path.join(vaultPath, '40_Review_Queue', 'symlink_outside');
      fs.symlinkSync(outsideDir, linkInSessions, 'junction');
      fs.symlinkSync(outsideDir, linkInQueue, 'junction');

      const danglingDir = path.join(root, 'missing-outside-target');
      const danglingLink = path.join(vaultPath, '10_Readable_Sessions', 'symlink_dangling');
      fs.symlinkSync(danglingDir, danglingLink, 'junction');
      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[10_Readable_Sessions/symlink_dangling/SES-dangling#^event-000001]]'
        });
      }, /ERR_SYMLINK_BLOCKED/);

      const scannedSessions = findMarkdownFiles(path.join(vaultPath, '10_Readable_Sessions'), { boundaryDir: vaultPath });
      assert.equal(scannedSessions.some(p => p.includes('SES-outside.md')), false, 'findMarkdownFiles 默认绝不可跟随目录链接进入外部目录');

      assert.throws(() => {
        locateSnapshotEvent({
          vaultDir: vaultPath,
          dataDir,
          sourceLink: '[[10_Readable_Sessions/symlink_outside/SES-outside#^event-000001]]'
        });
      }, /ERR_SYMLINK_BLOCKED|ERR_PATH_OUTSIDE_BOUNDARY/);

      assert.throws(() => {
        findMarkdownFiles(linkInSessions, { boundaryDir: vaultPath });
      }, /ERR_SYMLINK_BLOCKED|ERR_PATH_OUTSIDE_BOUNDARY/);

      assert.throws(() => {
        findMarkdownFiles(outsideDir, { boundaryDir: vaultPath });
      }, /ERR_PATH_OUTSIDE_BOUNDARY/);

      assert.ok(fs.existsSync(targetPath));
    } finally {
      db.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('V3.3-T02: query-engine 回退 100% 复用真实 Mode 0，并拒绝 [] / 非数组 / 重复 / 越界 orderedIds', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v33-t02');
    const db = openDatabase(dbPath);
    try {
      const idA = 'KN-019316a8-7c40-7000-8000-330200000001';
      const idB = 'KN-019316a8-7c40-7000-8000-330200000002';
      const idSem = 'KN-019316a8-7c40-7000-8000-330200000003';
      const idToken = 'KN-019316a8-7c40-7000-8000-330200000004';

      publishKnowledgeNote({
        db, vaultPath, dataPath, id: idA,
        relPath: '30_Knowledge_Notes/Playbooks/KN-a.md',
        title: '网络代理节点A',
        body: '处理 容器端口映射 服务故障方案 alpha --port=8080'
      });
      publishKnowledgeNote({
        db, vaultPath, dataPath, id: idB,
        relPath: '30_Knowledge_Notes/Playbooks/KN-b.md',
        title: '网络代理节点B',
        body: '处理 容器端口映射 服务备选方案 alpha'
      });
      // 纯语义候选：对查询 "容器端口映射" literalScore === 0（无连续子串），但二元分词余弦 hybridScore >= 1.2
      publishKnowledgeNote({
        db, vaultPath, dataPath, id: idSem,
        relPath: '30_Knowledge_Notes/Playbooks/KN-sem.md',
        title: '语义候选笔记',
        body: '记录 容器 与 端口 及 映射 配置详情，用于检验混合召回在回退时必须被清除。'
      });
      publishKnowledgeNote({
        db, vaultPath, dataPath, id: idToken,
        relPath: '30_Knowledge_Notes/Playbooks/KN-tok.md',
        title: '精确符号参数笔记',
        body: '执行命令 --strict-flag=true 完成校验'
      });

      const indexDir = path.join(dataPath, 'runtime', 'index');
      const appr = issueTrustedEgressApproval({
        db,
        snapshotId: 'benchmark-or-search',
        provider: 'siliconflow',
        purpose: 'rerank',
        trustedHumanContext: true
      });

      // 先验证该查询在 hybrid 下确实包含纯语义候选 idSem，而 literal (Mode 0) 仅返回 A 与 B 且分值不同
      const hybridCheck = searchKnowledge({
        db, vaultDir: vaultPath, query: '容器端口映射', mode: 'hybrid', indexDir, todayStr: '2026-11-10'
      });
      assert.equal(hybridCheck.items.length, 3, '前置条件：hybrid 必须召回 A、B 与纯语义候选 C');
      assert.ok(hybridCheck.items.some(i => i.id === idSem), '前置条件：hybrid 必须召回纯语义候选');

      const expectedMode0 = searchKnowledge({
        db, vaultDir: vaultPath, query: '容器端口映射', mode: 'literal', indexDir, todayStr: '2026-11-10'
      });
      assert.equal(expectedMode0.items.length, 2, 'Mode 0 对精确词仅返回 A 与 B');

      // 1. 测试空数组 [] 必须被判无效并回退真实 Mode 0
      const emptyRes = searchKnowledge({
        db,
        vaultDir: vaultPath,
        query: '容器端口映射',
        mode: 'rerank',
        indexDir,
        todayStr: '2026-11-10',
        provider: 'siliconflow',
        egressApprovalId: appr.egressApprovalId,
        externalRerankFn: () => []
      });
      assert.equal(emptyRes.mode, 'literal');
      assert.equal(emptyRes.fallbackUsed, true);
      assert.equal(emptyRes.fallbackReason, 'invalid_rerank_output_fallback_to_mode0:empty_array');
      assert.ok(emptyRes.egressBytes > 0);
      assert.deepEqual(emptyRes.items, expectedMode0.items);
      assert.equal(emptyRes.noAnswer, expectedMode0.noAnswer);

      // 2. 测试抛出异常 / 非数组 / 重复 ID / 越界 ID 全部回退且与直接 Mode 0 完全一致（无 hybridScore 残余）
      const invalidCases = [
        { name: 'throw', fn: () => { throw new Error('upstream_502'); }, expectedReason: 'external_rerank_error_fallback_to_mode0:upstream_502' },
        { name: 'non_array', fn: () => ({ ids: [idA] }), expectedReason: 'invalid_rerank_output_fallback_to_mode0:not_array' },
        { name: 'duplicate', fn: () => [idA, idA], expectedReason: 'invalid_rerank_output_fallback_to_mode0:duplicate_id' },
        { name: 'out_of_set', fn: () => [idA, 'KN-OUT-OF-CANDIDATE-SET'], expectedReason: 'invalid_rerank_output_fallback_to_mode0:out_of_candidate_set' }
      ];
      for (const c of invalidCases) {
        const res = searchKnowledge({
          db,
          vaultDir: vaultPath,
          query: '容器端口映射',
          mode: 'rerank',
          indexDir,
          todayStr: '2026-11-10',
          provider: 'siliconflow',
          egressApprovalId: appr.egressApprovalId,
          externalRerankFn: c.fn
        });
        assert.equal(res.mode, 'literal', `${c.name} 必须回退 literal`);
        assert.equal(res.fallbackUsed, true);
        assert.equal(res.fallbackReason, c.expectedReason);
        assert.ok(res.egressBytes > 0);
        assert.deepEqual(res.items, expectedMode0.items, `${c.name} 回退结果与真实 Mode 0 必须 100% 一致`);
        assert.equal(res.noAnswer, expectedMode0.noAnswer);
      }

      // 3. 缺批准回退：egressBytes === 0 且保留 missing_egress_approval_fallback_to_mode0
      const noApprRes = searchKnowledge({
        db,
        vaultDir: vaultPath,
        query: '容器端口映射',
        mode: 'rerank',
        indexDir,
        todayStr: '2026-11-10',
        provider: 'siliconflow',
        egressApprovalId: null,
        externalRerankFn: () => [idB, idA]
      });
      assert.equal(noApprRes.fallbackUsed, true);
      assert.equal(noApprRes.fallbackReason, 'missing_egress_approval_fallback_to_mode0');
      assert.equal(noApprRes.egressBytes, 0);
      assert.deepEqual(noApprRes.items, expectedMode0.items);

      // 4. 带符号精确词 + 合法部分子集重排 [idB] 正常生效
      const symMode0 = searchKnowledge({ db, vaultDir: vaultPath, query: '--strict-flag=true', mode: 'literal', todayStr: '2026-11-10' });
      assert.equal(symMode0.items[0].id, idToken);

      const validRerank = searchKnowledge({
        db,
        vaultDir: vaultPath,
        query: '容器端口映射',
        mode: 'rerank',
        indexDir,
        todayStr: '2026-11-10',
        provider: 'siliconflow',
        egressApprovalId: appr.egressApprovalId,
        externalRerankFn: () => [idB]
      });
      assert.equal(validRerank.mode, 'rerank');
      assert.equal(validRerank.fallbackUsed, false);
      assert.equal(validRerank.items[0].id, idB);
    } finally {
      db.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('V3.3-T03: 评测前 5 唯一 actionableHit@5 / rawHit@5、main/holdout 分母、「不可评估」、参与评分证据链与 approvalDb 隔离', () => {
    const { root, vaultPath, dataPath: dataDir, dbPath } = makeTempEnv('v33-t03');
    const db = openDatabase(dbPath);
    try {
      // A. 验证 14 题试点集上：单请求 P50/P95、旧字段兼容、actionableHit@5、splits、approvalDb 隔离无 state.sqlite 复制
      const pilotCorpusDir = path.join(root, 'pilot-synth');
      const pilotReport = runBenchmarkSuite({
        suite: 'pilot',
        corpusDir: pilotCorpusDir,
        outputPath: path.join(root, 'pilot-out.json')
      });
      const m0 = pilotReport.modes['Mode 0 (literal)'];
      const m2Timeout = pilotReport.modes['Mode 2 (fallback_drill_timeout)'];
      assert.equal(m0.actionableHitAt5, 1);
      assert.equal(m0.rawHitAt5, 1);
      assert.equal(m0.actionableMrrAt5, 1);
      assert.equal(m0.evaluable, true);
      assert.equal(m0.evaluationStatus, 'evaluable');
      assert.deepEqual(m0.denominators, { total: 14, answerable: 10, noAnswer: 2, conflictOrStaleTrap: 2 });
      assert.ok(typeof m0.p50RequestLatencyMs === 'number' && m0.p50RequestLatencyMs >= 0);
      assert.ok(typeof m0.p95RequestLatencyMs === 'number' && m0.p95RequestLatencyMs >= m0.p50RequestLatencyMs);
      assert.equal(m0.estimatedCostCny, m0.legacyByteEstimateCostCny);
      assert.equal(m0.costBasisVersion, 'legacy_byte_estimate_v1');
      assert.equal(m0.splits.holdout.evaluationStatus, '不可评估');
      assert.equal(m0.splits.holdout.actionableHitAt5, null);
      assert.equal(m2Timeout.actionableHitAt5, m0.actionableHitAt5, '使用独立 approvalDb 演练时，不能将原库笔记误标为未登记');

      // 确认 runner.mjs 中不再存在 state.sqlite 的 copyFileSync
      const runnerSource = fs.readFileSync(path.resolve('src/benchmark/runner.mjs'), 'utf8');
      assert.equal(runnerSource.includes('copyFileSync'), false, 'runner.mjs 禁止使用 copyFileSync 复制 state.sqlite');

      // B. 构造 Channel 2 命中陷阱 + 仅目录孤立来源标签（未参与评分证据链）+ holdout 集
      const srcDir = path.join(root, 'sources');
      fs.mkdirSync(srcDir, { recursive: true });
      const makeSessionAndEvidence = (tool, sesId, evId, sesTitle) => {
        const sFile = path.join(srcDir, `${tool}.jsonl`);
        fs.writeFileSync(sFile, JSON.stringify({ type: 'user', content: `${tool} 证据内容` }) + '\n', 'utf8');
        const ing = ingestSession({
          db, vaultDir: vaultPath, dataDir, sourcePath: sFile, sourceTool: tool, sessionId: sesId, project: 'M0AProj', title: sesTitle, sensitivity: 'synthetic'
        });
        assert.equal(ing.status, 'ingested', `${tool} ingest status should be ingested`);
        const sesBase = path.basename(ing.readableSessionPath);
        const evFile = path.join(vaultPath, '20_Evidence_Cards', `${evId}.md`);
        const evContent = `---
schema_version: 1
id: "${evId}"
note_type: "evidence"
title: "${tool} 证据卡"
project: "M0AProj"
privacy: "sanitized"
source_tool: "${tool}"
evidence_level: "observed"
sources:
  - "[[10_Readable_Sessions/${sesBase}#^event-000001]]"
created_at: "2026-11-10T12:00:00+08:00"
---
# ${tool} 证据卡
`;
        const stg = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: evId, content: evContent });
        publishFile({
          db, operationId: `op-${evId}`, outputUuid: evId, stagingPath: stg.stagingPath, vaultTargetPath: evFile, contentSha256: stg.contentSha256,
          metadata: { note_type: 'evidence', source_tool: tool, title: `${tool} 证据卡`, project: 'M0AProj', privacy: 'sanitized' }
        });
        return `[[20_Evidence_Cards/${evId}.md]]`;
      };

      const evCodex = makeSessionAndEvidence('codex', 't03-codex', 'EV-019316a8-7c40-7000-8000-330300000e01', 'Codex会话');
      const evAgy = makeSessionAndEvidence('antigravity', 't03-agy', 'EV-019316a8-7c40-7000-8000-330300000e02', 'Agy会话');
      // 孤立 DSH 会话文件 + 子目录同名文件（若 KN 明确指向不存在的子路径 10_Readable_Sessions/missing_dir/dsh-same.md，绝不降级命中该子目录同名 DSH）
      const dshOrphanRaw = path.join(srcDir, 'dsh-orphan.jsonl');
      fs.writeFileSync(dshOrphanRaw, JSON.stringify({ type: 'user', content: '孤立DSH' }) + '\n', 'utf8');
      const dshIng = ingestSession({
        db, vaultDir: vaultPath, dataDir, sourcePath: dshOrphanRaw, sourceTool: 'dsh', sessionId: 't03-dsh-orphan', project: 'M0AProj', title: '孤立DSH会话', sensitivity: 'synthetic'
      });
      assert.equal(dshIng.status, 'ingested');
      const dshSubDir = path.join(vaultPath, '10_Readable_Sessions', 'subDsh');
      fs.mkdirSync(dshSubDir, { recursive: true });
      fs.renameSync(dshIng.readableSessionPath, path.join(dshSubDir, 'dsh-same.md'));

      const knActionable = 'KN-019316a8-7c40-7000-8000-330300000001';
      publishKnowledgeNote({
        db, vaultPath, dataPath: dataDir, id: knActionable,
        relPath: '30_Knowledge_Notes/Playbooks/KN-main-ok.md',
        title: '网关超时排查主集条目',
        sources: [evCodex, '[[10_Readable_Sessions/missing_dir/dsh-same.md#^event-000001]]'],
        body: '主集正确答案：检查 upstream_timeout 参数'
      });

      const knCh2Trap = 'KN-019316a8-7c40-7000-8000-330300000002';
      publishKnowledgeNote({
        db, vaultPath, dataPath: dataDir, id: knCh2Trap,
        relPath: '30_Knowledge_Notes/Playbooks/KN-ch2-expected.md',
        title: '留出题未审核条目',
        reviewState: 'draft', // 处于 Channel 2 (actionable: false)
        sources: [evAgy],
        body: '留出题命中但处于 draft，不可操作 holdout_ch2_marker'
      });

      // 构造 6 条共享关键词 rank6_probe 的可操作笔记，其中 5 条同时命中标题（分值 14），期望笔记仅正文命中（分值 4，落于第 6 位即前 5 之外）
      for (let idx = 1; idx <= 5; idx++) {
        publishKnowledgeNote({
          db, vaultPath, dataPath: dataDir, id: `KN-019316a8-7c40-7000-8000-33030000010${idx}`,
          relPath: `30_Knowledge_Notes/Playbooks/KN-rank-${idx}.md`,
          title: `rank6_probe 干扰项 ${idx}`,
          sources: [evCodex],
          body: `包含 rank6_probe 的高分干扰条目 ${idx}`
        });
      }
      const knRank6 = 'KN-019316a8-7c40-7000-8000-330300000106';
      publishKnowledgeNote({
        db, vaultPath, dataPath: dataDir, id: knRank6,
        relPath: '30_Knowledge_Notes/Playbooks/KN-rank-6.md',
        title: '低分目标条目',
        sources: [evCodex],
        body: '仅在正文命中 rank6_probe，排序位于第 6 位（前 5 之外）'
      });

      const customQuestions = [
        { id: 'MQ1', query: 'upstream_timeout', project: 'M0AProj', expectedIds: [knActionable], isNoAnswer: false, expectNonActionableOnly: false },
        { id: 'MQ2', query: '完全不存在的词xyz999', project: 'M0AProj', expectedIds: [], isNoAnswer: true, expectNonActionableOnly: false },
        { id: 'MQ3', query: 'holdout_ch2_marker', project: 'M0AProj', expectedIds: [knCh2Trap], isNoAnswer: false, expectNonActionableOnly: true },
        { id: 'HQ1', split: 'holdout', query: 'holdout_ch2_marker', project: 'M0AProj', expectedIds: [knCh2Trap], isNoAnswer: false, expectNonActionableOnly: false },
        { id: 'HQ2', split: 'holdout', query: 'rank6_probe', project: 'M0AProj', expectedIds: [knRank6], isNoAnswer: false, expectNonActionableOnly: false }
      ];

      db.close();
      const customReport = runBenchmarkSuite({
        suite: 'pilot',
        vaultDir: vaultPath,
        dataDir,
        questions: customQuestions,
        outputPath: path.join(root, 'custom-report.json'),
        allowIndexWrite: false,
        todayStr: '2026-11-10'
      });

      // 孤立 DSH 标签与错误相对路径不应混入参与评分的三来源核对
      assert.deepEqual(customReport.corpusSourceCoverage, ['antigravity', 'codex']);

      const cm0 = customReport.modes['Mode 0 (literal)'];
      // 主集全可评估且命中
      assert.equal(cm0.splits.main.evaluable, true);
      assert.equal(cm0.splits.main.evaluationStatus, 'evaluable');
      assert.equal(cm0.splits.main.actionableHitAt5, 1);
      assert.equal(cm0.splits.main.rawHitAt5, 1);
      assert.deepEqual(cm0.splits.main.denominators, { total: 3, answerable: 1, noAnswer: 1, conflictOrStaleTrap: 1 });

      // holdout 中 HQ1 为前 5 内 Channel 2 命中 (raw=1, actionable=0)，HQ2 为前 5 之外真实命中 (raw=0, actionable=0)
      assert.equal(cm0.splits.holdout.rawHitAt5, 0.5);
      assert.equal(cm0.splits.holdout.actionableHitAt5, 0);
      assert.equal(cm0.splits.holdout.actionableEvaluationStatus, 'evaluable');
      assert.equal(cm0.splits.holdout.evaluationStatus, '不可评估');
      assert.equal(cm0.splits.holdout.noAnswerAccuracy, null);
      assert.deepEqual(cm0.splits.holdout.denominators, { total: 2, answerable: 2, noAnswer: 0, conflictOrStaleTrap: 0 });
    } finally {
      try { db.close(); } catch {}
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test('V3.3-T04: §3.3 对齐 — sanitized 未登记手建笔记在 Mode 0 留作 Channel 2，local_only/缺 privacy 永不返回', () => {
    const { root, vaultPath, dataPath, dbPath } = makeTempEnv('v33-t04');
    const db = openDatabase(dbPath);
    try {
      const notesDir = path.join(vaultPath, '30_Knowledge_Notes', 'Playbooks');
      fs.mkdirSync(notesDir, { recursive: true });

      const unregPath = path.join(notesDir, 'KN-manual-unreg.md');
      fs.writeFileSync(unregPath, `---
schema_version: 1
id: "KN-019316a8-7c40-7000-8000-330400000001"
note_type: "playbook"
title: "手建未登记合规笔记"
project: "M0AProj"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
created_at: "2026-11-10T12:00:00+08:00"
---
手建未登记关键词 unique_unreg_token_v33
`, 'utf8');

      const localPath = path.join(notesDir, 'KN-manual-local.md');
      fs.writeFileSync(localPath, `---
schema_version: 1
id: "KN-019316a8-7c40-7000-8000-330400000002"
note_type: "playbook"
title: "私密手建笔记"
project: "M0AProj"
privacy: "local_only"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
created_at: "2026-11-10T12:00:00+08:00"
---
手建私密关键词 unique_local_token_v33
`, 'utf8');

      const missingPrivPath = path.join(notesDir, 'KN-manual-nopriv.md');
      fs.writeFileSync(missingPrivPath, `---
schema_version: 1
id: "KN-019316a8-7c40-7000-8000-330400000003"
note_type: "playbook"
title: "缺少隐私字段笔记"
project: "M0AProj"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
created_at: "2026-11-10T12:00:00+08:00"
---
缺少隐私关键词 unique_nopriv_token_v33
`, 'utf8');

      const resUnreg = searchKnowledge({ db, vaultDir: vaultPath, query: 'unique_unreg_token_v33', mode: 'literal', todayStr: '2026-11-10' });
      assert.equal(resUnreg.items.length, 1);
      assert.equal(resUnreg.items[0].actionable, false);
      assert.equal(resUnreg.items[0].reason, 'unregistered_note_pending_enrollment');

      const resLocal = searchKnowledge({ db, vaultDir: vaultPath, query: 'unique_local_token_v33', mode: 'literal', todayStr: '2026-11-10' });
      assert.equal(resLocal.items.length, 0);
      assert.equal(resLocal.noAnswer, true);

      const resNoPriv = searchKnowledge({ db, vaultDir: vaultPath, query: 'unique_nopriv_token_v33', mode: 'literal', todayStr: '2026-11-10' });
      assert.equal(resNoPriv.items.length, 0);
      assert.equal(resNoPriv.noAnswer, true);

      // 确保 PILOT_QUESTIONS 未被破坏
      assert.equal(PILOT_QUESTIONS.length, 14);
    } finally {
      db.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
