import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { openDatabase } from '../src/db/sqlite.mjs';
import { initRepository } from '../src/init.mjs';
import {
  createSessionSanitizer,
  sanitizeOutputText,
  detectResidualSecrets
} from '../src/security/sanitizer.mjs';
import { issueTrustedEgressApproval } from '../src/security/trusted-approvals.mjs';
import { exportEgressPackage } from '../src/egress/egress-controller.mjs';
import { ingestSession, distillSnapshotFacts, locateSnapshotEvent } from '../src/ingest/session-ingestor.mjs';
import { createProposal, parseProposalContent, reconcileProposal } from '../src/reconcile/engine.mjs';
import { searchKnowledge } from '../src/search/query-engine.mjs';
import { registerManualNote } from '../src/tombstone/tracker.mjs';
import { parseMarkdownFrontmatter } from '../src/schema/frontmatter.mjs';
import { stageCandidate, recoverInterruptedPublish } from '../src/storage/atomic-publisher.mjs';
import { createConsistentBackup, restoreFromBackup } from '../src/backup/backup-manager.mjs';

const CLI_PATH = path.resolve('cli/mem.mjs');

test('B07: 全量代码审计回归测试 (覆盖脱敏/解压定位/遍历防护/防空提案/R1记账/R4校验/CLI完整链路)', async (t) => {
  const baseDir = path.resolve('.tmp/test-b07-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');
  const srcDir = path.join(baseDir, 'sources');
  fs.mkdirSync(srcDir, { recursive: true });
  initRepository({ vaultPath: vaultDir, dataPath: dataDir });
  const dbPath = path.join(dataDir, 'runtime', 'state.sqlite');
  const db = openDatabase(dbPath);

  t.after(() => {
    try {
      db.close();
    } catch {}
    try {
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {}
  });

  await t.test('1. Sanitizer 与 Exit A 递归字段脱敏覆盖 JSON 键值、Basic Auth 与任意 raw/ 路径', () => {
    const s = createSessionSanitizer();
    const dynSecret = ['mySecretKey', '998877', 'Alpha'].join('');
    const dynPwd = ['Adm1n', 'Pass', 'word!88'].join('');
    const dynTok = ['tok', 'Plain', 'Secret123'].join('_');
    const dynBasic = Buffer.from('user:secretpass').toString('base64');

    const jsonPayload = JSON.stringify({
      api_key: dynSecret,
      password: dynPwd,
      token: dynTok,
      cookie: 'sid=abc998877; path=/',
      authorization: `Basic ${dynBasic}`
    });

    const out = s.sanitize(jsonPayload).text;
    assert.equal(out.includes(dynSecret), false);
    assert.equal(out.includes(dynPwd), false);
    assert.equal(out.includes(dynTok), false);
    assert.equal(out.includes('abc998877'), false);
    assert.equal(out.includes(dynBasic), false);
    assert.equal(detectResidualSecrets(out).clean, true);

    assert.equal(sanitizeOutputText('ENOENT: D:\\Temp\\b01-xyz\\raw\\sentinel.jsonl').includes('\\raw\\'), false);
    assert.equal(sanitizeOutputText('path=raw/secret.jsonl').includes('raw/secret'), false);
    assert.equal(detectResidualSecrets('{"password":"rawPlainPassword"}').clean, false);

    // Exit A 必须递归清洗除 title/text 之外的 summary/metadata 字段
    const appr = issueTrustedEgressApproval({
      db,
      snapshotId: 'snap-b07-1',
      provider: 'siliconflow',
      purpose: 'distill',
      trustedHumanContext: true
    });
    const egr = exportEgressPackage({
      db,
      dataPath: dataDir,
      snapshotId: 'snap-b07-1',
      egressApprovalId: appr.egressApprovalId,
      provider: 'siliconflow',
      purpose: 'distill',
      items: [{
        id: 'EV-B07-1',
        privacy: 'sanitized',
        title: 'ok',
        summary: `password=${dynPwd}`,
        metadata: { nestedAuth: `Basic ${dynBasic}`, rawRef: 'D:\\Other\\raw\\s1.jsonl' }
      }]
    });
    const pkgText = fs.readFileSync(egr.egressPath, 'utf8');
    assert.equal(pkgText.includes(dynPwd), false);
    assert.equal(pkgText.includes(dynBasic), false);
    assert.equal(pkgText.includes('s1.jsonl'), false);
    assert.equal(detectResidualSecrets(pkgText).clean, true);
  });

  await t.test('2. 会话导入字节偏移精确切片、锚点防劫持、附件穿越阻断、YAML 防注入与版本重建一致性', () => {
    const outsideSecret = path.join(baseDir, 'outside-secret.txt');
    fs.writeFileSync(outsideSecret, 'DO_NOT_EXFILTRATE_OUTSIDE_SECRET', 'utf8');

    const lines = [
      JSON.stringify({ type: 'user', content: '诱饵锚点 ^event-000002 不应劫持定位', attachment: '../../outside-secret.txt' }),
      JSON.stringify({ type: 'assistant', content: '真实第二事件：中文多字节与符号 🚀 验证' })
    ];
    const zstPath = path.join(srcDir, 'b07-mixed.jsonl.zst');
    const rawBuf = Buffer.from('\uFEFF' + lines.join('\r\n') + '\r\n', 'utf8');
    fs.writeFileSync(zstPath, zlib.zstdCompressSync(rawBuf));

    const ing = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: zstPath,
      sessionId: 'sess-b07-01',
      title: '正常标题"\nprivacy: "sanitized',
      privacy: 'local_only',
      sensitivity: 'synthetic'
    });
    assert.equal(ing.status, 'ingested');
    assert.equal(fs.existsSync(path.join(dataDir, 'attachments', 'outside-secret.txt')), false, '禁止穿越读取源目录外文件');
    assert.ok(ing.anomalies.some(a => a.type === 'blocked_attachment_traversal'));

    // 确认 title 中的换行被安全转义，privacy 保持 local_only
    const md = fs.readFileSync(ing.readableSessionPath, 'utf8');
    assert.equal(parseMarkdownFrontmatter(md).frontmatter.privacy, 'local_only');

    // 支持带 |别名 的 wikilink，且不被事件 1 中的 ^event-000002 文本劫持
    const sessionBase = path.basename(ing.readableSessionPath, '.md');
    const loc = locateSnapshotEvent({
      vaultDir,
      dataDir,
      sourceLink: `[[10_Readable_Sessions/${sessionBase}#^event-000002|事件2别名]]`
    });
    assert.equal(loc.eventId, 2);
    assert.ok(loc.readableExcerpt.includes('真实第二事件'));
    assert.ok(loc.rawEventSanitized.includes('🚀'));

    // dryRun 升级检测 & 真实升级重建保持 YAML id 与 DB id 完全一致
    const dryRebuild = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: zstPath,
      sessionId: 'sess-b07-01',
      parserVersion: 'v2.9.0',
      privacy: 'local_only',
      sensitivity: 'synthetic',
      dryRun: true
    });
    assert.equal(dryRebuild.status, 'dry_run_rebuild_derived_session');

    const rebuild = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: zstPath,
      sessionId: 'sess-b07-01',
      parserVersion: 'v2.9.0',
      privacy: 'local_only',
      sensitivity: 'synthetic'
    });
    assert.equal(rebuild.status, 'rebuilt_derived_session');
    const rebuiltYamlId = parseMarkdownFrontmatter(fs.readFileSync(rebuild.readableSessionPath, 'utf8')).frontmatter.id;
    const rebuiltDbRow = db.prepare('SELECT id FROM notes WHERE path = ?').get(rebuild.readableSessionPath);
    assert.equal(rebuiltDbRow.id, rebuiltYamlId);

    // 增量快照自动强制 K+1..N 范围（即使调用方未显式传 range）
    const snap1Res = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: zstPath,
      sessionId: 'sess-b07-distill',
      sensitivity: 'synthetic'
    });
    distillSnapshotFacts({
      db,
      snapshotId: snap1Res.snapshotId,
      facts: [{ eventId: 1, factType: 'fact', normalizedSubject: 's1', title: 'S1', summary: 'old' }]
    });
    const zst2Path = path.join(srcDir, 'b07-appended.jsonl.zst');
    const lines2 = [...lines, JSON.stringify({ type: 'user', content: '新增第三事件' })];
    fs.writeFileSync(zst2Path, zlib.zstdCompressSync(Buffer.from('\uFEFF' + lines2.join('\r\n') + '\r\n', 'utf8')));
    const snap2Res = ingestSession({
      db,
      vaultDir,
      dataDir,
      sourcePath: zst2Path,
      sessionId: 'sess-b07-distill',
      sensitivity: 'synthetic'
    });
    const autoInc = distillSnapshotFacts({
      db,
      snapshotId: snap2Res.snapshotId,
      facts: [
        { eventId: 1, factType: 'fact', normalizedSubject: 's1', title: 'S1', summary: 'old' },
        { eventId: 3, factType: 'fact', normalizedSubject: 's3', title: 'S3', summary: 'new' }
      ]
    });
    assert.equal(autoInc.skippedOutOfRange.length, 1);
    assert.equal(autoInc.acceptedFacts.length, 1);
    assert.equal(autoInc.acceptedFacts[0].eventId, 3);
  });

  await t.test('3. YAML Frontmatter 边缘解析、防空条件绕过、时间戳复核到期与环境匹配', () => {
    const complexFm = parseMarkdownFrontmatter(
      '---\nid: "KN-1"\ntitle: "Fix \'401\' bug"\nas_of:\nreview_after: "2026-11-10T09:00:00+08:00"\nenv:\n  os: "windows"\naliases: ["a", "b"]\n---\nbody'
    ).frontmatter;
    assert.equal(complexFm.title, "Fix '401' bug");
    assert.equal(complexFm.as_of, null);
    assert.equal(complexFm.env.os, 'windows');
    assert.deepEqual(complexFm.aliases, ['a', 'b']);

    // 空条件提案严禁自动通过 verified_applied
    const notesDir = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks');
    const targetPath = path.join(notesDir, 'KN-vacuous.md');
    fs.writeFileSync(
      targetPath,
      '---\nschema_version: 1\nid: "KN-VAC-1"\nnote_type: "playbook"\ntitle: "空条件测试"\nproject: "B07"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv:\n  os: "windows"\nreview_after: "2026-11-10T18:00:00+08:00"\ncreated_at: "2026-11-01T00:00:00+08:00"\n---\n旧内容\n',
      'utf8'
    );
    registerManualNote({ db, vaultDir, filePath: targetPath });
    const prop = createProposal({
      queueDir: path.join(vaultDir, '40_Review_Queue'),
      proposalUuid: 'PROP-VAC-1',
      title: '空条件提案',
      project: 'B07',
      targetId: 'KN-VAC-1',
      targetNoteRef: '[[KN-vacuous]]',
      proposalKind: 'conflict',
      preConditions: [],
      postConditions: []
    });
    fs.writeFileSync(prop.proposalPath, fs.readFileSync(prop.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
    const rec = reconcileProposal({ db, proposalPath: prop.proposalPath, targetPath });
    assert.equal(rec.reconcile_state, 'mismatch');
    assert.equal(rec.reason, 'missing_structured_conditions');

    // review_after 为当日 ISO 时间戳必须归入 Channel 2；且 env 不匹配归入 Channel 2
    const srExp = searchKnowledge({ db, vaultDir, query: '空条件测试', project: 'B07', todayStr: '2026-11-10' });
    assert.equal(srExp.items[0].actionable, false);

    // 移除提案与到期限制后验证 env 过滤
    fs.unlinkSync(prop.proposalPath);
    fs.writeFileSync(
      targetPath,
      fs.readFileSync(targetPath, 'utf8').replace('2026-11-10T18:00:00+08:00', '2026-12-31'),
      'utf8'
    );
    const srEnvMismatch = searchKnowledge({ db, vaultDir, query: '空条件测试', project: 'B07', env: 'linux', todayStr: '2026-11-10' });
    assert.equal(srEnvMismatch.items[0].actionable, false);
    assert.ok(srEnvMismatch.items[0].reason.includes('env_mismatch'));
    const srEnvOk = searchKnowledge({ db, vaultDir, query: '空条件测试', project: 'B07', env: 'windows', todayStr: '2026-11-10' });
    assert.equal(srEnvOk.items[0].actionable, true);

    // 清理 Test 3 临时受控登记笔记，避免影响后续子测试的 B07 LIMIT 1 选择
    db.prepare("DELETE FROM notes WHERE id = 'KN-VAC-1'").run();
    if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
  });

  await t.test('4. CLI 完整链路: stage-candidate + publish, local_only delete 防泄, 真实版本 restore, reconcile 回退与 init 保护', () => {
    const env = { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir };

    // 4a. stage-candidate -> publish -> delete -> restore 保留完整 Frontmatter 与正文
    const candId = 'KN-019316a8-7c40-7000-8000-b07000000001';
    const candContent = `---
schema_version: 1
id: "${candId}"
note_type: "playbook"
title: "CLI全链路恢复验证"
project: "B07"
privacy: "sanitized"
lifecycle: "active"
evidence_level: "observed"
review_state: "accepted"
env: "windows"
created_at: "2026-11-10T12:00:00+08:00"
---
## 1. 现象与触发情境
完整正文字段必须被 mem restore 原样恢复
`;
    const candFile = path.join(srcDir, 'cand-b07.json');
    fs.writeFileSync(candFile, JSON.stringify({ id: candId, operation_id: 'op-b07-cli', content: candContent }), 'utf8');

    const stgOut = execFileSync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', candFile], { env, encoding: 'utf8' });
    assert.ok(stgOut.includes('operation: op-b07-cli'));

    const pubOut = execFileSync(process.execPath, [CLI_PATH, 'publish', '--operation', 'op-b07-cli'], { env, encoding: 'utf8' });
    assert.ok(pubOut.includes('[mem publish 成功]'));

    execFileSync(process.execPath, [CLI_PATH, 'delete', candId, '--confirm'], { env, encoding: 'utf8' });
    const restPreviewOut = execFileSync(process.execPath, [CLI_PATH, 'restore', candId, '--revision', 'rev-0001'], { env, encoding: 'utf8' });
    assert.ok(restPreviewOut.includes('[mem restore 预览]'));
    assert.equal(fs.existsSync(db.prepare('SELECT path FROM notes WHERE id = ?').get(candId).path), false, '未确认恢复前绝不可写回 Vault 文件');
    const restOut = execFileSync(process.execPath, [CLI_PATH, 'restore', candId, '--revision', 'rev-0001', '--confirm'], { env, encoding: 'utf8' });
    assert.ok(restOut.includes('[mem restore 成功]'));

    const noteRow = db.prepare('SELECT path FROM notes WHERE id = ?').get(candId);
    const restoredText = fs.readFileSync(noteRow.path, 'utf8');
    assert.ok(restoredText.includes('完整正文字段必须被 mem restore 原样恢复'), 'mem restore 绝不可只写回单行占位符');
    assert.equal(parseMarkdownFrontmatter(restoredText).frontmatter.id, candId);

    // 4b. local_only 笔记 mem delete 预览严禁泄露标题与路径
    const localId = 'KN-019316a8-7c40-7000-8000-b07000000002';
    const localSecretName = '私密银行凭证笔记';
    const localCand = path.join(srcDir, 'cand-local.json');
    fs.writeFileSync(localCand, JSON.stringify({
      id: localId,
      operation_id: 'op-b07-local',
      content: `---\nschema_version: 1\nid: "${localId}"\nnote_type: "playbook"\ntitle: "${localSecretName}"\nproject: "B07"\nprivacy: "local_only"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv: "windows"\ncreated_at: "2026-11-10T12:00:00+08:00"\n---\n机密正文\n`
    }), 'utf8');
    execFileSync(process.execPath, [CLI_PATH, 'stage-candidate', '--input', localCand], { env, encoding: 'utf8' });
    execFileSync(process.execPath, [CLI_PATH, 'publish', '--operation', 'op-b07-local'], { env, encoding: 'utf8' });

    const delPreview = execFileSync(process.execPath, [CLI_PATH, 'delete', localId], { env, encoding: 'utf8' });
    assert.equal(delPreview.includes(localSecretName), false, 'local_only 标题与路径文件名绝不能出现在 delete 预览输出');
    assert.ok(delPreview.includes('[REDACTED_LOCAL_ONLY]'));

    // 4c. 备份目标不得位于 Vault/Data 内部；R1 恢复必须同步写入 notes 表
    assert.throws(() => {
      createConsistentBackup({ vaultPath: vaultDir, dataPath: dataDir, targetDir: path.join(dataDir, 'inside-backup') });
    }, /INVALID_BACKUP_TARGET/);

    const r1CrashId = 'KN-019316a8-7c40-7000-8000-b07000000003';
    const r1Path = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-20261110-000003_R1自动入库.md');
    const r1Content = `---\nschema_version: 1\nid: "${r1CrashId}"\nnote_type: "playbook"\ntitle: "R1自动入库"\nproject: "B07"\nprivacy: "sanitized"\nlifecycle: "active"\nevidence_level: "observed"\nreview_state: "accepted"\nenv: "windows"\ncreated_at: "2026-11-10T12:00:00+08:00"\n---\nR1恢复正文\n`;
    const r1Staged = stageCandidate({ stagingDir: path.join(dataDir, 'staging'), outputUuid: r1CrashId, content: r1Content });
    db.prepare(`
      INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
      VALUES ('op-b07-r1', ?, ?, ?, ?, 'linking', datetime('now'), datetime('now'))
    `).run(r1CrashId, r1Staged.stagingPath, r1Path, r1Staged.contentSha256);
    fs.linkSync(r1Staged.stagingPath, r1Path);

    const bkpDir = path.join(baseDir, 'ExternalBkp');
    const bkp = createConsistentBackup({ vaultPath: vaultDir, dataPath: dataDir, targetDir: bkpDir });
    assert.equal(bkp.status, 'complete');

    const restVault = path.join(baseDir, 'Restored', 'AgentMemory');
    const restData = path.join(baseDir, 'Restored', 'AgentMemory-Data');
    const restRes = restoreFromBackup({ backupDir: bkp.backupDir, newVaultPath: restVault, newDataPath: restData });
    assert.equal(restRes.verification.sqliteIntegrityOk, true);
    assert.equal(restRes.verification.checksumMismatches.length, 0);

    const checkRestDb = openDatabase(path.join(restData, 'runtime', 'state.sqlite'));
    try {
      const recoveredNote = checkRestDb.prepare('SELECT id, status FROM notes WHERE id = ?').get(r1CrashId);
      assert.ok(recoveredNote, 'R1 恢复的笔记必须补全登记到 notes 表');
      assert.equal(recoveredNote.status, 'active');
    } finally {
      checkRestDb.close();
    }

    // 4d. 已有数据但 state.sqlite 缺失时，initRepository 与 mem doctor 必须阻断
    const brokenBase = path.join(baseDir, 'BrokenDbCheck');
    const bVault = path.join(brokenBase, 'AgentMemory');
    const bData = path.join(brokenBase, 'AgentMemory-Data');
    initRepository({ vaultPath: bVault, dataPath: bData });
    fs.writeFileSync(path.join(bVault, '30_Knowledge_Notes', 'Playbooks', 'KN-existing.md'), '# keep', 'utf8');
    fs.unlinkSync(path.join(bData, 'runtime', 'state.sqlite'));

    assert.throws(() => {
      initRepository({ vaultPath: bVault, dataPath: bData });
    }, /CRITICAL_STATE_DB_MISSING/);

    let doctorExit = 0;
    try {
      execFileSync(process.execPath, [CLI_PATH, 'doctor'], {
        env: { ...process.env, AGENT_MEMORY_VAULT: bVault, AGENT_MEMORY_DATA: bData },
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (e) {
      doctorExit = e.status || 1;
    }
    assert.notEqual(doctorExit, 0, 'state.sqlite 缺失且存在持久化笔记时 mem doctor 必须报错退出');
  });

  await t.test('5. 防 YAML 隐私篡改绕过、reconcile 退回刷新与 inspect-raw-local.ps1 Zstd 解压语法校验', () => {
    const env = { ...process.env, AGENT_MEMORY_VAULT: vaultDir, AGENT_MEMORY_DATA: dataDir };

    // 5a. 篡改已入库 local_only 笔记的 YAML privacy 为 sanitized，仍必须被 searchKnowledge 与 proposal show 阻断
    const localNoteRow = db.prepare("SELECT id, path FROM notes WHERE privacy = 'local_only' LIMIT 1").get();
    assert.ok(localNoteRow);
    const origLocalMd = fs.readFileSync(localNoteRow.path, 'utf8');
    fs.writeFileSync(localNoteRow.path, origLocalMd.replace('privacy: "local_only"', 'privacy: "sanitized"'), 'utf8');

    const tamperedSearch = searchKnowledge({ db, vaultDir, query: '机密正文', project: 'B07' });
    assert.equal(tamperedSearch.items.length, 0, '即使 YAML privacy 被篡改为 sanitized，DB 中登记为 local_only 的笔记绝不可召回');

    const localTargetProp = createProposal({
      queueDir: path.join(vaultDir, '40_Review_Queue'),
      proposalUuid: 'PROP-B07-LOCAL-TARGET',
      title: '针对私密笔记的提案',
      project: 'B07',
      targetId: localNoteRow.id,
      targetNoteRef: `[[${localNoteRow.id}]]`,
      proposalKind: 'conflict',
      preConditions: ['机密正文'],
      postConditions: ['新文本']
    });
    const propShowOut = execFileSync(process.execPath, [CLI_PATH, 'proposal', 'show', 'PROP-B07-LOCAL-TARGET'], {
      env,
      encoding: 'utf8'
    });
    const propShowJson = JSON.parse(propShowOut);
    assert.equal(propShowJson.base_revision_diff?.redacted, true);
    assert.equal(propShowJson.condition_checks, null);

    // 5b. mem reconcile 在提案从 accepted 改回 pending 后，必须同步退回 reconcile_states 状态
    const sanRow = db.prepare("SELECT id, path FROM notes WHERE privacy = 'sanitized' AND project = 'B07' LIMIT 1").get();
    const sanOrig = fs.readFileSync(sanRow.path, 'utf8');
    fs.writeFileSync(sanRow.path, sanOrig.replace('完整正文字段必须被 mem restore 原样恢复', '新版正确指令'), 'utf8');
    const revProp = createProposal({
      queueDir: path.join(vaultDir, '40_Review_Queue'),
      proposalUuid: 'PROP-B07-REVERT',
      title: '可逆提案核对测试',
      project: 'B07',
      targetId: sanRow.id,
      targetNoteRef: `[[${sanRow.id}]]`,
      proposalKind: 'conflict',
      preConditions: ['完整正文字段必须被 mem restore 原样恢复'],
      postConditions: ['新版正确指令']
    });
    fs.writeFileSync(revProp.proposalPath, fs.readFileSync(revProp.proposalPath, 'utf8').replace('proposal_status: "pending"', 'proposal_status: "accepted"'), 'utf8');
    execFileSync(process.execPath, [CLI_PATH, 'reconcile'], { env, encoding: 'utf8' });
    assert.equal(db.prepare('SELECT reconcile_state FROM reconcile_states WHERE proposal_id = ?').get('PROP-B07-REVERT').reconcile_state, 'verified_applied');

    fs.writeFileSync(revProp.proposalPath, fs.readFileSync(revProp.proposalPath, 'utf8').replace('proposal_status: "accepted"', 'proposal_status: "pending"'), 'utf8');
    execFileSync(process.execPath, [CLI_PATH, 'reconcile'], { env, encoding: 'utf8' });
    const revertedRec = db.prepare('SELECT reconcile_state, reason FROM reconcile_states WHERE proposal_id = ?').get('PROP-B07-REVERT');
    assert.equal(revertedRec.reconcile_state, 'unverified');
    assert.ok(revertedRec.reason.includes('proposal_status_is_pending'));

    // 5c. 验证 inspect-raw-local.ps1 中的 .zst Node 解压单行脚本对真实 .jsonl.zst 文件可正常解压
    const ps1Text = fs.readFileSync(path.resolve('cli/inspect-raw-local.ps1'), 'utf8');
    const matchOneLiner = ps1Text.match(/\$jsOneLiner\s*=\s*'([^']+)'/);
    assert.ok(matchOneLiner, 'inspect-raw-local.ps1 必须使用 $jsOneLiner + node -e 传入目标文件路径');
    const testZstFile = path.join(srcDir, 'ps1-zst-check.jsonl.zst');
    const payload = '{"type":"user","content":"PS1_ZSTD_CHECK_OK_中文"}\n';
    fs.writeFileSync(testZstFile, zlib.zstdCompressSync(Buffer.from(payload, 'utf8')));
    const decompOut = execFileSync(process.execPath, ['-e', matchOneLiner[1], testZstFile], { encoding: 'utf8' });
    assert.equal(decompOut, payload);
  });
});
