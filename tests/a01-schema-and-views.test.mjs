import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateFrontmatter, isTemplatePath, evaluateBaseFilter } from '../src/schema/validator.mjs';
import { BASES_VIEWS, TEMPLATES } from '../src/init.mjs';

describe('A01: Schema 与 Bases 视图正反例验证', () => {
  it('应当正确识别 90_Templates/ 下的模板路径并支持全局隔离', () => {
    assert.equal(isTemplatePath('90_Templates/Template_Playbook.md'), true);
    assert.equal(isTemplatePath('C:/Work/MindLoom/90_Templates/Template_Session.md'), true);
    assert.equal(isTemplatePath('30_Knowledge_Notes/Playbooks/KN-001.md'), false);
  });

  it('知识笔记合规用例应当校验通过', () => {
    const validPlaybook = {
      schema_version: 1,
      id: 'KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f',
      note_type: 'playbook',
      title: '容器端口绑定失败排查',
      project: 'codex',
      privacy: 'sanitized',
      lifecycle: 'active',
      evidence_level: 'observed',
      review_state: 'pending',
      env: { os: 'windows' },
      sources: ['[[20_Evidence_Cards/EV-001.md]]'],
      created_at: '2026-11-10T12:00:00+08:00'
    };

    const res = validateFrontmatter(validPlaybook);
    assert.equal(res.valid, true);
    assert.equal(res.errors.length, 0);
  });

  it('知识笔记缺失核心必填字段或枚举非法应当校验失败', () => {
    // 缺失 project 和 privacy 非法
    const invalidNote = {
      schema_version: 1,
      id: 'KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f',
      note_type: 'playbook',
      title: '测试',
      privacy: 'public_leak', // 非法枚举
      lifecycle: 'unknown_state', // 非法枚举
      evidence_level: 'observed',
      review_state: 'pending',
      created_at: '2026-11-10T12:00:00+08:00'
    };

    const res = validateFrontmatter(invalidNote);
    assert.equal(res.valid, false);
    assert.ok(res.errors.some(e => e.includes('privacy')));
    assert.ok(res.errors.some(e => e.includes('lifecycle')));
    assert.ok(res.errors.some(e => e.includes('project')));
  });

  it('project_state 缺失 as_of 或 review_after 应当报错', () => {
    const missingDates = {
      schema_version: 1,
      id: 'KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f',
      note_type: 'project_state',
      title: '阶段状态',
      project: 'codex',
      privacy: 'sanitized',
      lifecycle: 'active',
      evidence_level: 'user_confirmed',
      review_state: 'accepted',
      created_at: '2026-11-10T12:00:00+08:00'
    };

    const res = validateFrontmatter(missingDates);
    assert.equal(res.valid, false);
    assert.ok(res.errors.some(e => e.includes('as_of')));
    assert.ok(res.errors.some(e => e.includes('review_after')));
  });

  it('更新提案字段与独立枚举校验生效', () => {
    const validProposal = {
      schema_version: 1,
      id: 'PROP-019316a8-7c40-7000-8000-1a2b3c4d5e6f',
      note_type: 'proposal',
      title: '更新排障步骤',
      project: 'codex',
      privacy: 'sanitized',
      target_id: 'KN-019316a8-7c40-7000-8000-111111111111',
      target_note: '[[30_Knowledge_Notes/Playbooks/KN-001.md]]',
      base_revision_id: 'rev-0001',
      proposal_kind: 'conflict',
      proposal_status: 'pending',
      sources: ['[[20_Evidence_Cards/EV-002.md]]'],
      created_at: '2026-11-10T12:00:00+08:00'
    };

    const res = validateFrontmatter(validProposal);
    assert.equal(res.valid, true);

    // 提案状态非法枚举
    const invalidProposal = { ...validProposal, proposal_status: 'needs_recheck' }; // needs_recheck 在三审 C-1 中已废弃
    const resBad = validateFrontmatter(invalidProposal);
    assert.equal(resBad.valid, false);
    assert.ok(resBad.errors.some(e => e.includes('proposal_status')));
  });

  it('Bases 视图: 到期复核.base 逻辑验证 (未来日期不计入到期)', () => {
    const pastNote = {
      file: { inFolder: (f) => f === '30_Knowledge_Notes' },
      note: {
        lifecycle: 'active',
        review_state: 'accepted',
        review_after: '2026-11-09' // 昨天 -> 已到期
      }
    };

    const futureNote = {
      file: { inFolder: (f) => f === '30_Knowledge_Notes' },
      note: {
        lifecycle: 'active',
        review_state: 'accepted',
        review_after: '2026-11-20' // 未来日期 -> 未到期
      }
    };

    const pendingNote = {
      file: { inFolder: (f) => f === '30_Knowledge_Notes' },
      note: {
        lifecycle: 'active',
        review_state: 'pending', // 待审 -> 无论日期都需复核
        review_after: '2026-12-01'
      }
    };

    const todayStr = '2026-11-10';
    assert.equal(evaluateBaseFilter('到期复核', pastNote, todayStr), true);
    assert.equal(evaluateBaseFilter('到期复核', futureNote, todayStr), false);
    assert.equal(evaluateBaseFilter('到期复核', pendingNote, todayStr), true);
  });

  it('Bases 视图: 待处理更新.base 包含双页签定义，会话与证据溯源.base 与 Template_Evidence.md 包含 source_tool', () => {
    const content = BASES_VIEWS['待处理更新.base'];
    assert.ok(content.includes('name: 待处理更新提案'));
    assert.ok(content.includes('name: 已标采纳（核对状态见 mem status）'));
    assert.ok(content.includes("note.proposal_status == \"pending\""));
    assert.ok(content.includes("note.proposal_status == \"accepted\""));

    const traceBase = BASES_VIEWS['会话与证据溯源.base'];
    assert.ok(traceBase.includes('note.source_tool:'));
    assert.ok(traceBase.includes('displayName: 来源Agent'));
    assert.ok(TEMPLATES['Template_Evidence.md'].includes('source_tool:'));
  });

  it('evidence 原子证据卡必须声明合法单值 source_tool (codex|antigravity|dsh)', () => {
    const validEv = {
      schema_version: 1,
      id: 'EV-019316a8-7c40-7000-8000-1a2b3c4d5e6f',
      note_type: 'evidence',
      title: '端口占用证据',
      project: 'ObsidianAgentMemory',
      privacy: 'sanitized',
      source_tool: 'codex',
      evidence_level: 'observed',
      sources: ['[[10_Readable_Sessions/SES-20261110-codex-123456_test.md#^event-000001]]'],
      created_at: '2026-11-10T12:00:00+08:00'
    };
    assert.equal(validateFrontmatter(validEv).valid, true);

    const missingTool = { ...validEv };
    delete missingTool.source_tool;
    const resMissing = validateFrontmatter(missingTool);
    assert.equal(resMissing.valid, false);
    assert.ok(resMissing.errors.some(e => e.includes('source_tool')));

    const badTool = { ...validEv, source_tool: 'unknown_agent' };
    const resBad = validateFrontmatter(badTool);
    assert.equal(resBad.valid, false);
    assert.ok(resBad.errors.some(e => e.includes('source_tool')));
  });
});
