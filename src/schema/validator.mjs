/**
 * Schema 校验与 Bases 视图过滤器评估模块 (v2.4)
 */

export const ALLOWED_NOTE_TYPES = [
  'session',
  'evidence',
  'playbook',
  'decision',
  'project_state',
  'preference',
  'proposal'
];

export const ALLOWED_PRIVACY = ['sanitized', 'local_only'];
export const ALLOWED_SOURCE_TOOLS = ['codex', 'antigravity', 'dsh'];
export const ALLOWED_LIFECYCLES = ['active', 'stale', 'superseded', 'deprecated'];
export const ALLOWED_EVIDENCE_LEVELS = ['observed', 'user_confirmed', 'agent_claim', 'hypothesis'];
export const ALLOWED_REVIEW_STATES = ['pending', 'accepted', 'disputed'];
export const ALLOWED_PROPOSAL_KINDS = ['supplement', 'conflict', 'supersede'];
export const ALLOWED_PROPOSAL_STATUSES = ['pending', 'accepted', 'rejected', 'obsolete'];

/**
 * 判断指定文件路径是否属于模板目录或模板文件
 * @param {string} filePath
 * @returns {boolean}
 */
export function isTemplatePath(filePath) {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/');
  return normalized.includes('90_Templates/') || normalized.includes('/Template_') || normalized.startsWith('Template_');
}

/**
 * 校验 Frontmatter 结构是否符合规范
 * @param {object} frontmatter
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateFrontmatter(frontmatter) {
  const errors = [];
  if (!frontmatter || typeof frontmatter !== 'object') {
    return { valid: false, errors: ['Frontmatter 必须为非空对象'] };
  }

  // 1. 通用核心 7 个字段校验
  if (frontmatter.schema_version !== 1 && frontmatter.schema_version !== '1') {
    errors.push('schema_version 必须为 1');
  }

  if (!frontmatter.id || typeof frontmatter.id !== 'string') {
    errors.push('id 必须为非空字符串');
  }

  if (!frontmatter.note_type || !ALLOWED_NOTE_TYPES.includes(frontmatter.note_type)) {
    errors.push(`note_type 非法，必须为 [${ALLOWED_NOTE_TYPES.join(', ')}] 之一`);
  }

  if (!frontmatter.title || typeof frontmatter.title !== 'string') {
    errors.push('title 必须为非空字符串');
  }

  if (!frontmatter.project || typeof frontmatter.project !== 'string') {
    errors.push('project 必须为非空字符串');
  }

  if (!frontmatter.privacy || !ALLOWED_PRIVACY.includes(frontmatter.privacy)) {
    errors.push(`privacy 非法，必须为 [${ALLOWED_PRIVACY.join(', ')}] 之一`);
  }

  if (!frontmatter.created_at || typeof frontmatter.created_at !== 'string') {
    errors.push('created_at 必须为 ISO 8601 字符串');
  }

  const type = frontmatter.note_type;

  // 2. 知识笔记专属字段校验
  if (['playbook', 'decision', 'project_state', 'preference'].includes(type)) {
    if (!frontmatter.lifecycle || !ALLOWED_LIFECYCLES.includes(frontmatter.lifecycle)) {
      errors.push(`lifecycle 非法，必须为 [${ALLOWED_LIFECYCLES.join(', ')}] 之一`);
    }
    if (!frontmatter.evidence_level || !ALLOWED_EVIDENCE_LEVELS.includes(frontmatter.evidence_level)) {
      errors.push(`evidence_level 非法，必须为 [${ALLOWED_EVIDENCE_LEVELS.join(', ')}] 之一`);
    }
    if (!frontmatter.review_state || !ALLOWED_REVIEW_STATES.includes(frontmatter.review_state)) {
      errors.push(`review_state 非法，必须为 [${ALLOWED_REVIEW_STATES.join(', ')}] 之一`);
    }

    if (type === 'project_state') {
      if (!frontmatter.as_of) errors.push('project_state 必须包含 as_of 字段');
      if (!frontmatter.review_after) errors.push('project_state 必须包含 review_after 字段');
    }

    if (type === 'playbook') {
      if (!frontmatter.env) errors.push('playbook 必须包含 env 字段');
    }
  }

  // 3. 提案专属字段校验
  if (type === 'proposal') {
    if (!frontmatter.target_id) errors.push('proposal 必须包含 target_id 字段');
    if (!frontmatter.target_note) errors.push('proposal 必须包含 target_note 字段');
    if (!frontmatter.base_revision_id) errors.push('proposal 必须包含 base_revision_id 字段');
    if (!frontmatter.proposal_kind || !ALLOWED_PROPOSAL_KINDS.includes(frontmatter.proposal_kind)) {
      errors.push(`proposal_kind 非法，必须为 [${ALLOWED_PROPOSAL_KINDS.join(', ')}] 之一`);
    }
    if (!frontmatter.proposal_status || !ALLOWED_PROPOSAL_STATUSES.includes(frontmatter.proposal_status)) {
      errors.push(`proposal_status 非法，必须为 [${ALLOWED_PROPOSAL_STATUSES.join(', ')}] 之一`);
    }
  }

  // 4. 会话专属字段校验
  if (type === 'session') {
    if (!frontmatter.source_tool || typeof frontmatter.source_tool !== 'string') {
      errors.push('session 必须包含 source_tool 字段');
    }
    if (!frontmatter.session_id) errors.push('session 必须包含 session_id 字段');
    if (!frontmatter.snapshot_id) errors.push('session 必须包含 snapshot_id 字段');
    if (!frontmatter.coverage || typeof frontmatter.coverage !== 'object') {
      errors.push('session 必须包含 coverage 统计对象');
    }
  }

  // 5. 证据卡专属字段校验 (§4.2: 单张证据卡必填单值 source_tool)
  if (type === 'evidence') {
    if (!frontmatter.source_tool || !ALLOWED_SOURCE_TOOLS.includes(String(frontmatter.source_tool).toLowerCase())) {
      errors.push(`evidence 的 source_tool 非法或缺失，必须为 [${ALLOWED_SOURCE_TOOLS.join(', ')}] 之一`);
    }
    if (!frontmatter.evidence_level || !ALLOWED_EVIDENCE_LEVELS.includes(frontmatter.evidence_level)) {
      errors.push(`evidence_level 非法，必须为 [${ALLOWED_EVIDENCE_LEVELS.join(', ')}] 之一`);
    }
    if (!Array.isArray(frontmatter.sources) || frontmatter.sources.length === 0) {
      errors.push('evidence 必须包含非空 sources 数组');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * 评估 Bases 视图筛选逻辑（供本地离线单测与验证）
 * @param {string} viewName
 * @param {object} item
 * @param {string} todayStr YYYY-MM-DD
 * @returns {boolean}
 */
export function evaluateBaseFilter(
  viewName,
  item,
  todayStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date())
) {
  const note = item?.note || {};
  const inFolder = typeof item?.file?.inFolder === 'function' ? (f) => Boolean(item.file.inFolder(f)) : null;

  if (inFolder && inFolder('90_Templates')) {
    return false;
  }

  if (viewName === '知识总览') {
    return inFolder ? inFolder('30_Knowledge_Notes') : true;
  }

  if (viewName === '到期复核') {
    if (inFolder && !inFolder('30_Knowledge_Notes')) return false;
    if (note.lifecycle !== 'active') return false;
    if (note.review_state === 'pending' || note.review_state === 'disputed') {
      return true;
    }
    if (note.review_after && String(note.review_after).slice(0, 10) <= todayStr) {
      return true;
    }
    return false;
  }

  if (viewName === '待处理更新') {
    if (inFolder && !inFolder('40_Review_Queue')) return false;
    return note.proposal_status === 'pending' || note.proposal_status === 'accepted';
  }
  if (viewName === '待处理更新:待处理更新提案') {
    if (inFolder && !inFolder('40_Review_Queue')) return false;
    return note.proposal_status === 'pending';
  }
  if (viewName === '待处理更新:已标采纳') {
    if (inFolder && !inFolder('40_Review_Queue')) return false;
    return note.proposal_status === 'accepted';
  }

  if (viewName === '会话与证据溯源') {
    return inFolder ? (inFolder('10_Readable_Sessions') || inFolder('20_Evidence_Cards')) : true;
  }
  if (viewName === '会话与证据溯源:已整理会话台账') {
    return inFolder ? inFolder('10_Readable_Sessions') : note.note_type === 'session';
  }
  if (viewName === '会话与证据溯源:原子证据卡台账') {
    return inFolder ? inFolder('20_Evidence_Cards') : note.note_type === 'evidence';
  }

  return true;
}
