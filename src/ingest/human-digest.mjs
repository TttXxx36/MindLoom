import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseRenderedSessionEvents } from '../distill/llm-distiller.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { assertVaultGitNoRemote, isWhitelistedVaultPath } from '../git/repo-manager.mjs';
import { scanAndSyncNotes } from '../tombstone/tracker.mjs';

const DIGEST_HEADING = '## 人类精读摘要（对话要点与结论）';
const EVENTS_HEADING = '## 会话事件记录';

/**
 * 清洗会话文本中的包裹标签与系统上下文噪声，保留人类可读正文
 * @param {string} rawText
 * @returns {string}
 */
export function stripInstructionNoise(rawText) {
  let out = String(rawText || '').replace(/\r\n/g, '\n');
  out = out.replace(/<ADDITIONAL_METADATA>[\s\S]*?(?:<\/ADDITIONAL_METADATA>|$)/gi, '');
  out = out.replace(/<USER_SETTINGS_CHANGE>[\s\S]*?(?:<\/USER_SETTINGS_CHANGE>|$)/gi, '');
  out = out.replace(/<CONTEXT_SUMMARY>[\s\S]*?(?:<\/CONTEXT_SUMMARY>|$)/gi, '');
  out = out.replace(/<SYSTEM_MESSAGE>[\s\S]*?(?:<\/SYSTEM_MESSAGE>|$)/gi, '');
  out = out.replace(/<ENVIRONMENT_CONTEXT>[\s\S]*?(?:<\/ENVIRONMENT_CONTEXT>|$)/gi, '');
  out = out.replace(/<INSTRUCTIONS>[\s\S]*?(?:<\/INSTRUCTIONS>|$)/gi, '');
  out = out.replace(/<user_instructions>[\s\S]*?(?:<\/user_instructions>|$)/gi, '');
  out = out.replace(/<\/?USER_REQUEST>/gi, '');
  out = out.replace(/^#\s*Files mentioned by the user:[\s\S]*?^##\s*My request:\s*/im, '');
  out = out.replace(/<agent-embed\b[^>]*>[\s\S]*?<\/agent-embed>/gi, '');
  out = out.replace(/\[answer-me-with-html[^\]]*\]/gi, '');
  out = out.replace(/\n{3,}/g, '\n\n').trim();
  return out;
}

function classifyHumanTurn(heading, cleanedText) {
  if (!cleanedText) return null;
  if (/^\s*#\s*AGENTS\.md|<environment_context>/i.test(cleanedText)) return null;
  if (/\b(?:GENERIC|EPHEMERAL_MESSAGE|SYSTEM_MESSAGE|CHECKPOINT|TASK_BOUNDARY|TOOL_CALL|TOOL_RESPONSE|tool_use|tool_result|turn_context|world_state|token_usage_record)\b/i.test(heading)) {
    return null;
  }

  const trimmed = cleanedText.trim();
  if (
    trimmed.startsWith('{') &&
    (trimmed.includes('"step_index"') ||
      trimmed.includes('"tool_calls"') ||
      trimmed.includes('"item_completed"') ||
      trimmed.includes('"encrypted_content"') ||
      trimmed.includes('"function_call"') ||
      trimmed.includes('"call_id"'))
  ) {
    return null;
  }

  if (/\bUSER_INPUT\b|\(user\)/i.test(heading)) {
    return 'user';
  }
  if (/\bPLANNER_RESPONSE\b|\(assistant\)/i.test(heading)) {
    return 'assistant';
  }
  return null;
}

function toCompactExcerpt(text, maxChars = 300) {
  const singleLine = String(text || '').replace(/\s+/g, ' ').trim();
  if (singleLine.length <= maxChars) return singleLine;
  return `${singleLine.slice(0, maxChars - 1)}…`;
}

/**
 * 从可读会话 Markdown 提取面向人类阅读的对答要点（自动跳过工具 JSON 与噪声事件）
 * @param {string} sessionMarkdown
 * @param {{ maxTurns?: number, maxCharsPerTurn?: number }} [options]
 * @returns {Array<{ role: 'user'|'assistant', eventId: number, anchor: string, excerpt: string }>}
 */
export function extractHumanDigestTurnsFromMarkdown(sessionMarkdown, options = {}) {
  const maxTurns = Number(options.maxTurns ?? 24);
  const maxCharsPerTurn = Number(options.maxCharsPerTurn ?? 300);
  const parsed = parseRenderedSessionEvents(sessionMarkdown);

  const turns = [];
  let lastExcerpt = '';
  for (const ev of parsed.events) {
    if (ev.isPlaceholder) continue;
    const cleaned = stripInstructionNoise(ev.text);
    const role = classifyHumanTurn(ev.heading, cleaned);
    if (!role) continue;
    const excerpt = toCompactExcerpt(cleaned, maxCharsPerTurn);
    if (!excerpt || excerpt.length < 4) continue;

    // 跳过连续重复的镜像事件（如 event_msg 与 response_item 相同内容）
    if (excerpt === lastExcerpt) continue;
    lastExcerpt = excerpt;

    turns.push({
      role,
      eventId: ev.eventId,
      anchor: ev.anchor,
      excerpt
    });
    if (turns.length >= maxTurns) break;
  }
  return turns;
}

/**
 * 构建可嵌入会话顶部的「人类精读摘要」Markdown 段落
 * @param {Array<{ role: 'user'|'assistant', eventId: number, anchor: string, excerpt: string }>} turns
 * @returns {string}
 */
export function buildHumanDigestSection(turns) {
  if (!Array.isArray(turns) || turns.length === 0) {
    return `${DIGEST_HEADING}\n> 暂无可独立摘录的纯文本对答；请直接在下方审计事件流检索详细记录。\n`;
  }
  const lines = [
    DIGEST_HEADING,
    '> 自动过滤系统提示、工具调用 JSON 与中间噪声；点击末尾 `#^event-` 可跳回下方原审计锚点。',
    ''
  ];
  for (let i = 0; i < turns.length; i++) {
    const t = turns[i];
    const badge = t.role === 'user' ? '🧑 需求' : '🤖 结论';
    lines.push(`${i + 1}. **${badge}** ([[#${t.anchor}|事件 #${t.eventId}]]): ${t.excerpt}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * 为已发布的 sanitized 会话补充或刷新顶部「人类精读摘要」，绝不改写下方 `^event-` 原文与锚点
 * @param {string} sessionPath
 * @returns {{ updated: boolean, skippedReason?: string, turnsCount?: number }}
 */
export function refreshSessionHumanDigestHeader(sessionPath) {
  if (!sessionPath || !fs.existsSync(sessionPath)) {
    return { updated: false, skippedReason: 'file_missing' };
  }
  const raw = fs.readFileSync(sessionPath, 'utf8');
  const { frontmatter } = parseMarkdownFrontmatter(raw);
  if (frontmatter?.note_type !== 'session' || frontmatter?.privacy !== 'sanitized') {
    return { updated: false, skippedReason: 'privacy_or_type_blocked' };
  }

  const eventsIdx = raw.indexOf(EVENTS_HEADING);
  if (eventsIdx === -1) {
    return { updated: false, skippedReason: 'missing_events_heading' };
  }

  const turns = extractHumanDigestTurnsFromMarkdown(raw);
  const digestSection = buildHumanDigestSection(turns);
  const existingDigestIdx = raw.indexOf(DIGEST_HEADING);

  let updatedRaw;
  if (existingDigestIdx !== -1 && existingDigestIdx < eventsIdx) {
    updatedRaw = `${raw.slice(0, existingDigestIdx)}${digestSection}\n${raw.slice(eventsIdx)}`;
  } else {
    updatedRaw = `${raw.slice(0, eventsIdx)}${digestSection}\n${raw.slice(eventsIdx)}`;
  }

  if (updatedRaw === raw) {
    return { updated: false, skippedReason: 'unchanged', turnsCount: turns.length };
  }
  fs.writeFileSync(sessionPath, updatedRaw, 'utf8');
  return { updated: true, turnsCount: turns.length };
}

function toSafeFileSlug(name) {
  const safe = String(name || 'Unmapped')
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
    .trim();
  return safe || 'Unmapped';
}

function readVerifiedSanitizedMarkdown(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, 'utf8');
  const { frontmatter } = parseMarkdownFrontmatter(raw);
  if (frontmatter?.privacy !== 'sanitized') return null;
  return { raw, frontmatter };
}

/**
 * 重建 Obsidian `00_MOC/` 主题地图、`学习简报_最新会话精华.md` 与升级版 `首页.md`
 * 严格仅纳入 active + privacy === 'sanitized' 笔记，绝不泄露 local_only 标题或内容。
 *
 * @param {{
 *   db: any,
 *   vaultDir: string,
 *   updateSessionDigests?: boolean,
 *   nowIso?: string
 * }} params
 */
export function rebuildVaultMocAndHome({
  db,
  vaultDir,
  updateSessionDigests = false,
  nowIso = new Date().toISOString()
}) {
  if (!db || !vaultDir) {
    throw new Error('rebuildVaultMocAndHome requires db and vaultDir');
  }

  const touchedPaths = [];
  if (updateSessionDigests) {
    const activeSessions = db
      .prepare("SELECT path FROM notes WHERE status = 'active' AND privacy = 'sanitized' AND note_type = 'session'")
      .all();
    for (const row of activeSessions) {
      const res = refreshSessionHumanDigestHeader(row.path);
      if (res.updated) {
        touchedPaths.push(row.path);
      }
    }
    if (touchedPaths.length > 0) {
      scanAndSyncNotes({ db, vaultDir });
    }
  }

  const rows = db
    .prepare(
      `SELECT id, note_type, title, project, privacy, lifecycle, review_state, path, created_at
       FROM notes
       WHERE status = 'active' AND privacy = 'sanitized'
       ORDER BY created_at DESC`
    )
    .all();

  const verifiedNotes = [];
  for (const row of rows) {
    const checked = readVerifiedSanitizedMarkdown(row.path);
    if (!checked) continue;
    const relNoExt = path.relative(vaultDir, row.path).replace(/\\/g, '/').replace(/\.md$/i, '');
    verifiedNotes.push({ ...row, relNoExt, raw: checked.raw });
  }

  const mocDir = path.join(vaultDir, '00_MOC');
  if (!fs.existsSync(mocDir)) {
    fs.mkdirSync(mocDir, { recursive: true });
  }

  const byProject = new Map();
  for (const n of verifiedNotes) {
    const proj = String(n.project || 'unmapped').trim() || 'unmapped';
    if (!byProject.has(proj)) byProject.set(proj, []);
    byProject.get(proj).push(n);
  }

  const projectMocLinks = [];
  const sortedProjects = [...byProject.entries()].sort((a, b) => b[1].length - a[1].length);

  for (const [project, list] of sortedProjects) {
    const knowledge = list.filter((n) => ['playbook', 'decision', 'project_state', 'preference'].includes(n.note_type));
    const evidence = list.filter((n) => n.note_type === 'evidence');
    const sessions = list.filter((n) => n.note_type === 'session');
    const proposals = list.filter((n) => n.note_type === 'proposal');

    const lines = [
      `# ${project} · 项目记忆地图 (MOC)`,
      '',
      `> 自动生成于 ${nowIso.slice(0, 10)}｜本页仅汇集 \`privacy: sanitized\` 公开合规条目，供快速检索与阅读学习。`,
      '',
      `- 知识笔记: **${knowledge.length}** 篇｜原子证据: **${evidence.length}** 篇｜会话档案: **${sessions.length}** 篇｜提案: **${proposals.length}** 篇`,
      '',
      '## 1. 可直接学习与复用的知识笔记',
      ''
    ];

    if (knowledge.length === 0) {
      lines.push('- 暂无已整理知识笔记；可从下方会话精读要点中提炼生成。');
    } else {
      for (const k of knowledge) {
        const badge = k.review_state === 'accepted' && k.lifecycle === 'active' ? '✅ 已核准' : `⏳ ${k.review_state || 'pending'}`;
        lines.push(`- ${badge} [[${k.relNoExt}|${k.title}]]（\`${k.note_type}\`，${String(k.created_at || '').slice(0, 10)}）`);
      }
    }

    lines.push('', '## 2. 原子证据卡', '');
    if (evidence.length === 0) {
      lines.push('- 暂无原子证据卡。');
    } else {
      for (const ev of evidence) {
        lines.push(`- [[${ev.relNoExt}|${ev.title}]]（${String(ev.created_at || '').slice(0, 10)}）`);
      }
    }

    lines.push('', '## 3. 已入库会话精读要点', '');
    if (sessions.length === 0) {
      lines.push('- 暂无已入库会话。');
    } else {
      for (const s of sessions) {
        lines.push(`### [[${s.relNoExt}|${s.title}]]`);
        const turns = extractHumanDigestTurnsFromMarkdown(s.raw, { maxTurns: 6, maxCharsPerTurn: 180 });
        if (turns.length === 0) {
          lines.push('- 暂无精读对答摘录，点击上方链接查看原档。');
        } else {
          for (const t of turns.slice(0, 4)) {
            const roleLabel = t.role === 'user' ? '🧑 需求' : '🤖 结论';
            lines.push(`- **${roleLabel}** ([[${s.relNoExt}#${t.anchor}|#${t.eventId}]]): ${t.excerpt}`);
          }
        }
        lines.push('');
      }
    }

    if (proposals.length > 0) {
      lines.push('## 4. 关联更新提案', '');
      for (const p of proposals) {
        lines.push(`- [[${p.relNoExt}|${p.title}]]`);
      }
    }

    const safeFile = `${toSafeFileSlug(project)}.md`;
    const mocPath = path.join(mocDir, safeFile);
    fs.writeFileSync(mocPath, lines.join('\n').trimEnd() + '\n', 'utf8');
    touchedPaths.push(mocPath);
    projectMocLinks.push({
      project,
      relPath: `00_MOC/${safeFile}`,
      knowledgeCount: knowledge.length,
      evidenceCount: evidence.length,
      sessionsCount: sessions.length
    });
  }

  // 全局学习简报：最新会话精华
  const allSessions = verifiedNotes.filter((n) => n.note_type === 'session');
  const pendingProps = verifiedNotes.filter((n) => n.note_type === 'proposal' && /proposal_status:\s*"?pending"?/i.test(n.raw));
  const digestLines = [
    '# 学习简报 · 最新会话精华导读',
    '',
    `> 更新时间: ${nowIso.slice(0, 10)}｜按时间倒序汇总所有合规会话的人类可读要点，帮你不必打开 MB 级工具日志即可吸收核心知识。`,
    '',
    `- 已收录合规知识笔记: **${verifiedNotes.filter((n) => ['playbook', 'decision', 'project_state', 'preference'].includes(n.note_type)).length}** 篇`,
    `- 已收录合规会话: **${allSessions.length}** 篇`,
    `- 待审更新提案: **${pendingProps.length}** 篇`,
    '',
    '## 各会话关键问答回顾',
    ''
  ];

  for (const s of allSessions.slice(0, 12)) {
    digestLines.push(`### [${s.project || 'unmapped'}] [[${s.relNoExt}|${s.title}]]`);
    const turns = extractHumanDigestTurnsFromMarkdown(s.raw, { maxTurns: 6, maxCharsPerTurn: 200 });
    for (const t of turns.slice(0, 4)) {
      const roleLabel = t.role === 'user' ? '🧑 问' : '🤖 答';
      digestLines.push(`- **${roleLabel}**: ${t.excerpt}（[[${s.relNoExt}#${t.anchor}|事件 #${t.eventId}]]）`);
    }
    digestLines.push('');
  }

  const digestPath = path.join(mocDir, '学习简报_最新会话精华.md');
  fs.writeFileSync(digestPath, digestLines.join('\n').trimEnd() + '\n', 'utf8');
  touchedPaths.push(digestPath);

  // 升级版 首页.md
  const homeLines = [
    '# Obsidian Agent 记忆库',
    '',
    `> 本地原生记忆库（零社区插件 · 双目录安全隔离 · 最近导航同步: ${nowIso.slice(0, 10)}）`,
    '',
    '## 一、学习导读与项目知识地图 (MOC)',
    '- 🌟 **[[00_MOC/学习简报_最新会话精华|最新会话学习简报（已过滤工具日志）]]** — 先看这里快速吸收近期对话精华',
    ''
  ];
  for (const pm of projectMocLinks) {
    homeLines.push(
      `- 📂 **[[${pm.relPath.replace(/\.md$/i, '')}|${pm.project}]]**（知识 ${pm.knowledgeCount} · 证据 ${pm.evidenceCount} · 会话 ${pm.sessionsCount}）`
    );
  }
  homeLines.push(
    '',
    '## 二、原生数据库看板 (Bases Views)',
    '- [[50_Bases_Views/知识总览.base|知识总览 (全部正式知识)]]',
    '- [[50_Bases_Views/待处理更新.base|待处理更新 (待审提案与已采纳队列)]]',
    '- [[50_Bases_Views/到期复核.base|到期复核 (待审与到期复核队列)]]',
    '- [[50_Bases_Views/会话与证据溯源.base|会话与证据溯源 (会话台账与证据卡)]]',
    '',
    '## 三、目录结构说明',
    '- `00_MOC/`: 按项目聚合的知识地图与人类精华学习简报',
    '- `10_Readable_Sessions/`: 经脱敏会话档案（顶部含人类精读摘要，下方保留完整 `^event-` 溯源锚点）',
    '- `20_Evidence_Cards/`: 原子证据卡（严格锚定原始会话节点）',
    '- `30_Knowledge_Notes/`: 正式可复用知识笔记（Playbooks / Decisions / Project_States / Preferences）',
    '- `40_Review_Queue/`: 独立更新提案队列（只增不改，人工核对防覆盖）',
    '- `50_Bases_Views/`: 原生 Bases 中文视图',
    '- `90_Templates/`: 模板目录（全局排除在检索与看板外）',
    ''
  );

  const homePath = path.join(vaultDir, '首页.md');
  fs.writeFileSync(homePath, homeLines.join('\n'), 'utf8');
  touchedPaths.push(homePath);

  let gitState = 'skipped_no_git';
  if (fs.existsSync(path.join(vaultDir, '.git'))) {
    assertVaultGitNoRemote(vaultDir);
    const relToAdd = [];
    for (const p of [...new Set(touchedPaths)]) {
      if (isWhitelistedVaultPath(vaultDir, p)) {
        relToAdd.push(path.relative(vaultDir, p).replace(/\\/g, '/'));
      }
    }
    if (relToAdd.length > 0) {
      try {
        execFileSync('git', ['add', '--', ...relToAdd], { cwd: vaultDir, stdio: ['pipe', 'pipe', 'pipe'] });
        const staged = execFileSync('git', ['diff', '--cached', '--name-only'], {
          cwd: vaultDir,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        }).trim();
        if (staged) {
          execFileSync('git', ['commit', '-m', 'docs(memory): rebuild MOC knowledge maps and human reading digests'], {
            cwd: vaultDir,
            stdio: ['pipe', 'pipe', 'pipe']
          });
          gitState = 'committed';
        } else {
          gitState = 'unchanged';
        }
      } catch {
        gitState = 'failed';
      }
    }
  }

  return {
    status: 'ok',
    projectsCount: projectMocLinks.length,
    sanitizedNotesCount: verifiedNotes.length,
    projectMocs: projectMocLinks,
    digestPath,
    homePath,
    gitState
  };
}
