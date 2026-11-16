import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { readFrontmatterId, findMarkdownFiles } from '../storage/path-sanitizer.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { validateFrontmatter } from '../schema/validator.mjs';
import { detectResidualSecrets } from '../security/sanitizer.mjs';

function parseFrontmatterFields(content) {
  const { frontmatter } = parseMarkdownFrontmatter(content);
  return {
    id: frontmatter.id ?? null,
    title: frontmatter.title ?? null,
    source_tool: frontmatter.source_tool ?? null,
    session_id: frontmatter.session_id ?? null,
    canonical_event_anchor: frontmatter.canonical_event_anchor ?? null,
    fact_type: frontmatter.fact_type ?? null,
    normalized_subject: frontmatter.normalized_subject ?? null
  };
}

/**
 * 跨快照稳定 item_key 计算 (严禁包含 snapshot_id，合入 ADR-004 与 D2 规范)
 * 基于 (source_tool, session_id, canonical_event_anchor, fact_type, normalized_subject)
 *
 * @param {{
 *   sourceTool: string,
 *   sessionId: string,
 *   canonicalEventAnchor: string,
 *   factType: string,
 *   normalizedSubject: string,
 *   snapshotId?: string // 即使传入也必须被显式忽略
 * }} params
 * @returns {string}
 */
export function calculateItemKey({
  sourceTool,
  sessionId,
  canonicalEventAnchor,
  factType,
  normalizedSubject
}) {
  const tool = (sourceTool || 'unknown').trim().toLowerCase();
  const session = (sessionId || '').trim();
  const anchor = (canonicalEventAnchor || '^event-000000').trim();
  const type = (factType || 'fact').trim().toLowerCase();
  const subject = (normalizedSubject || '').trim().toLowerCase();

  const raw = `${tool}::${session}::${anchor}::${type}::${subject}`;
  const hash = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  return `item-${hash.slice(0, 32)}`;
}

function sameFsPath(a, b) {
  if (!a || !b) return false;
  const ra = path.resolve(a);
  const rb = path.resolve(b);
  return process.platform === 'win32' ? ra.toLowerCase() === rb.toLowerCase() : ra === rb;
}

/**
 * 扫描 Vault 目录并同步状态（同步前校验 Schema 与 ID 唯一性；事务内更新手改字段与内容指纹；未知笔记只报告待登记）
 * @param {{
 *   db: any,
 *   vaultDir: string
 * }} options
 * @returns {{
 *   renamed: Array<object>,
 *   missing: Array<object>,
 *   activated: Array<object>,
 *   metadataUpdated: Array<object>,
 *   untracked: Array<object>,
 *   conflicts: Array<object>,
 *   schemaErrors: Array<object>
 * }}
 */
export function scanAndSyncNotes({ db, vaultDir }) {
  const noteFolders = [
    '10_Readable_Sessions',
    '20_Evidence_Cards',
    '30_Knowledge_Notes',
    '40_Review_Queue'
  ];
  const diskFiles = [];
  for (const folder of noteFolders) {
    diskFiles.push(...findMarkdownFiles(path.join(vaultDir, folder), { excludeTemplates: true, followSymlinks: false, boundaryDir: vaultDir }));
  }

  const entriesById = new Map();
  const unnamedFiles = [];
  const schemaErrors = [];

  for (const filePath of diskFiles) {
    if (filePath.replace(/\\/g, '/').includes('90_Templates/')) continue;
    const raw = fs.readFileSync(filePath, 'utf8');
    const sha256 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
    const parsed = parseMarkdownFrontmatter(raw);
    const fm = parsed.hasFrontmatter ? parsed.frontmatter : null;
    const id = (fm && typeof fm.id === 'string' && fm.id.trim()) ? fm.id.trim() : null;
    const schemaCheck = fm ? validateFrontmatter(fm) : { valid: false, errors: ['missing_frontmatter'] };

    if (!schemaCheck.valid) {
      schemaErrors.push({
        id,
        path: filePath,
        errors: schemaCheck.errors
      });
    }

    const entry = {
      id,
      filePath,
      raw,
      sha256,
      fm,
      schemaValid: schemaCheck.valid,
      schemaErrors: schemaCheck.errors
    };

    if (!id) {
      unnamedFiles.push(entry);
    } else {
      if (!entriesById.has(id)) {
        entriesById.set(id, []);
      }
      entriesById.get(id).push(entry);
    }
  }

  const uniqueFilesById = new Map();
  const duplicateIds = new Set();
  const conflicts = [];
  for (const [id, list] of entriesById.entries()) {
    if (list.length > 1) {
      duplicateIds.add(id);
      conflicts.push({
        id,
        paths: list.map(item => item.filePath)
      });
    } else {
      uniqueFilesById.set(id, list[0]);
    }
  }

  const dbNotes = db.prepare(`
    SELECT id, note_type, title, project, privacy, path, content_sha256,
           lifecycle, evidence_level, review_state, as_of, review_after, status
    FROM notes
  `).all();
  const dbIdSet = new Set(dbNotes.map(n => n.id));

  const untracked = [];
  for (const entry of unnamedFiles) {
    untracked.push({
      id: null,
      path: entry.filePath,
      noteType: entry.fm?.note_type || null,
      schemaValid: entry.schemaValid,
      schemaErrors: entry.schemaErrors,
      status: 'pending_enrollment'
    });
  }
  for (const [id, entry] of uniqueFilesById.entries()) {
    if (!dbIdSet.has(id)) {
      untracked.push({
        id,
        path: entry.filePath,
        noteType: entry.fm?.note_type || null,
        schemaValid: entry.schemaValid,
        schemaErrors: entry.schemaErrors,
        status: 'pending_enrollment'
      });
    }
  }

  const renamed = [];
  const missing = [];
  const activated = [];
  const metadataUpdated = [];
  const nowIso = new Date().toISOString();

  db.exec('SAVEPOINT sync_notes');
  try {
    for (const note of dbNotes) {
      if (duplicateIds.has(note.id)) {
        // ID 冲突时不自动挑选或覆写台账路径/元数据，留待人工处理
        continue;
      }

      const entry = uniqueFilesById.get(note.id);

      if (entry) {
        const currentDiskPath = entry.filePath;
        // 执行单向隐私降级锁：若磁盘去除 sanitized 或含残余密钥，立即同步降级 DB，且绝不反向提权
        let effectivePrivacy = note.privacy;
        const diskIsSanitized = Boolean(entry.fm && entry.fm.privacy === 'sanitized');
        if (note.privacy === 'sanitized' && (!diskIsSanitized || !detectResidualSecrets(entry.raw).clean)) {
          effectivePrivacy = 'local_only';
        }

        let nextTitle = note.title;
        let nextProject = note.project;
        let nextLifecycle = note.lifecycle;
        let nextEvidenceLevel = note.evidence_level;
        let nextReviewState = note.review_state;
        let nextAsOf = note.as_of;
        let nextReviewAfter = note.review_after;
        let nextContentSha = note.content_sha256;
        const changedFields = [];

        if (entry.schemaValid && entry.fm) {
          const fm = entry.fm;
          const candTitle = typeof fm.title === 'string' && fm.title.trim() ? fm.title : note.title;
          const candProject = typeof fm.project === 'string' && fm.project.trim() ? fm.project : note.project;
          const candLifecycle = typeof fm.lifecycle === 'string' && fm.lifecycle.trim() ? fm.lifecycle : note.lifecycle;
          const candEvidence = fm.evidence_level !== undefined ? String(fm.evidence_level) : note.evidence_level;
          const candReviewState = typeof fm.review_state === 'string' && fm.review_state.trim() ? fm.review_state : note.review_state;
          const candAsOf = fm.as_of === undefined || fm.as_of === null ? null : String(fm.as_of);
          const candReviewAfter = fm.review_after === undefined || fm.review_after === null ? null : String(fm.review_after);

          if (candTitle !== note.title) { nextTitle = candTitle; changedFields.push('title'); }
          if (candProject !== note.project) { nextProject = candProject; changedFields.push('project'); }
          if (candLifecycle !== note.lifecycle) { nextLifecycle = candLifecycle; changedFields.push('lifecycle'); }
          if (candEvidence !== note.evidence_level) { nextEvidenceLevel = candEvidence; changedFields.push('evidence_level'); }
          if (candReviewState !== note.review_state) { nextReviewState = candReviewState; changedFields.push('review_state'); }
          if (candAsOf !== note.as_of) { nextAsOf = candAsOf; changedFields.push('as_of'); }
          if (candReviewAfter !== note.review_after) { nextReviewAfter = candReviewAfter; changedFields.push('review_after'); }
        }
        if (entry.sha256 !== note.content_sha256) {
          nextContentSha = entry.sha256;
          changedFields.push('content_sha256');
        }
        if (effectivePrivacy !== note.privacy) {
          changedFields.push('privacy');
        }

        if (!sameFsPath(currentDiskPath, note.path)) {
          // 1. 改名自动识别：路径发生变化但 UUID 唯一匹配，保留 deleted 墓碑状态
          const newStatus = note.status === 'deleted' ? 'deleted' : 'active';
          db.prepare(`
            UPDATE notes
            SET path = ?, status = ?, privacy = ?,
                title = ?, project = ?, lifecycle = ?, evidence_level = ?,
                review_state = ?, as_of = ?, review_after = ?, content_sha256 = ?,
                updated_at = ?
            WHERE id = ?
          `).run(
            currentDiskPath, newStatus, effectivePrivacy,
            nextTitle, nextProject, nextLifecycle, nextEvidenceLevel,
            nextReviewState, nextAsOf, nextReviewAfter, nextContentSha,
            nowIso, note.id
          );

          renamed.push({
            id: note.id,
            oldPath: note.path,
            newPath: currentDiskPath
          });
          if (changedFields.length > 0) {
            metadataUpdated.push({ id: note.id, path: currentDiskPath, changedFields });
          }
        } else if (note.status === 'missing' || effectivePrivacy !== note.privacy || changedFields.length > 0) {
          // 恢复正常、同步单向隐私降级或刷新允许手改字段与内容指纹
          const newStatus = note.status === 'missing' ? 'active' : note.status;
          db.prepare(`
            UPDATE notes
            SET status = ?, privacy = ?,
                title = ?, project = ?, lifecycle = ?, evidence_level = ?,
                review_state = ?, as_of = ?, review_after = ?, content_sha256 = ?,
                updated_at = ?
            WHERE id = ?
          `).run(
            newStatus, effectivePrivacy,
            nextTitle, nextProject, nextLifecycle, nextEvidenceLevel,
            nextReviewState, nextAsOf, nextReviewAfter, nextContentSha,
            nowIso, note.id
          );

          if (note.status === 'missing') {
            activated.push({
              id: note.id,
              path: currentDiskPath
            });
          }
          if (changedFields.length > 0) {
            metadataUpdated.push({ id: note.id, path: currentDiskPath, changedFields });
          }
        }
      } else {
        // 2. 磁盘上找不到该 UUID 的文件
        if (note.status !== 'missing' && note.status !== 'deleted') {
          db.prepare(`
            UPDATE notes
            SET status = 'missing', updated_at = ?
            WHERE id = ?
          `).run(nowIso, note.id);

          missing.push({
            id: note.id,
            path: note.path
          });
        }
      }
    }
    db.exec('RELEASE SAVEPOINT sync_notes');
  } catch (err) {
    try { db.exec('ROLLBACK TO SAVEPOINT sync_notes; RELEASE SAVEPOINT sync_notes'); } catch {}
    throw err;
  }

  return {
    renamed,
    missing,
    activated,
    metadataUpdated,
    untracked,
    conflicts,
    schemaErrors
  };
}

/**
 * 受控登记手动创建的合规笔记：校验路径、Schema、唯一 ID 与残余密钥后才允许入库台账
 * @param {{
 *   db: any,
 *   vaultDir: string,
 *   filePath: string
 * }} options
 */
export function registerManualNote({ db, vaultDir, filePath }) {
  const noteFolders = [
    '10_Readable_Sessions',
    '20_Evidence_Cards',
    '30_Knowledge_Notes',
    '40_Review_Queue'
  ];
  const resolvedVault = path.resolve(vaultDir);
  const resolvedFile = path.resolve(filePath);
  if (!fs.existsSync(resolvedFile) || !resolvedFile.toLowerCase().endsWith('.md')) {
    throw new Error(`ERR_MANUAL_NOTE_NOT_FOUND: 手动笔记不存在或非 Markdown 文件 (${resolvedFile})`);
  }
  if (resolvedFile.replace(/\\/g, '/').includes('/90_Templates/')) {
    throw new Error(`ERR_MANUAL_NOTE_INVALID_PATH: 不允许登记模板文件 (${resolvedFile})`);
  }

  const isInsideAllowedFolder = noteFolders.some(folder => {
    const folderAbs = path.join(resolvedVault, folder);
    const rel = path.relative(folderAbs, resolvedFile);
    return rel && !rel.startsWith('..') && !path.isAbsolute(rel);
  });
  if (!isInsideAllowedFolder) {
    throw new Error(`ERR_MANUAL_NOTE_INVALID_PATH: 仅允许登记四类托管笔记目录内的文件 (${resolvedFile})`);
  }

  const raw = fs.readFileSync(resolvedFile, 'utf8');
  const sha256 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  const parsed = parseMarkdownFrontmatter(raw);
  if (!parsed.hasFrontmatter || !parsed.frontmatter) {
    throw new Error('ERR_MANUAL_NOTE_SCHEMA_INVALID: 缺少 YAML Frontmatter');
  }
  const fm = parsed.frontmatter;
  const schemaCheck = validateFrontmatter(fm);
  if (!schemaCheck.valid) {
    throw new Error(`ERR_MANUAL_NOTE_SCHEMA_INVALID: ${schemaCheck.errors.join(', ')}`);
  }

  // 检查磁盘上所有四类目录中的 ID 唯一性
  const matchingPaths = [];
  for (const folder of noteFolders) {
    for (const candidate of findMarkdownFiles(path.join(resolvedVault, folder), { excludeTemplates: true, followSymlinks: false, boundaryDir: resolvedVault })) {
      if (readFrontmatterId(candidate) === fm.id) {
        matchingPaths.push(path.resolve(candidate));
      }
    }
  }
  if (matchingPaths.length > 1) {
    throw new Error(`ERR_DUPLICATE_NOTE_ID: 磁盘存在重复 id=${fm.id} (${matchingPaths.join(', ')})`);
  }

  const existing = db.prepare('SELECT id, path, status FROM notes WHERE id = ?').get(fm.id);
  if (existing) {
    if (sameFsPath(existing.path, resolvedFile)) {
      return { enrolled: false, reason: 'already_registered', id: fm.id, path: resolvedFile };
    }
    throw new Error(`ERR_DUPLICATE_NOTE_ID: 台账已登记 id=${fm.id} 位于 ${existing.path}`);
  }

  if (fm.privacy === 'sanitized') {
    const residual = detectResidualSecrets(raw);
    if (!residual.clean) {
      throw new Error(`ERR_MANUAL_NOTE_RESIDUAL_SECRETS: 标为 sanitized 的笔记检测到残余敏感信息 (${residual.findings.join(', ')})`);
    }
  }

  const effectivePrivacy = fm.privacy === 'sanitized' ? 'sanitized' : 'local_only';
  const nowIso = new Date().toISOString();
  db.exec('SAVEPOINT register_manual_note');
  try {
    db.prepare(`
      INSERT INTO notes (
        id, note_type, title, project, privacy, path, content_sha256,
        lifecycle, evidence_level, review_state, as_of, review_after,
        status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    `).run(
      fm.id,
      fm.note_type,
      fm.title || path.basename(resolvedFile, '.md'),
      fm.project,
      effectivePrivacy,
      resolvedFile,
      sha256,
      fm.lifecycle || 'active',
      fm.evidence_level || 'E1',
      fm.review_state || 'draft',
      fm.as_of || nowIso.slice(0, 10),
      fm.review_after ?? null,
      nowIso,
      nowIso
    );
    db.exec('RELEASE SAVEPOINT register_manual_note');
  } catch (err) {
    try { db.exec('ROLLBACK TO SAVEPOINT register_manual_note; RELEASE SAVEPOINT register_manual_note'); } catch {}
    throw err;
  }

  return {
    enrolled: true,
    id: fm.id,
    noteType: fm.note_type,
    title: fm.title,
    project: fm.project,
    privacy: effectivePrivacy,
    path: resolvedFile,
    contentSha256: sha256
  };
}

/**
 * 确认删除知识笔记并登记跨快照稳定墓碑 (mem delete <id> --confirm)
 * @param {{
 *   db: any,
 *   noteId: string,
 *   notePath?: string,
 *   reason?: string,
 *   revisionsDir?: string
 * }} params
 * @returns {{ deleted: boolean, noteId: string, itemKey: string }}
 */
export function confirmDeleteNote({ db, noteId, notePath, reason = 'user_deleted', revisionsDir = null, archiveAsRev1 = true }) {
  let filePath = notePath;
  let title = 'Deleted Note';

  const noteInDb = db.prepare('SELECT * FROM notes WHERE id = ?').get(noteId);
  if (noteInDb) {
    filePath = filePath || noteInDb.path;
    title = noteInDb.title || title;
  }

  let sourceTool = 'manual';
  let sessionId = 'unknown';
  let canonicalEventAnchor = '^event-000000';
  let factType = 'knowledge';
  let normalizedSubject = title;

  let diskDowngradedToLocalOnly = false;
  if (filePath && fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const rawParsed = parseMarkdownFrontmatter(content);
      if (!rawParsed.hasFrontmatter || rawParsed.frontmatter?.privacy !== 'sanitized') {
        diskDowngradedToLocalOnly = true;
      }
      if (revisionsDir) {
        const noteRevDir = path.join(revisionsDir, noteId);
        if (!fs.existsSync(noteRevDir)) fs.mkdirSync(noteRevDir, { recursive: true });
        const revPath = path.join(noteRevDir, 'rev-0001.md');
        if (archiveAsRev1 && !fs.existsSync(revPath)) {
          fs.writeFileSync(revPath, content, 'utf8');
        }
        fs.writeFileSync(path.join(noteRevDir, 'latest.md'), content, 'utf8');
      }
      const fields = parseFrontmatterFields(content);
      sourceTool = fields.source_tool || sourceTool;
      sessionId = fields.session_id || sessionId;
      canonicalEventAnchor = fields.canonical_event_anchor || canonicalEventAnchor;
      factType = fields.fact_type || factType;
      normalizedSubject = fields.normalized_subject || fields.title || normalizedSubject;
      title = fields.title || title;
    } catch {
      // ignore
    }
  }

  const itemKey = calculateItemKey({
    sourceTool,
    sessionId,
    canonicalEventAnchor,
    factType,
    normalizedSubject
  });

  const nowIso = new Date().toISOString();

  // 写入 tombstones 墓碑表
  db.prepare(`
    INSERT INTO tombstones (item_key, output_uuid, note_title, reason, deleted_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(item_key) DO UPDATE SET
      output_uuid = excluded.output_uuid,
      note_title = excluded.note_title,
      reason = excluded.reason,
      deleted_at = excluded.deleted_at
  `).run(itemKey, noteId, title, reason, nowIso);

  // 更新 notes 状态为 deleted（同步记录单向隐私降级，严防删后恢复绕过 Exit B）
  db.prepare(`
    UPDATE notes
    SET status = 'deleted',
        privacy = CASE WHEN privacy = 'local_only' OR ? = 1 THEN 'local_only' ELSE privacy END,
        updated_at = ?
    WHERE id = ?
  `).run(diskDowngradedToLocalOnly ? 1 : 0, nowIso, noteId);

  // 移除物理文件（如果存在）
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  return {
    deleted: true,
    noteId,
    itemKey
  };
}

/**
 * 检查事实项是否受墓碑抑制
 * @param {{
 *   db: any,
 *   itemKey: string
 * }} params
 * @returns {boolean}
 */
export function isFactTombstoned({ db, itemKey }) {
  const row = db.prepare('SELECT 1 FROM tombstones WHERE item_key = ?').get(itemKey);
  return Boolean(row);
}
