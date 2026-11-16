import fs from 'node:fs';
import path from 'node:path';
import { stageCandidate, publishFile, assertPublisherUnlocked } from './atomic-publisher.mjs';
import { sanitizeOutputText } from '../security/sanitizer.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';

function isContentSanitized(markdownText) {
  const parsed = parseMarkdownFrontmatter(String(markdownText || ''));
  return parsed.hasFrontmatter && parsed.frontmatter?.privacy === 'sanitized';
}

/**
 * 单篇历史恢复与预览 (mem restore <id> --revision <rev>)
 * @param {{
 *   db: any,
 *   noteId: string,
 *   revision: string,
 *   content: string,
 *   targetVaultPath?: string,
 *   stagingDir: string,
 *   revisionsDir?: string | null,
 *   force?: boolean,
 *   confirm?: boolean
 * }} options
 * @returns {{ restored: boolean, targetPath?: string, previewPath: string, reason?: string, redacted?: boolean }}
 */
export function restoreNote({
  db,
  noteId,
  revision = 'rev-0001',
  content,
  targetVaultPath,
  stagingDir,
  revisionsDir = null,
  force = false,
  confirm = true
}) {
  const previewDir = path.join(stagingDir, 'restore-preview');
  assertPublisherUnlocked(stagingDir);
  if (!fs.existsSync(previewDir)) {
    fs.mkdirSync(previewDir, { recursive: true });
  }

  // 1. 提取指定旧版本内容至 staging/restore-preview/ 供差异预览（Exit B 强制脱敏与 local_only / 缺失 privacy / 降级笔记剥离）
  const safeNoteId = String(noteId || 'note').replace(/[^A-Za-z0-9_.-]/g, '_').replace(/\.{2,}/g, '_');
  const safeRevision = String(revision || 'rev-0001').replace(/[^A-Za-z0-9_.-]/g, '_').replace(/\.{2,}/g, '_');
  const previewPath = path.resolve(previewDir, `${safeNoteId}-${safeRevision}.md`);
  const relPreview = path.relative(path.resolve(previewDir), previewPath);
  if (!relPreview || relPreview.startsWith('..') || path.isAbsolute(relPreview)) {
    throw new Error('INVALID_PREVIEW_PATH: 预览路径禁止越出 staging/restore-preview');
  }

  const contentSanitized = isContentSanitized(content);
  let dbSanitized = true;
  if (db && noteId) {
    try {
      const dbRow = db.prepare('SELECT privacy FROM notes WHERE id = ?').get(noteId);
      if (dbRow && dbRow.privacy !== 'sanitized') {
        dbSanitized = false;
      }
    } catch {
      // ignore if notes table missing in minimal unit context
    }
  }
  let diskSanitized = true;
  if (targetVaultPath && fs.existsSync(targetVaultPath)) {
    try {
      const diskRaw = fs.readFileSync(targetVaultPath, 'utf8');
      const diskParsed = parseMarkdownFrontmatter(diskRaw);
      if (!diskParsed.hasFrontmatter || diskParsed.frontmatter?.privacy !== 'sanitized') {
        diskSanitized = false;
      }
    } catch {
      diskSanitized = false;
    }
  }
  let latestRevSanitized = true;
  if (revisionsDir && noteId) {
    const latestRevFile = path.join(revisionsDir, safeNoteId, 'latest.md');
    if (fs.existsSync(latestRevFile)) {
      try {
        if (!isContentSanitized(fs.readFileSync(latestRevFile, 'utf8'))) {
          latestRevSanitized = false;
        }
      } catch {
        latestRevSanitized = false;
      }
    }
  }

  const redacted = !(contentSanitized && dbSanitized && diskSanitized && latestRevSanitized);
  const safePreviewContent = redacted
    ? `[REDACTED: privacy=local_only、缺失/非法 privacy 或已降级笔记正文禁止进入可预览文件通道]`
    : sanitizeOutputText(content);
  fs.writeFileSync(previewPath, safePreviewContent, 'utf8');

  // 2. 若指定了 Vault 恢复目标路径
  if (targetVaultPath) {
    // 保护原则：若原文件仍在，由用户在 Obsidian 中合入差异，严禁盲目原地覆盖
    if (fs.existsSync(targetVaultPath) && !force) {
      return {
        restored: false,
        reason: 'target_file_exists_merge_in_obsidian',
        targetPath: targetVaultPath,
        previewPath,
        redacted
      };
    }

    // C-blocker 1 / 预览与实际恢复分离：未显式确认前绝不发布、绝不解除墓碑
    if (!confirm) {
      return {
        restored: false,
        reason: 'confirmation_required',
        targetPath: targetVaultPath,
        previewPath,
        redacted
      };
    }

    // 若原文件已删除且已显式确认：通过 §5.2 原子发布安全恢复
    const opId = `restore-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
    const { stagingPath, contentSha256 } = stageCandidate({
      stagingDir,
      outputUuid: noteId,
      content
    });

    const pubResult = publishFile({
      db,
      operationId: opId,
      outputUuid: noteId,
      stagingPath,
      vaultTargetPath: targetVaultPath,
      contentSha256,
      revisionsDir
    });

    const nowIso = new Date().toISOString();

    // 3. 精确解除墓碑表中针对该 output_uuid 的抑制
    db.prepare('DELETE FROM tombstones WHERE output_uuid = ?').run(noteId);

    // 4. 更新 notes 表状态为 active（并执行隐私单向降级锁：若恢复内容非 sanitized，则强制记录为 local_only）
    const restoredParsed = parseMarkdownFrontmatter(String(content || ''));
    const restoredIsSanitized = restoredParsed.hasFrontmatter && restoredParsed.frontmatter?.privacy === 'sanitized';
    db.prepare(`
      UPDATE notes
      SET status = 'active',
          path = ?,
          content_sha256 = ?,
          privacy = CASE WHEN privacy = 'local_only' OR ? = 0 THEN 'local_only' ELSE privacy END,
          updated_at = ?
      WHERE id = ?
    `).run(pubResult.vaultTargetPath, contentSha256, restoredIsSanitized ? 1 : 0, nowIso, noteId);

    return {
      restored: true,
      operationId: opId,
      targetPath: pubResult.vaultTargetPath,
      previewPath,
      redacted
    };
  }

  return {
    restored: false,
    previewPath,
    redacted
  };
}
