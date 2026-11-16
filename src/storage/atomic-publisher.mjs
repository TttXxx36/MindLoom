import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { readFrontmatterId, resolveTargetFilePath } from './path-sanitizer.mjs';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { validateFrontmatter } from '../schema/validator.mjs';

/**
 * 计算文本内容的 SHA-256 哈希
 * @param {string} content
 * @returns {string}
 */
export function calculateSha256(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function isLockPidAlive(pid) {
  const num = Number(pid);
  if (!Number.isInteger(num) || num <= 0) return false;
  try {
    process.kill(num, 0);
    return true;
  } catch (err) {
    return Boolean(err && err.code === 'EPERM');
  }
}

export function assertPublisherUnlocked(stagingDir) {
  if (!stagingDir) return;
  if (path.basename(stagingDir) === 'staging') {
    const runtimeDir = path.join(path.dirname(stagingDir), 'runtime');
    const legacyLockPath = path.join(runtimeDir, 'publisher.lock');
    if (fs.existsSync(legacyLockPath)) {
      throw new Error('PUBLISHER_LOCKED: 检测到遗留发布器互斥锁 publisher.lock，已暂停状态写入');
    }
    const writeLockPath = path.join(runtimeDir, 'write.lock');
    if (fs.existsSync(writeLockPath)) {
      let lockBlocked = false;
      let lockReason = '检测到 write.lock 活跃写锁，已暂停非持锁状态写入';
      try {
        const rawLock = fs.readFileSync(writeLockPath, 'utf8');
        const parsed = rawLock.trim() ? JSON.parse(rawLock) : null;
        if (!parsed) {
          lockBlocked = true;
          lockReason = '检测到半写入 write.lock，已暂停状态写入';
        } else if (parsed.command === 'backup') {
          lockBlocked = true;
          lockReason = '本地发布器正处于 R4 一致性备份窗口，已暂停状态写入';
        } else if (parsed.pid && Number(parsed.pid) !== process.pid && isLockPidAlive(parsed.pid)) {
          lockBlocked = true;
          lockReason = `检测到其他进程 (PID=${parsed.pid}, command=${parsed.command || 'unknown'}) 持有 write.lock，已暂停并发状态写入`;
        }
      } catch {
        lockBlocked = true;
        lockReason = '检测到无法解析的 write.lock，已暂停状态写入';
      }
      if (lockBlocked) {
        throw new Error(`PUBLISHER_LOCKED: ${lockReason}`);
      }
    }
  }
}

function extractFallbackMetadata(filePath, nowIso) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const { frontmatter } = parseMarkdownFrontmatter(raw);
    if (!frontmatter.note_type) return null;
    return {
      note_type: frontmatter.note_type,
      title: frontmatter.title || 'Untitled',
      project: frontmatter.project || 'Default',
      privacy: frontmatter.privacy || 'local_only',
      lifecycle: frontmatter.lifecycle || 'active',
      evidence_level: frontmatter.evidence_level || 'observed',
      review_state: frontmatter.review_state || 'pending',
      as_of: frontmatter.as_of || null,
      review_after: frontmatter.review_after || null,
      created_at: frontmatter.created_at || nowIso
    };
  } catch {
    return null;
  }
}

/**
 * 同卷优先硬链接原子发布；跨卷/跨文件系统遇到 EXDEV 时，在目标目录内 wx 独占写入临时文件后再硬链接落盘，绝不覆盖既有文件
 * @param {string} stagingPath
 * @param {string} targetPath
 */
export function linkFileAtomically(stagingPath, targetPath) {
  try {
    fs.linkSync(stagingPath, targetPath);
    return { crossVolumeFallback: false };
  } catch (err) {
    if (err?.code !== 'EXDEV') {
      throw err;
    }
    const targetDir = path.dirname(targetPath);
    const tmpName = `.mindloom-xdev-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.tmp`;
    const tmpPath = path.join(targetDir, tmpName);
    const buf = fs.readFileSync(stagingPath);
    const fd = fs.openSync(tmpPath, 'wx', 0o644);
    try {
      fs.writeSync(fd, buf, 0, buf.length, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.linkSync(tmpPath, targetPath);
    } finally {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {
        // ignore temp cleanup failure
      }
    }
    return { crossVolumeFallback: true };
  }
}

/**
 * 暂存候选文件 (Panel B 规范：wx 独占创建，保持可写权限，严禁设置 OS 只读属性)
 * @param {{
 *   stagingDir: string,
 *   outputUuid: string,
 *   content: string,
 *   validateSchema?: boolean
 * }} options
 * @returns {{ stagingPath: string, contentSha256: string, frontmatter?: object }}
 */
export function stageCandidate({ stagingDir, outputUuid, content, validateSchema = false }) {
  assertPublisherUnlocked(stagingDir);
  if (!fs.existsSync(stagingDir)) {
    fs.mkdirSync(stagingDir, { recursive: true });
  }

  const stagingPath = path.join(stagingDir, `stg-${outputUuid}.md`);
  const contentSha256 = calculateSha256(content);

  // 使用 wx 独占模式打开并写入，如果文件已存在抛出 EEXIST
  // 保持 0o644 可写权限，严禁设为只读
  const fd = fs.openSync(stagingPath, 'wx', 0o644);
  try {
    fs.writeSync(fd, content, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  if (process.platform !== 'win32') {
    const st = fs.statSync(stagingPath);
    if ((st.mode & 0o200) === 0) {
      fs.chmodSync(stagingPath, st.mode | 0o644);
    }
  }

  // §5.2 步骤 1：关闭写入句柄后，重新以只读模式 ('r') 打开校验 Schema 与隐私规则
  const rfd = fs.openSync(stagingPath, 'r');
  let readBack = '';
  try {
    readBack = fs.readFileSync(rfd, 'utf8');
  } finally {
    fs.closeSync(rfd);
  }

  const { frontmatter, hasFrontmatter } = parseMarkdownFrontmatter(readBack);
  if (validateSchema) {
    if (!hasFrontmatter) {
      fs.unlinkSync(stagingPath);
      throw new Error('CANDIDATE_SCHEMA_INVALID: 候选文件缺少 YAML Frontmatter');
    }
    const fmCheck = validateFrontmatter(frontmatter);
    if (!fmCheck.valid) {
      fs.unlinkSync(stagingPath);
      throw new Error(`CANDIDATE_SCHEMA_INVALID: ${fmCheck.errors.join('; ')}`);
    }
  }

  return {
    stagingPath,
    contentSha256,
    frontmatter
  };
}

function recordNoteInDb(db, outputUuid, targetPath, contentSha256, metadata, nowIso) {
  db.prepare(`
    INSERT INTO notes (id, note_type, title, project, privacy, path, content_sha256, lifecycle, evidence_level, review_state, as_of, review_after, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      title = excluded.title,
      project = excluded.project,
      privacy = CASE WHEN notes.privacy = 'local_only' THEN 'local_only' ELSE excluded.privacy END,
      path = excluded.path,
      content_sha256 = excluded.content_sha256,
      lifecycle = excluded.lifecycle,
      evidence_level = excluded.evidence_level,
      review_state = excluded.review_state,
      as_of = excluded.as_of,
      review_after = excluded.review_after,
      status = 'active',
      updated_at = excluded.updated_at
  `).run(
    outputUuid,
    metadata.note_type || 'knowledge',
    metadata.title || 'Untitled',
    metadata.project || 'Default',
    metadata.privacy || 'local_only',
    targetPath,
    contentSha256,
    metadata.lifecycle || 'active',
    metadata.evidence_level || 'observed',
    metadata.review_state || 'pending',
    metadata.as_of || null,
    metadata.review_after || null,
    metadata.created_at || nowIso,
    nowIso
  );
}

/**
 * NTFS 硬链接原子发布 (同卷不覆盖原子发布，合入 R7 碰撞消歧)
 * @param {{
 *   db: any,
 *   operationId: string,
 *   outputUuid: string,
 *   stagingPath: string,
 *   vaultTargetPath: string,
 *   contentSha256: string,
 *   metadata?: object,
 *   revisionsDir?: string
 * }} params
 * @returns {{ success: boolean, vaultTargetPath: string, isRetry?: boolean, collided?: boolean, expanded?: boolean }}
 */
export function publishFile({
  db,
  operationId,
  outputUuid,
  stagingPath,
  vaultTargetPath,
  contentSha256,
  metadata,
  revisionsDir = null
}) {
  assertPublisherUnlocked(path.dirname(stagingPath));
  if (!fs.existsSync(stagingPath)) {
    throw new Error(`暂存文件不存在: ${stagingPath}`);
  }

  const nowIso = new Date().toISOString();
  let actualTargetPath = vaultTargetPath;
  let isRetry = false;
  let collided = false;
  let expanded = false;

  // 检查目标路径是否已存在 (R7 / R1 协议)
  if (fs.existsSync(actualTargetPath)) {
    const existingId = readFrontmatterId(actualTargetPath);
    if (existingId && existingId === outputUuid) {
      // 1. 同作业重试场景：复用原路径
      if (fs.existsSync(stagingPath)) {
        fs.unlinkSync(stagingPath);
      }
      db.prepare(`
        INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'files_published', ?, ?)
        ON CONFLICT(operation_id) DO UPDATE SET
          target_path = excluded.target_path,
          state = 'files_published',
          updated_at = excluded.updated_at
      `).run(operationId, outputUuid, stagingPath, actualTargetPath, contentSha256, nowIso, nowIso);

      const effectiveMetadata = metadata || extractFallbackMetadata(actualTargetPath, nowIso);
      if (effectiveMetadata) {
        recordNoteInDb(db, outputUuid, actualTargetPath, contentSha256, effectiveMetadata, nowIso);
      }

      if (revisionsDir && fs.existsSync(actualTargetPath)) {
        try {
          const noteRevDir = path.join(revisionsDir, outputUuid);
          if (!fs.existsSync(noteRevDir)) fs.mkdirSync(noteRevDir, { recursive: true });
          const finalContent = fs.readFileSync(actualTargetPath, 'utf8');
          const rev1 = path.join(noteRevDir, 'rev-0001.md');
          if (!fs.existsSync(rev1)) fs.writeFileSync(rev1, finalContent, 'utf8');
          fs.writeFileSync(path.join(noteRevDir, 'latest.md'), finalContent, 'utf8');
        } catch {
          // ignore non-critical revision cache write failure
        }
      }

      return {
        success: true,
        vaultTargetPath: actualTargetPath,
        isRetry: true,
        collided: false,
        expanded: false
      };
    } else {
      // 2. 发生短文件名碰撞：严禁覆盖原文件！按 R7 规则消歧扩展路径
      collided = true;
      const targetDir = path.dirname(actualTargetPath);
      const baseName = path.basename(actualTargetPath);
      const parsedMatch = baseName.match(/^([A-Za-z]+)-(\d{8})-(?:([a-z0-9_-]+?)-)?([0-9a-fA-F]+)_(.+)\.md$/);
      const prefix = (metadata && metadata.prefix) || (parsedMatch ? parsedMatch[1] : 'KN');
      const dateStr = (metadata && metadata.dateStr) || (parsedMatch ? parsedMatch[2] : new Date().toISOString().slice(0, 10).replace(/-/g, ''));
      const sourceTool = (metadata && metadata.source_tool) || (parsedMatch ? parsedMatch[3] || null : null);
      const title = (metadata && metadata.title) || (parsedMatch ? parsedMatch[5] : '未命名');

      const resolved = resolveTargetFilePath({
        targetDir,
        prefix,
        dateStr,
        sourceTool,
        uuid: outputUuid,
        title
      });

      actualTargetPath = resolved.targetPath;
      expanded = true;
    }
  }

  const targetDir = path.dirname(actualTargetPath);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  // 1. 预登记发布意图
  db.prepare(`
    INSERT INTO publish_intents (operation_id, output_uuid, staging_path, target_path, content_sha256, state, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'linking', ?, ?)
    ON CONFLICT(operation_id) DO UPDATE SET
      output_uuid = excluded.output_uuid,
      staging_path = excluded.staging_path,
      target_path = excluded.target_path,
      content_sha256 = excluded.content_sha256,
      state = 'linking',
      updated_at = excluded.updated_at
  `).run(operationId, outputUuid, stagingPath, actualTargetPath, contentSha256, nowIso, nowIso);

  // 2. 建立硬链接（或同目录 EXDEV 原子 fallback）
  linkFileAtomically(stagingPath, actualTargetPath);

  // 3. 断开暂存侧链接
  fs.unlinkSync(stagingPath);

  // 4. 更新台账状态为 files_published
  db.prepare(`
    UPDATE publish_intents
    SET state = 'files_published', updated_at = ?
    WHERE operation_id = ?
  `).run(nowIso, operationId);

  // 5. 若传入 metadata 或文件含合法 Frontmatter，记录到 notes 表中
  const effectiveMetadata = metadata || extractFallbackMetadata(actualTargetPath, nowIso);
  if (effectiveMetadata) {
    recordNoteInDb(db, outputUuid, actualTargetPath, contentSha256, effectiveMetadata, nowIso);
  }

  // 6. 保存本地基准版本快照 (供 mem restore 提取历史版本)
  if (revisionsDir && fs.existsSync(actualTargetPath)) {
    try {
      const noteRevDir = path.join(revisionsDir, outputUuid);
      if (!fs.existsSync(noteRevDir)) fs.mkdirSync(noteRevDir, { recursive: true });
      const content = fs.readFileSync(actualTargetPath, 'utf8');
      const rev1 = path.join(noteRevDir, 'rev-0001.md');
      if (!fs.existsSync(rev1)) fs.writeFileSync(rev1, content, 'utf8');
      fs.writeFileSync(path.join(noteRevDir, 'latest.md'), content, 'utf8');
    } catch {
      // ignore non-critical revision cache write failure
    }
  }

  return {
    success: true,
    vaultTargetPath: actualTargetPath,
    isRetry,
    collided,
    expanded
  };
}

/**
 * R1 中断恢复协议
 * @param {{
 *   db: any,
 *   operationId?: string,
 *   revisionsDir?: string | null
 * }} params
 * @returns {{ recovered: boolean, count: number, details: Array<object> }}
 */
export function recoverInterruptedPublish({ db, operationId, revisionsDir = null }) {
  const query = operationId
    ? db.prepare('SELECT * FROM publish_intents WHERE operation_id = ? AND state = ?').all(operationId, 'linking')
    : db.prepare('SELECT * FROM publish_intents WHERE state = ?').all('linking');

  const results = [];
  const nowIso = new Date().toISOString();

  for (const intent of query) {
    const { staging_path: stagingPath, target_path: targetPath, output_uuid: outputUuid, operation_id: opId, content_sha256: contentSha } = intent;
    let finalTargetPath = null;
    let action = null;

    // 检查 targetPath 是否存在
    if (fs.existsSync(targetPath)) {
      const targetId = readFrontmatterId(targetPath);
      if (targetId === outputUuid) {
        // 硬链接已建立成功！
        // 铁律：绝对保留用户在崩溃期间修改的内容，绝不覆盖或截断 targetPath，绝不向 staging 写入
        if (fs.existsSync(stagingPath)) {
          fs.unlinkSync(stagingPath);
        }

        db.prepare(`
          UPDATE publish_intents
          SET state = 'files_published', updated_at = ?
          WHERE operation_id = ?
        `).run(nowIso, opId);

        finalTargetPath = targetPath;
        action = 'unlinked_staging_kept_user_content';
      } else {
        // 目标存在但归属其他笔记 ID：按 §4.1 的 R7 碰撞消歧分配扩展后缀新路径并重新建立硬链接
        const targetDir = path.dirname(targetPath);
        const baseName = path.basename(targetPath);
        const parsedMatch = baseName.match(/^([A-Za-z]+)-(\d{8})-(?:([a-z0-9_-]+?)-)?([0-9a-fA-F]+)_(.+)\.md$/);
        const prefix = parsedMatch ? parsedMatch[1] : 'KN';
        const dateStr = parsedMatch ? parsedMatch[2] : new Date().toISOString().slice(0, 10).replace(/-/g, '');
        const sourceTool = parsedMatch ? parsedMatch[3] || null : null;
        const title = parsedMatch ? parsedMatch[5] : '未命名';

        const resolved = resolveTargetFilePath({
          targetDir,
          prefix,
          dateStr,
          sourceTool,
          uuid: outputUuid,
          title
        });
        const expandedTargetPath = resolved.targetPath;

        if (fs.existsSync(stagingPath)) {
          linkFileAtomically(stagingPath, expandedTargetPath);
          fs.unlinkSync(stagingPath);
        }

        db.prepare(`
          UPDATE publish_intents
          SET target_path = ?, state = 'files_published', updated_at = ?
          WHERE operation_id = ?
        `).run(expandedTargetPath, nowIso, opId);

        finalTargetPath = expandedTargetPath;
        action = 'disambiguated_collision_expanded';
      }
    } else if (fs.existsSync(stagingPath)) {
      // 目标尚不存在，若 stagingPath 存在则继续完成 link 与 unlink
      const targetDir = path.dirname(targetPath);
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }
      linkFileAtomically(stagingPath, targetPath);
      fs.unlinkSync(stagingPath);

      db.prepare(`
        UPDATE publish_intents
        SET state = 'files_published', updated_at = ?
        WHERE operation_id = ?
      `).run(nowIso, opId);

      finalTargetPath = targetPath;
      action = 'completed_link_and_unlink';
    }

    if (finalTargetPath && fs.existsSync(finalTargetPath)) {
      // 确保 notes 表同步登记 R1 恢复后的正式笔记（绝不遗漏未执行第 5 步的崩溃作业）
      const fallbackMeta = extractFallbackMetadata(finalTargetPath, nowIso);
      const currentSha = calculateSha256(fs.readFileSync(finalTargetPath, 'utf8'));
      const existingNote = db.prepare('SELECT id FROM notes WHERE id = ?').get(outputUuid);
      if (!existingNote && fallbackMeta) {
        recordNoteInDb(db, outputUuid, finalTargetPath, currentSha || contentSha, fallbackMeta, nowIso);
      } else if (existingNote) {
        db.prepare(`
          UPDATE notes
          SET path = ?, status = 'active', content_sha256 = COALESCE(?, content_sha256), updated_at = ?
          WHERE id = ?
        `).run(finalTargetPath, currentSha || contentSha || null, nowIso, outputUuid);
      }

      if (revisionsDir) {
        try {
          const noteRevDir = path.join(revisionsDir, outputUuid);
          if (!fs.existsSync(noteRevDir)) fs.mkdirSync(noteRevDir, { recursive: true });
          const finalContent = fs.readFileSync(finalTargetPath, 'utf8');
          const rev1 = path.join(noteRevDir, 'rev-0001.md');
          if (!fs.existsSync(rev1)) fs.writeFileSync(rev1, finalContent, 'utf8');
          fs.writeFileSync(path.join(noteRevDir, 'latest.md'), finalContent, 'utf8');
        } catch {
          // ignore non-critical revision cache write failure
        }
      }

      results.push({
        operationId: opId,
        outputUuid,
        recovered: true,
        action,
        targetPath: finalTargetPath
      });
    }
  }

  return {
    recovered: results.length > 0 && results.every(r => r.recovered),
    count: results.length,
    details: results
  };
}
