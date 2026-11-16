import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { openExistingDatabase } from '../db/sqlite.mjs';
import { recoverInterruptedPublish } from './atomic-publisher.mjs';
import { settlePublishedGitCommit } from '../git/repo-manager.mjs';

export function recordOperationSettlement({ db, operationId, gitState, indexState = 'stale' }) {
  if (!db || !operationId) return;
  db.prepare(`
    INSERT INTO auxiliary_states (operation_id, git_state, index_state, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(operation_id) DO UPDATE SET
      git_state = excluded.git_state,
      index_state = excluded.index_state,
      updated_at = excluded.updated_at
  `).run(operationId, gitState, indexState, new Date().toISOString());
}

export const DEFAULT_LOCK_TIMEOUT_MS = 30000;
export const DEFAULT_RETRY_INTERVAL_MS = 50;
export const HALF_WRITTEN_GRACE_MS = 150;

function sleepSync(ms) {
  if (ms <= 0) return;
  const sab = new SharedArrayBuffer(4);
  const view = new Int32Array(sab);
  Atomics.wait(view, 0, 0, ms);
}

/**
 * 检查指定 PID 是否仍在当前操作系统存活
 * @param {number} pid
 * @returns {boolean}
 */
export function isPidAlive(pid) {
  const num = Number(pid);
  if (!Number.isInteger(num) || num <= 0) return false;
  try {
    process.kill(num, 0);
    return true;
  } catch (err) {
    if (err && err.code === 'EPERM') {
      return true;
    }
    return false;
  }
}

/**
 * 读取并解析 write.lock 内容
 * @param {string} lockPath
 * @returns {{ valid: boolean, payload: object | null, raw: string, stat: fs.Stats | null }}
 */
export function inspectWriteLockFile(lockPath) {
  if (!fs.existsSync(lockPath)) {
    return { valid: false, payload: null, raw: '', stat: null };
  }
  try {
    const stat = fs.statSync(lockPath);
    const raw = fs.readFileSync(lockPath, 'utf8');
    if (!raw || !raw.trim()) {
      return { valid: false, payload: null, raw, stat };
    }
    const parsed = JSON.parse(raw);
    const valid = Boolean(
      parsed &&
      typeof parsed === 'object' &&
      Number.isInteger(Number(parsed.pid)) &&
      typeof parsed.lock_token === 'string' &&
      parsed.lock_token.length > 0
    );
    return { valid, payload: valid ? parsed : null, raw, stat };
  } catch {
    let stat = null;
    try { stat = fs.statSync(lockPath); } catch {}
    return { valid: false, payload: null, raw: '', stat };
  }
}

export function inspectPublisherLockFile(lockPath) {
  if (!fs.existsSync(lockPath)) {
    return { exists: false, valid: false, payload: null, raw: '', stat: null };
  }
  try {
    const stat = fs.statSync(lockPath);
    const raw = fs.readFileSync(lockPath, 'utf8');
    if (!raw || !raw.trim()) {
      return { exists: true, valid: false, payload: null, raw, stat };
    }
    const parsed = JSON.parse(raw);
    const valid = Boolean(
      parsed &&
      typeof parsed === 'object' &&
      Number.isInteger(Number(parsed.pid)) &&
      Number(parsed.pid) > 0
    );
    return { exists: true, valid, payload: valid ? parsed : null, raw, stat };
  } catch {
    let stat = null;
    try { stat = fs.statSync(lockPath); } catch {}
    return { exists: true, valid: false, payload: null, raw: '', stat };
  }
}

/**
 * 获取跨进程全局写锁 (runtime/write.lock)
 * 铁律 (§4.2 & 第 5/6 轮审核):
 *   1. 使用 wx 独占创建，写入 { pid, host_tool, command, acquired_at, hostname, lock_token } 并 fsync
 *   2. 普通等待进程发现陈旧锁（PID 已死）或超过宽限期仍损坏的半写锁时，严禁自行删除 write.lock，
 *      必须立即中止并抛出 ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY，提示运行 mem recover-lock
 *   3. 释放时核对 lock_token 一致才允许 unlink，严禁误删其他进程的锁
 *
 * @param {{
 *   dataPath: string,
 *   command?: string,
 *   hostTool?: string,
 *   timeoutMs?: number,
 *   retryIntervalMs?: number,
 *   pidOverride?: number,
 *   isPidAliveFn?: (pid: number) => boolean
 * }} options
 */
export function acquireWriteLock({
  dataPath,
  command = 'unknown',
  hostTool = process.env.AGENT_MEMORY_HOST_TOOL || 'cli',
  timeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
  retryIntervalMs = DEFAULT_RETRY_INTERVAL_MS,
  pidOverride = process.pid,
  isPidAliveFn = isPidAlive
}) {
  const runtimeDir = path.join(dataPath, 'runtime');
  if (!fs.existsSync(runtimeDir)) {
    fs.mkdirSync(runtimeDir, { recursive: true });
  }

  const lockPath = path.join(runtimeDir, 'write.lock');
  const legacyPublisherLockPath = path.join(runtimeDir, 'publisher.lock');
  const recoveringLockPath = path.join(runtimeDir, 'write.recovering.lock');
  const lockToken = `wlk-${crypto.randomUUID()}`;
  const startMs = Date.now();
  let malformedFirstSeenMs = null;
  let legacyMalformedFirstSeenMs = null;

  while (true) {
    // 若正在执行 mem recover-lock 过渡阶段，等待或提示恢复中
    if (fs.existsSync(recoveringLockPath) && command !== 'recover-lock') {
      if (Date.now() - startMs >= timeoutMs) {
        const err = new Error('ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS: 写锁恢复流程正在进行中，等待超时');
        err.code = 'ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS';
        throw err;
      }
      sleepSync(retryIntervalMs);
      continue;
    }

    // D3 过渡保护：若旧版孤儿 runtime/publisher.lock 存在，按同等状态机处理（存活等待，死锁拒绝并要求 recover-lock）
    if (command !== 'recover-lock' && fs.existsSync(legacyPublisherLockPath)) {
      const pubInfo = inspectPublisherLockFile(legacyPublisherLockPath);
      if (pubInfo.exists) {
        if (pubInfo.valid && pubInfo.payload) {
          legacyMalformedFirstSeenMs = null;
          const pubPid = Number(pubInfo.payload.pid);
          if (!isPidAliveFn(pubPid)) {
            const staleErr = new Error(
              `ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY: 检测到已终止进程 (PID=${pubPid}) 遗留的陈旧 publisher.lock；普通写进程严禁擅自删锁，请先执行 mem recover-lock`
            );
            staleErr.code = 'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY';
            throw staleErr;
          }
        } else {
          if (legacyMalformedFirstSeenMs === null) {
            legacyMalformedFirstSeenMs = Date.now();
          } else if (Date.now() - legacyMalformedFirstSeenMs >= HALF_WRITTEN_GRACE_MS) {
            const corruptErr = new Error(
              'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY: 检测到损坏的遗留 publisher.lock；请先执行 mem recover-lock'
            );
            corruptErr.code = 'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY';
            throw corruptErr;
          }
        }

        if (Date.now() - startMs >= timeoutMs) {
          const timeoutErr = new Error(
            `ERR_WRITE_LOCK_TIMEOUT: 等待全局写锁超时 (${timeoutMs}ms) [EEXIST], 遗留 publisher.lock 持有者 PID=${pubInfo.payload?.pid ?? 'unknown'}`
          );
          timeoutErr.code = 'ERR_WRITE_LOCK_TIMEOUT';
          throw timeoutErr;
        }
        sleepSync(retryIntervalMs);
        continue;
      }
    }

    try {
      const fd = fs.openSync(lockPath, 'wx');
      const payload = {
        pid: pidOverride,
        host_tool: hostTool,
        command,
        acquired_at: new Date().toISOString(),
        hostname: os.hostname(),
        lock_token: lockToken
      };
      try {
        fs.writeSync(fd, JSON.stringify(payload, null, 2) + '\n', 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }

      return {
        lockPath,
        lockToken,
        payload,
        release() {
          return releaseWriteLock({ lockPath, lockToken });
        }
      };
    } catch (openErr) {
      if (openErr.code !== 'EEXIST') {
        throw openErr;
      }

      const info = inspectWriteLockFile(lockPath);
      if (!info.stat && !fs.existsSync(lockPath)) {
        // 锁刚刚被正常释放，立即重试
        malformedFirstSeenMs = null;
        continue;
      }

      if (info.valid && info.payload) {
        malformedFirstSeenMs = null;
        const holderPid = Number(info.payload.pid);
        if (!isPidAliveFn(holderPid)) {
          const staleErr = new Error(
            `ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY: 检测到已终止进程 (PID=${holderPid}, command=${info.payload.command || 'unknown'}) 遗留的陈旧 write.lock；普通写进程严禁擅自删锁，请先执行 mem recover-lock`
          );
          staleErr.code = 'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY';
          throw staleErr;
        }
      } else {
        // 可能遇到正在写入的半写锁，给予短暂宽限期；若超过宽限期仍无法解析则判定为损坏陈旧锁
        if (malformedFirstSeenMs === null) {
          malformedFirstSeenMs = Date.now();
        } else if (Date.now() - malformedFirstSeenMs >= HALF_WRITTEN_GRACE_MS) {
          const corruptErr = new Error(
            'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY: 检测到半写或损坏的 write.lock 文件；普通写进程严禁擅自删锁，请先执行 mem recover-lock'
          );
          corruptErr.code = 'ERR_WRITE_LOCK_STALE_REQUIRES_RECOVERY';
          throw corruptErr;
        }
      }

      if (Date.now() - startMs >= timeoutMs) {
        const timeoutErr = new Error(
          `ERR_WRITE_LOCK_TIMEOUT: 等待全局写锁超时 (${timeoutMs}ms) [EEXIST]，当前持有者 PID=${info.payload?.pid ?? 'unknown'} (${info.payload?.command ?? 'unknown'})`
        );
        timeoutErr.code = 'ERR_WRITE_LOCK_TIMEOUT';
        throw timeoutErr;
      }

      sleepSync(retryIntervalMs);
    }
  }
}

/**
 * 释放全局写锁（强制核对 lock_token，不一致严禁删除）
 * @param {{ lockPath: string, lockToken: string }} params
 * @returns {boolean}
 */
export function releaseWriteLock({ lockPath, lockToken }) {
  if (!lockPath || !lockToken || !fs.existsSync(lockPath)) {
    return false;
  }
  const info = inspectWriteLockFile(lockPath);
  if (!info.valid || !info.payload || info.payload.lock_token !== lockToken) {
    return false;
  }
  try {
    fs.unlinkSync(lockPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * 在全局写锁保护下执行同步或异步回调
 * @param {{
 *   dataPath: string,
 *   command: string,
 *   hostTool?: string,
 *   timeoutMs?: number
 * }} options
 * @param {() => any} fn
 */
export function withWriteLock(options, fn) {
  const handle = acquireWriteLock(options);
  let isAsync = false;
  try {
    const result = fn(handle);
    if (result && typeof result.then === 'function') {
      isAsync = true;
      return result.finally(() => {
        handle.release();
      });
    }
    return result;
  } finally {
    if (!isAsync) {
      handle.release();
    }
  }
}

function inspectRecoveringLockFile(lockPath) {
  if (!fs.existsSync(lockPath)) {
    return { valid: false, payload: null, stat: null };
  }
  try {
    const stat = fs.statSync(lockPath);
    const raw = fs.readFileSync(lockPath, 'utf8');
    if (!raw || !raw.trim()) {
      return { valid: false, payload: null, stat };
    }
    const parsed = JSON.parse(raw);
    const valid = Boolean(parsed && typeof parsed === 'object' && Number.isInteger(Number(parsed.pid)));
    return { valid, payload: valid ? parsed : null, stat };
  } catch {
    let stat = null;
    try { stat = fs.statSync(lockPath); } catch {}
    return { valid: false, payload: null, stat };
  }
}

/**
 * 专用锁恢复流程 (mem recover-lock)
 * 第 5 轮 & 第 6 轮审核闭环规约 (§4.2):
 *   1. 先以 wx 独占获取 runtime/write.recovering.lock，阻止并发恢复与普通抢锁
 *   2. 核验现有 write.lock 是否确实陈旧（持有者 PID 已不存在或文件内容损坏）；若 PID 仍存活则拒绝恢复
 *   3. 将陈旧 write.lock 原子移入 runtime/stale-locks/ 归档留痕
 *   4. 【第 6 轮审核修复 1】在释放 write.recovering.lock 及触碰任何台账/文件/Git 之前，
 *      恢复者必须先以 wx 获取正常 runtime/write.lock（持有独立 lock_token），严防普通写进程在恢复期间插入撞车！
 *   5. 持正常 write.lock 执行 R1 未决发布恢复 (recoverInterruptedPublish) 与未完成 Git 补提交
 *   6. 校验 lock_token 后释放正常 write.lock
 *
 * @param {{
 *   vaultPath: string,
 *   dataPath: string,
 *   hostTool?: string,
 *   isPidAliveFn?: (pid: number) => boolean,
 *   duringRecoveryHook?: (context: { activeWriteLockPath: string, activeLockToken: string }) => void
 * }} params
 */
export function recoverStaleWriteLock({
  vaultPath,
  dataPath,
  hostTool = process.env.AGENT_MEMORY_HOST_TOOL || 'cli',
  isPidAliveFn = isPidAlive,
  duringRecoveryHook = null
}) {
  const runtimeDir = path.join(dataPath, 'runtime');
  const staleLocksDir = path.join(runtimeDir, 'stale-locks');
  if (!fs.existsSync(staleLocksDir)) {
    fs.mkdirSync(staleLocksDir, { recursive: true });
  }

  const lockPath = path.join(runtimeDir, 'write.lock');
  const legacyPublisherLockPath = path.join(runtimeDir, 'publisher.lock');
  const recoveringLockPath = path.join(runtimeDir, 'write.recovering.lock');

  // 1. 独占获取 write.recovering.lock（若存在已终止进程的遗留恢复锁则安全归档后接管，避免永久死锁）
  let recFd;
  for (let recAttempt = 0; recAttempt < 2; recAttempt++) {
    try {
      recFd = fs.openSync(recoveringLockPath, 'wx');
      fs.writeSync(
        recFd,
        JSON.stringify({
          pid: process.pid,
          host_tool: hostTool,
          command: 'recover-lock',
          started_at: new Date().toISOString()
        }, null, 2) + '\n',
        'utf8'
      );
      fs.fsyncSync(recFd);
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') {
        throw err;
      }
      let recInfo = inspectRecoveringLockFile(recoveringLockPath);
      if (!recInfo.valid && recInfo.stat && Date.now() - recInfo.stat.mtimeMs < HALF_WRITTEN_GRACE_MS) {
        sleepSync(HALF_WRITTEN_GRACE_MS);
        recInfo = inspectRecoveringLockFile(recoveringLockPath);
      }
      if (recInfo.valid && recInfo.payload && isPidAliveFn(Number(recInfo.payload.pid))) {
        const busyErr = new Error('ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS: 另一个 mem recover-lock 进程正在执行恢复');
        busyErr.code = 'ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS';
        throw busyErr;
      }
      if (recAttempt > 0) {
        const busyErr = new Error('ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS: 另一个 mem recover-lock 进程正在执行恢复');
        busyErr.code = 'ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS';
        throw busyErr;
      }
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const pidTag = recInfo.payload?.pid ? `pid${recInfo.payload.pid}` : 'corrupt';
      const archivedRecPath = path.join(staleLocksDir, `write.recovering.lock.${stamp}-${pidTag}-${process.pid}.json`);
      try {
        fs.renameSync(recoveringLockPath, archivedRecPath);
      } catch {
        const busyErr = new Error('ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS: 另一个 mem recover-lock 进程正在执行恢复');
        busyErr.code = 'ERR_WRITE_LOCK_RECOVERY_IN_PROGRESS';
        throw busyErr;
      }
    } finally {
      if (recFd !== undefined) {
        try { fs.closeSync(recFd); } catch {}
        recFd = undefined;
      }
    }
  }

  let normalLockHandle = null;
  let archivedLockPath = null;
  let staleInfo = null;
  let archivedPublisherLockPath = null;
  let stalePublisherLockInfo = null;

  try {
    // 2. 检查现有 write.lock 与遗留孤儿 publisher.lock 状态
    if (fs.existsSync(legacyPublisherLockPath)) {
      const pubInfo = inspectPublisherLockFile(legacyPublisherLockPath);
      if (pubInfo.valid && pubInfo.payload && isPidAliveFn(Number(pubInfo.payload.pid))) {
        const aliveErr = new Error(
          `ERR_WRITE_LOCK_ACTIVE_CANNOT_RECOVER: 当前遗留 publisher.lock 持有进程 (PID=${pubInfo.payload.pid}) 仍在存活运行，严禁强制接管！`
        );
        aliveErr.code = 'ERR_WRITE_LOCK_ACTIVE_CANNOT_RECOVER';
        throw aliveErr;
      }

      stalePublisherLockInfo = pubInfo.payload || { malformed: true, raw_preview: (pubInfo.raw || '').slice(0, 120) };
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const oldPubPidTag = pubInfo.payload?.pid ? `pid${pubInfo.payload.pid}` : 'corrupt';
      archivedPublisherLockPath = path.join(staleLocksDir, `publisher.lock.${stamp}-${oldPubPidTag}.json`);
      fs.renameSync(legacyPublisherLockPath, archivedPublisherLockPath);
    }

    if (fs.existsSync(lockPath)) {
      const info = inspectWriteLockFile(lockPath);
      if (info.valid && info.payload && isPidAliveFn(Number(info.payload.pid))) {
        const aliveErr = new Error(
          `ERR_WRITE_LOCK_ACTIVE_CANNOT_RECOVER: 当前 write.lock 持有进程 (PID=${info.payload.pid}, command=${info.payload.command}) 仍在存活运行，严禁强制接管！`
        );
        aliveErr.code = 'ERR_WRITE_LOCK_ACTIVE_CANNOT_RECOVER';
        throw aliveErr;
      }

      staleInfo = info.payload || { malformed: true, raw_preview: (info.raw || '').slice(0, 120) };
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const oldPidTag = info.payload?.pid ? `pid${info.payload.pid}` : 'corrupt';
      archivedLockPath = path.join(staleLocksDir, `write.lock.${stamp}-${oldPidTag}.json`);
      fs.renameSync(lockPath, archivedLockPath);
    }

    // 3. 【第 6 轮审核修复 1】立即获取正常 runtime/write.lock（此时 write.recovering.lock 仍持有，普通进程绝无可能抢锁）
    normalLockHandle = acquireWriteLock({
      dataPath,
      command: 'recover-lock',
      hostTool,
      timeoutMs: 5000,
      isPidAliveFn
    });
  } finally {
    // 4. 释放过渡锁 write.recovering.lock（此时恢复进程已稳固持有正常 write.lock）
    if (fs.existsSync(recoveringLockPath)) {
      try { fs.unlinkSync(recoveringLockPath); } catch {}
    }
  }

  // 5. 在正常 write.lock 保护下推进 R1 台账恢复、文件恢复与 Git 补提交
  try {
    if (duringRecoveryHook) {
      duringRecoveryHook({
        activeWriteLockPath: normalLockHandle.lockPath,
        activeLockToken: normalLockHandle.lockToken
      });
    }

    let r1Recovery = { recovered: false, count: 0, details: [] };
    const retriedGitCommits = [];
    const dbPath = path.join(runtimeDir, 'state.sqlite');

    if (fs.existsSync(dbPath)) {
      const db = openExistingDatabase(dbPath);
      try {
        r1Recovery = recoverInterruptedPublish({
          db,
          revisionsDir: path.join(dataPath, 'runtime', 'revisions')
        });

        // 检查 auxiliary_states 中未完成结算的已发布作业并对照预期版本安全结算
        if (vaultPath && fs.existsSync(path.join(vaultPath, '.git'))) {
          const pendingGitRows = db.prepare(`
            SELECT p.operation_id, p.output_uuid, p.target_path, p.content_sha256
            FROM publish_intents p
            LEFT JOIN auxiliary_states a ON p.operation_id = a.operation_id
            WHERE p.state = 'files_published'
              AND (a.git_state IS NULL OR a.git_state NOT IN ('committed', 'needs_review'))
          `).all();

          for (const row of pendingGitRows) {
            if (row.target_path) {
              let gitState = 'failed';
              let reason = null;
              try {
                const gitRes = settlePublishedGitCommit({
                  vaultDir: vaultPath,
                  filePath: row.target_path,
                  expectedSha256: row.content_sha256,
                  commitMessage: `feat(memory): recover commit ${row.output_uuid}`
                });
                gitState = gitRes.gitState;
                reason = gitRes.reason || null;
              } catch (gitErr) {
                gitState = 'failed';
                reason = String(gitErr?.message || gitErr);
              }
              recordOperationSettlement({
                db,
                operationId: row.operation_id,
                gitState,
                indexState: 'stale'
              });
              retriedGitCommits.push({
                operationId: row.operation_id,
                outputUuid: row.output_uuid,
                gitState,
                reason
              });
            }
          }
        }
      } finally {
        db.close();
      }
    }

    return {
      recovered: true,
      hadStaleLock: Boolean(archivedLockPath || archivedPublisherLockPath),
      archivedLockPath,
      staleLockInfo: staleInfo,
      archivedPublisherLockPath,
      stalePublisherLockInfo,
      acquiredNormalWriteLockToken: normalLockHandle.lockToken,
      r1Recovery,
      retriedGitCommits
    };
  } finally {
    if (normalLockHandle) {
      normalLockHandle.release();
    }
  }
}
