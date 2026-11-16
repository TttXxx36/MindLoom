import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export function checkpointDatabaseBestEffort(db) {
  if (!db) return { attempted: false, ok: false };
  try {
    const row = db.prepare('PRAGMA wal_checkpoint(PASSIVE)').get();
    return { attempted: true, ok: true, row: row || null };
  } catch (err) {
    return { attempted: true, ok: false, error: err?.message || String(err) };
  }
}

/**
 * 初始化或打开 state.sqlite 数据库
 * @param {string} dbPath
 * @returns {DatabaseSync}
 */
export function openDatabase(dbPath) {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new DatabaseSync(dbPath);

  try {
    // Set busy_timeout before switching journal_mode so concurrent openers never trip on transient WAL locks
    db.exec('PRAGMA busy_timeout = 5000;');
    // 启用 WAL 模式以提升并发性能与稳定性
    db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS publish_intents (
      operation_id TEXT PRIMARY KEY,
      output_uuid TEXT NOT NULL,
      staging_path TEXT NOT NULL,
      target_path TEXT NOT NULL,
      content_sha256 TEXT NOT NULL,
      state TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      note_type TEXT NOT NULL,
      title TEXT NOT NULL,
      project TEXT NOT NULL,
      privacy TEXT NOT NULL,
      path TEXT NOT NULL,
      content_sha256 TEXT NOT NULL,
      lifecycle TEXT,
      evidence_level TEXT,
      review_state TEXT,
      as_of TEXT,
      review_after TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS reconcile_states (
      proposal_id TEXT PRIMARY KEY,
      proposal_version_sha256 TEXT NOT NULL,
      target_id TEXT NOT NULL,
      target_version_sha256 TEXT NOT NULL,
      reconcile_state TEXT NOT NULL,
      reason TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tombstones (
      item_key TEXT PRIMARY KEY,
      output_uuid TEXT NOT NULL,
      note_title TEXT,
      reason TEXT,
      deleted_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS snapshot_lineage (
      snapshot_id TEXT PRIMARY KEY,
      source_tool TEXT NOT NULL,
      session_id TEXT NOT NULL,
      previous_snapshot_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS session_snapshots (
      snapshot_id TEXT PRIMARY KEY,
      source_tool TEXT NOT NULL,
      session_id TEXT NOT NULL,
      raw_sha256 TEXT NOT NULL,
      raw_path TEXT NOT NULL,
      compressed INTEGER NOT NULL DEFAULT 0,
      event_count INTEGER NOT NULL,
      prefix_hashes_json TEXT NOT NULL,
      parser_version TEXT NOT NULL,
      sanitizer_version TEXT NOT NULL,
      distiller_version TEXT,
      status TEXT NOT NULL DEFAULT 'ingested',
      reason TEXT,
      anomalies_json TEXT,
      readable_session_path TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS distillation_runs (
      run_id TEXT PRIMARY KEY,
      snapshot_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      parser_version TEXT NOT NULL,
      sanitizer_version TEXT NOT NULL,
      distiller_version TEXT NOT NULL,
      processed_through_event INTEGER NOT NULL,
      mode TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS egress_approvals (
      egress_approval_id TEXT PRIMARY KEY,
      snapshot_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      purpose TEXT NOT NULL,
      approved_by TEXT NOT NULL,
      approval_token_sha256 TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS trusted_human_confirmations (
      confirmation_id TEXT PRIMARY KEY,
      proposal_id TEXT NOT NULL,
      proposal_version_sha256 TEXT NOT NULL,
      target_id TEXT NOT NULL,
      target_version_sha256 TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS backups (
      backup_id TEXT PRIMARY KEY,
      target_dir TEXT NOT NULL,
      status TEXT NOT NULL,
      file_count INTEGER NOT NULL,
      changed_files_json TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auxiliary_states (
      operation_id TEXT PRIMARY KEY,
      git_state TEXT NOT NULL DEFAULT 'pending',
      index_state TEXT NOT NULL DEFAULT 'stale',
      updated_at TEXT NOT NULL
    );
  `);
  } catch (err) {
    try { db.close(); } catch {}
    throw err;
  }

  let closed = false;
  const origClose = db.close.bind(db);
  db.close = () => {
    if (closed) return;
    closed = true;
    checkpointDatabaseBestEffort(db);
    return origClose();
  };

  return db;
}

/**
 * 打开必须已存在的 state.sqlite（§2 铁律：缺失时立即阻断，严禁自动初始化为空库）
 * @param {string} dbPath
 * @param {{ readOnly?: boolean, allowImmutableFallback?: boolean }} [options]
 * @returns {DatabaseSync}
 */
export function openExistingDatabase(dbPath, options = {}) {
  if (!dbPath || !fs.existsSync(dbPath)) {
    throw new Error(`核心状态库 state.sqlite 缺失，已阻断操作（请从备份恢复，严禁自动初始化为空库）: ${dbPath}`);
  }
  if (options.readOnly) {
    let roDb = null;
    try {
      roDb = new DatabaseSync(dbPath, { readOnly: true });
      // SQLite WAL 延迟到首次 prepare/query 时才打开 -shm；立即执行只读探针以确保只读沙箱能正确触发 immutable=1 回退
      roDb.prepare('PRAGMA busy_timeout = 5000').get();
      roDb.prepare('SELECT 1 FROM sqlite_master LIMIT 1').get();
      return roDb;
    } catch (err) {
      if (roDb) {
        try { roDb.close(); } catch {}
      }
      const msg = String(err?.message || '');
      if (options.allowImmutableFallback !== false && /unable to open database file|readonly|SQLITE_CANTOPEN/i.test(msg)) {
        const uri = `${pathToFileURL(path.resolve(dbPath)).href}?immutable=1`;
        return new DatabaseSync(uri, { readOnly: true });
      }
      throw err;
    }
  }
  return openDatabase(dbPath);
}

/**
 * 优先以可写模式打开已存在的 state.sqlite；若受沙箱或只读目录限制无法写入，则安全回退为只读模式 (含 immutable=1 回退)
 * @param {string} dbPath
 * @returns {{ db: DatabaseSync, isReadOnly: boolean }}
 */
export function openExistingDatabasePreferWritable(dbPath) {
  if (!dbPath || !fs.existsSync(dbPath)) {
    throw new Error(`核心状态库 state.sqlite 缺失，已阻断操作（请从备份恢复，严禁自动初始化为空库）: ${dbPath}`);
  }
  try {
    return { db: openDatabase(dbPath), isReadOnly: false };
  } catch (err) {
    const msg = String(err?.message || '');
    if (/unable to open database file|readonly|EACCES|EPERM|EROFS|SQLITE_CANTOPEN/i.test(msg)) {
      return { db: openExistingDatabase(dbPath, { readOnly: true }), isReadOnly: true };
    }
    throw err;
  }
}
