import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { parseMarkdownFrontmatter } from '../schema/frontmatter.mjs';
import { findMarkdownFiles, assertPathWithinBoundary } from '../storage/path-sanitizer.mjs';
import { SANITIZER_VERSION } from '../security/sanitizer.mjs';
import { sanitizePayloadForExitA } from '../egress/egress-controller.mjs';

export const CHUNKING_VERSION = 'v3.3-chunk-1';

function createVectorIndexError(code, message, extra = {}) {
  const err = new Error(`[${code}] ${message}`);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

export function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

export function encodeFloat32Vector(vec) {
  if (!Array.isArray(vec) || vec.length === 0) {
    throw createVectorIndexError('ERR_INVALID_VECTOR', 'Vector must be a non-empty number array');
  }
  const f32 = new Float32Array(vec.length);
  for (let i = 0; i < vec.length; i++) {
    const v = vec[i];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw createVectorIndexError('ERR_INVALID_VECTOR', `Non-finite scalar at index ${i}`);
    }
    f32[i] = v;
  }
  return Buffer.from(f32.buffer, f32.byteOffset, f32.byteLength);
}

export function decodeFloat32Vector(blob, expectedDimensions = null) {
  if (!blob || !(blob instanceof Uint8Array || Buffer.isBuffer(blob))) {
    throw createVectorIndexError('ERR_CORRUPT_VECTOR_BLOB', 'Vector BLOB missing or invalid type');
  }
  if (blob.byteLength === 0 || blob.byteLength % 4 !== 0) {
    throw createVectorIndexError(
      'ERR_CORRUPT_VECTOR_BLOB',
      `Invalid Float32 BLOB byteLength: ${blob.byteLength}`
    );
  }
  const copied = Uint8Array.from(blob);
  const f32 = new Float32Array(copied.buffer, copied.byteOffset, copied.byteLength / 4);
  if (expectedDimensions !== null && f32.length !== expectedDimensions) {
    throw createVectorIndexError(
      'ERR_DIMENSION_MISMATCH',
      `Vector dimension ${f32.length} != space dimension ${expectedDimensions}`
    );
  }
  for (let i = 0; i < f32.length; i++) {
    if (!Number.isFinite(f32[i])) {
      throw createVectorIndexError('ERR_CORRUPT_VECTOR_BLOB', `Non-finite float at index ${i}`);
    }
  }
  return f32;
}

export function cosineSimilarity(a, b) {
  if (!a || !b || a.length !== b.length || a.length === 0) {
    return 0;
  }
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    const va = a[i];
    const vb = b[i];
    dot += va * vb;
    normA += va * va;
    normB += vb * vb;
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (!Number.isFinite(denom) || denom === 0) {
    return 0;
  }
  return dot / denom;
}

export function openVectorIndexDatabase(vectorsDbPath, { readOnly = false } = {}) {
  const resolved = path.resolve(vectorsDbPath);
  if (readOnly) {
    if (!fs.existsSync(resolved)) {
      throw createVectorIndexError('ERR_VECTOR_DB_MISSING', `vectors.sqlite missing: ${resolved}`);
    }
    let db;
    try {
      db = new DatabaseSync(resolved, { readOnly: true });
      db.exec('PRAGMA busy_timeout = 5000;');
      db.exec('PRAGMA foreign_keys = ON;');
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all()
        .map((r) => r.name);
      if (!tables.includes('embedding_spaces') || !tables.includes('vector_chunks')) {
        throw createVectorIndexError(
          'ERR_VECTOR_INDEX_CORRUPT',
          'vectors.sqlite missing required STRICT tables'
        );
      }
      return db;
    } catch (err) {
      try { db?.close(); } catch {}
      if (err.code === 'ERR_VECTOR_INDEX_CORRUPT') throw err;
      throw createVectorIndexError(
        'ERR_VECTOR_INDEX_CORRUPT',
        `Failed to open vectors.sqlite: ${err.message}`
      );
    }
  }

  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  let db;
  try {
    db = new DatabaseSync(resolved);
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec('PRAGMA foreign_keys = ON;');
    const jm = db.prepare('PRAGMA journal_mode;').get();
    if (!jm || String(jm.journal_mode).toLowerCase() !== 'wal') {
      db.exec('PRAGMA journal_mode = WAL;');
    }
    db.exec(`
      CREATE TABLE IF NOT EXISTS embedding_spaces (
        space_id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        dimensions INTEGER NOT NULL CHECK(dimensions > 0),
        distance_metric TEXT NOT NULL CHECK(distance_metric IN ('cosine')),
        chunking_version TEXT NOT NULL,
        sanitizer_version TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
        created_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS vector_chunks (
        chunk_id TEXT PRIMARY KEY,
        space_id TEXT NOT NULL REFERENCES embedding_spaces(space_id) ON DELETE CASCADE,
        doc_id TEXT NOT NULL,
        doc_sha256 TEXT NOT NULL,
        chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
        chunk_sha256 TEXT NOT NULL,
        vector_f32 BLOB NOT NULL,
        token_count INTEGER NOT NULL CHECK(token_count >= 0),
        updated_at TEXT NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS idx_vector_chunks_space_doc
        ON vector_chunks (space_id, doc_id);
    `);
    return db;
  } catch (err) {
    try { db?.close(); } catch {}
    throw createVectorIndexError(
      'ERR_VECTOR_INDEX_CORRUPT',
      `Failed to initialize vectors.sqlite: ${err.message}`
    );
  }
}

export function splitSanitizedNoteChunks({ title, body }, maxCharsPerChunk = 1200) {
  const cleanTitle = String(title || '').trim();
  const paragraphs = String(body || '')
    .split(/\r?\n\s*\r?\n+/)
    .map((p) => p.trim())
    .filter(Boolean);

  if (paragraphs.length === 0) {
    return cleanTitle ? [cleanTitle] : [];
  }

  const chunks = [];
  let current = cleanTitle ? `# ${cleanTitle}\n\n` : '';
  for (const para of paragraphs) {
    if (current.length + para.length + 2 > maxCharsPerChunk && current.trim().length > 0) {
      chunks.push(current.trim());
      current = para;
    } else {
      current = current ? `${current}\n\n${para}` : para;
    }
  }
  if (current.trim().length > 0) {
    chunks.push(current.trim());
  }
  return chunks;
}

export function collectRegisteredSanitizedDocuments({ db, vaultDir }) {
  if (!db || !vaultDir || !fs.existsSync(vaultDir)) {
    return [];
  }

  const files = findMarkdownFiles(vaultDir, {
    excludeTemplates: true,
    followSymlinks: false,
    boundaryDir: vaultDir
  });

  const selectNote = db.prepare(
    'SELECT id, title, privacy, status, path FROM notes WHERE id = ? LIMIT 1'
  );

  // Pre-scan all markdown files for duplicate IDs so ambiguous IDs are never indexed
  const idCounts = new Map();
  const parsedCache = new Map();
  for (const filePath of files) {
    let raw;
    try {
      raw = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    const parsed = parseMarkdownFrontmatter(raw);
    parsedCache.set(filePath, { raw, parsed });
    const fmId = parsed.hasFrontmatter ? parsed.frontmatter?.id : null;
    if (fmId && typeof fmId === 'string') {
      idCounts.set(fmId, (idCounts.get(fmId) || 0) + 1);
    }
  }

  const docs = [];
  for (const filePath of files) {
    const cached = parsedCache.get(filePath);
    if (!cached) continue;
    const { raw, parsed } = cached;
    if (!parsed.hasFrontmatter || parsed.frontmatter?.privacy !== 'sanitized') {
      // Strictly exclude local_only and missing/invalid privacy (0 bytes)
      continue;
    }
    const docId = parsed.frontmatter?.id;
    if (!docId || typeof docId !== 'string') {
      continue;
    }
    if ((idCounts.get(docId) || 0) > 1) {
      // Exclude duplicate ID conflict notes from vector index
      continue;
    }
    const noteRow = selectNote.get(docId);
    if (!noteRow || noteRow.status !== 'active' || noteRow.privacy !== 'sanitized') {
      // Strictly exclude unregistered manual notes and non-active / downgraded notes (0 bytes)
      continue;
    }

    const docSha256 = sha256Hex(raw);
    const title = String(parsed.frontmatter?.title || noteRow.title || docId);
    const chunks = splitSanitizedNoteChunks({ title, body: parsed.body });
    if (chunks.length === 0) {
      continue;
    }

    docs.push({
      docId,
      filePath,
      relPath: path.relative(path.resolve(vaultDir), path.resolve(filePath)),
      title,
      docSha256,
      chunks
    });
  }

  return docs;
}

function isDocStillValidAndCurrent({ db, docId, expectedSha256, vaultDir, filePath = null }) {
  const row = db
    .prepare('SELECT id, privacy, status, path FROM notes WHERE id = ? LIMIT 1')
    .get(docId);
  if (!row || row.status !== 'active' || row.privacy !== 'sanitized') {
    return { valid: false, reason: 'note_inactive_or_not_sanitized' };
  }

  const resolvedPath = filePath
    ? path.resolve(filePath)
    : path.resolve(vaultDir, row.path);
  try {
    assertPathWithinBoundary(resolvedPath, vaultDir, { followSymlinks: false });
  } catch {
    return { valid: false, reason: 'path_outside_boundary_or_symlink' };
  }
  if (!fs.existsSync(resolvedPath)) {
    return { valid: false, reason: 'file_missing' };
  }
  let raw;
  try {
    raw = fs.readFileSync(resolvedPath, 'utf8');
  } catch {
    return { valid: false, reason: 'file_unreadable' };
  }
  const parsed = parseMarkdownFrontmatter(raw);
  if (!parsed.hasFrontmatter || parsed.frontmatter?.privacy !== 'sanitized') {
    return { valid: false, reason: 'frontmatter_privacy_downgraded' };
  }
  const currentSha256 = sha256Hex(raw);
  if (currentSha256 !== expectedSha256) {
    return { valid: false, reason: 'doc_sha256_mutated' };
  }
  return { valid: true, currentSha256, resolvedPath, noteRow: row, parsed };
}

export function buildSpaceId({ provider, model, dimensions, chunkingVersion = CHUNKING_VERSION, sanitizerVersion = SANITIZER_VERSION }) {
  return `${provider}::${model}::d${dimensions}::${chunkingVersion}::${sanitizerVersion}`;
}

export async function indexSanitizedVaultVectors({
  stateDb,
  vectorsDbPath,
  vaultDir,
  embedTextsFn,
  provider = 'siliconflow',
  model = 'BAAI/bge-m3',
  maxBatchSize = 32
}) {
  if (typeof embedTextsFn !== 'function') {
    throw createVectorIndexError('ERR_EMBED_FN_REQUIRED', 'embedTextsFn callback is required');
  }

  const candidateDocs = collectRegisteredSanitizedDocuments({ db: stateDb, vaultDir });
  const vdb = openVectorIndexDatabase(vectorsDbPath);

  try {
    // Clean up chunks for docs no longer active/sanitized/current before indexing
    const existingRows = vdb
      .prepare('SELECT DISTINCT doc_id, doc_sha256 FROM vector_chunks')
      .all();
    const deleteDocStmt = vdb.prepare('DELETE FROM vector_chunks WHERE doc_id = ?');
    for (const row of existingRows) {
      const check = isDocStillValidAndCurrent({
        db: stateDb,
        docId: row.doc_id,
        expectedSha256: row.doc_sha256,
        vaultDir
      });
      if (!check.valid) {
        deleteDocStmt.run(row.doc_id);
      }
    }

    if (candidateDocs.length === 0) {
      return {
        indexedDocs: 0,
        indexedChunks: 0,
        skippedHotMutatedDocs: 0,
        spaceId: null
      };
    }

    // Prepare Exit A sanitized chunks strictly in memory
    const chunkJobs = [];
    for (const doc of candidateDocs) {
      const exitARes = sanitizePayloadForExitA({
        db: stateDb,
        requireRegisteredSanitized: true,
        items: doc.chunks.map((chunkText, idx) => ({
          noteId: doc.docId,
          ephemeralId: idx,
          privacy: 'sanitized',
          content: chunkText
        })),
        allowedFields: ['ephemeralId', 'content']
      });
      for (let idx = 0; idx < exitARes.sanitizedItems.length; idx++) {
        const sanitizedText = exitARes.sanitizedItems[idx].content;
        chunkJobs.push({
          docId: doc.docId,
          filePath: doc.filePath,
          docSha256: doc.docSha256,
          chunkIndex: idx,
          chunkSha256: sha256Hex(sanitizedText),
          sanitizedText,
          tokenCount: Math.max(1, Math.ceil(Buffer.byteLength(sanitizedText, 'utf8') / 3))
        });
      }
    }

    if (chunkJobs.length === 0) {
      return {
        indexedDocs: 0,
        indexedChunks: 0,
        skippedHotMutatedDocs: 0,
        spaceId: null
      };
    }

    const batchSize = Number.isSafeInteger(maxBatchSize) && maxBatchSize > 0 ? maxBatchSize : 32;
    const vectors = [];
    let dimensions = 0;
    for (let offset = 0; offset < chunkJobs.length; offset += batchSize) {
      const batch = chunkJobs.slice(offset, offset + batchSize);
      const embedRes = await embedTextsFn(batch.map((j) => j.sanitizedText));
      const batchVecs = embedRes?.vectors;
      const batchDim = embedRes?.dimension || (Array.isArray(batchVecs?.[0]) ? batchVecs[0].length : 0);
      if (!Array.isArray(batchVecs) || batchVecs.length !== batch.length || !batchDim) {
        throw createVectorIndexError(
          'ERR_EMBEDDING_RESULT_MISMATCH',
          'Embedding result count/dimension mismatch'
        );
      }
      if (!dimensions) {
        dimensions = batchDim;
      } else if (batchDim !== dimensions) {
        throw createVectorIndexError(
          'ERR_EMBEDDING_RESULT_MISMATCH',
          `Embedding dimension mismatch across batches: expected ${dimensions}, got ${batchDim}`
        );
      }
      vectors.push(...batchVecs);
    }

    const spaceId = buildSpaceId({ provider, model, dimensions });
    const nowIso = new Date().toISOString();

    vdb.exec('BEGIN IMMEDIATE;');
    let indexedChunks = 0;
    const indexedDocIds = new Set();
    const skippedDocs = new Set();

    try {
      vdb
        .prepare(
          `INSERT INTO embedding_spaces (
            space_id, provider, model, dimensions, distance_metric,
            chunking_version, sanitizer_version, is_active, created_at
          ) VALUES (?, ?, ?, ?, 'cosine', ?, ?, 1, ?)
          ON CONFLICT(space_id) DO UPDATE SET is_active = 1`
        )
        .run(spaceId, provider, model, dimensions, CHUNKING_VERSION, SANITIZER_VERSION, nowIso);

      // Keep active space unique to prevent cross-space vector mixing
      vdb
        .prepare('UPDATE embedding_spaces SET is_active = 0 WHERE space_id != ?')
        .run(spaceId);

      // Pre-check hot mutations right before committing batch
      const checkedDocs = new Map();
      for (const job of chunkJobs) {
        if (!checkedDocs.has(job.docId)) {
          const check = isDocStillValidAndCurrent({
            db: stateDb,
            docId: job.docId,
            expectedSha256: job.docSha256,
            vaultDir,
            filePath: job.filePath
          });
          checkedDocs.set(job.docId, check.valid);
          if (!check.valid) {
            skippedDocs.add(job.docId);
            deleteDocStmt.run(job.docId);
          }
        }
      }

      // Replace previous chunks for docs that are being cleanly refreshed
      for (const [docId, valid] of checkedDocs.entries()) {
        if (valid) {
          deleteDocStmt.run(docId);
        }
      }

      const insertChunk = vdb.prepare(
        `INSERT INTO vector_chunks (
          chunk_id, space_id, doc_id, doc_sha256, chunk_index,
          chunk_sha256, vector_f32, token_count, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );

      for (let i = 0; i < chunkJobs.length; i++) {
        const job = chunkJobs[i];
        if (!checkedDocs.get(job.docId)) {
          continue;
        }
        if (!Array.isArray(vectors[i]) || vectors[i].length !== dimensions) {
          throw createVectorIndexError(
            'ERR_EMBEDDING_RESULT_MISMATCH',
            `Embedding vector dimension mismatch at chunk ${i}: expected ${dimensions}, got ${Array.isArray(vectors[i]) ? vectors[i].length : 'non-array'}`
          );
        }
        const blob = encodeFloat32Vector(vectors[i]);
        const chunkId = `${spaceId}::${job.docId}::${job.chunkIndex}`;
        insertChunk.run(
          chunkId,
          spaceId,
          job.docId,
          job.docSha256,
          job.chunkIndex,
          job.chunkSha256,
          blob,
          job.tokenCount,
          nowIso
        );
        indexedDocIds.add(job.docId);
        indexedChunks += 1;
      }

      vdb.exec('COMMIT;');
    } catch (err) {
      try { vdb.exec('ROLLBACK;'); } catch {}
      throw err;
    }

    return {
      spaceId,
      dimensions,
      indexedDocs: indexedDocIds.size,
      indexedChunks,
      skippedHotMutatedDocs: skippedDocs.size
    };
  } finally {
    vdb.close();
  }
}

export function queryVectorIndex({
  stateDb,
  vectorsDbPath,
  vaultDir,
  queryVector,
  provider = null,
  model = null,
  topK = 10
}) {
  if (!Array.isArray(queryVector) || queryVector.length === 0) {
    throw createVectorIndexError('ERR_INVALID_QUERY_VECTOR', 'queryVector must be non-empty');
  }

  if (!fs.existsSync(path.resolve(vectorsDbPath))) {
    return {
      spaceId: null,
      items: [],
      invalidatedDocs: []
    };
  }

  let vdb;
  try {
    vdb = openVectorIndexDatabase(vectorsDbPath, { readOnly: true });
  } catch (err) {
    throw err;
  }

  let result;
  let invalidDocsToPurge = [];
  try {
    const activeSpace = provider && model
      ? vdb
          .prepare(
            `SELECT * FROM embedding_spaces
             WHERE provider = ? AND model = ? AND dimensions = ? AND is_active = 1
             LIMIT 1`
          )
          .get(provider, model, queryVector.length)
      : vdb
          .prepare(
            `SELECT * FROM embedding_spaces
             WHERE dimensions = ? AND is_active = 1
             LIMIT 1`
          )
          .get(queryVector.length);

    if (!activeSpace) {
      return {
        spaceId: null,
        items: [],
        invalidatedDocs: []
      };
    }

    const rows = vdb
      .prepare(
        `SELECT chunk_id, doc_id, doc_sha256, chunk_index, chunk_sha256, vector_f32
         FROM vector_chunks
         WHERE space_id = ?`
      )
      .all(activeSpace.space_id);

    const queryF32 = new Float32Array(queryVector);
    const bestByDoc = new Map();
    const invalidDocs = new Set();
    const docValidationCache = new Map();

    for (const row of rows) {
      if (!docValidationCache.has(row.doc_id)) {
        const check = isDocStillValidAndCurrent({
          db: stateDb,
          docId: row.doc_id,
          expectedSha256: row.doc_sha256,
          vaultDir
        });
        docValidationCache.set(row.doc_id, check);
        if (!check.valid) {
          invalidDocs.add(row.doc_id);
        }
      }
      const check = docValidationCache.get(row.doc_id);
      if (!check.valid) {
        continue;
      }

      const vecF32 = decodeFloat32Vector(row.vector_f32, activeSpace.dimensions);
      const score = cosineSimilarity(queryF32, vecF32);
      const prev = bestByDoc.get(row.doc_id);
      if (!prev || score > prev.score) {
        bestByDoc.set(row.doc_id, {
          docId: row.doc_id,
          chunkIndex: row.chunk_index,
          score,
          noteRow: check.noteRow,
          resolvedPath: check.resolvedPath,
          parsed: check.parsed
        });
      }
    }

    invalidDocsToPurge = [...invalidDocs];
    const sorted = [...bestByDoc.values()]
      .sort((a, b) => b.score - a.score)
      .slice(0, Math.max(1, topK));

    result = {
      spaceId: activeSpace.space_id,
      invalidatedDocs: invalidDocsToPurge,
      items: sorted
    };
  } finally {
    vdb.close();
  }

  // Purge stale/downgraded docs cleanly from disposable vectors.sqlite after closing readOnly handle
  if (invalidDocsToPurge.length > 0) {
    const rwVdb = openVectorIndexDatabase(vectorsDbPath, { readOnly: false });
    try {
      const delStmt = rwVdb.prepare('DELETE FROM vector_chunks WHERE doc_id = ?');
      for (const docId of invalidDocsToPurge) {
        delStmt.run(docId);
      }
    } finally {
      rwVdb.close();
    }
  }

  return result;
}
