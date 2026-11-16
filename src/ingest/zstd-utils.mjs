import fs from 'node:fs';
import zlib from 'node:zlib';

export const ZSTD_FRAME_MAGIC_LE = 0xfd2fb528;
export const ZSTD_SKIPPABLE_MAGIC_MIN = 0x184d2a50;
export const ZSTD_SKIPPABLE_MAGIC_MAX = 0x184d2a5f;

/**
 * 判断缓冲或文件名是否为 Zstd 压缩格式
 * @param {Buffer} buf
 * @param {string} [filePath]
 * @returns {boolean}
 */
export function isZstdBuffer(buf, filePath = '') {
  const lower = String(filePath || '').toLowerCase();
  if (lower.endsWith('.zst') || lower.endsWith('.zstd')) return true;
  if (!Buffer.isBuffer(buf) || buf.length < 4) return false;
  const magic = buf.readUInt32LE(0);
  return magic === ZSTD_FRAME_MAGIC_LE || (magic >= ZSTD_SKIPPABLE_MAGIC_MIN && magic <= ZSTD_SKIPPABLE_MAGIC_MAX);
}

/**
 * 仅解压第一帧 Zstd 数据并返回是否存在后续串联帧 (供 DSH 快速元数据检查使用)
 * @param {Buffer} buf
 * @returns {{ buffer: Buffer, hasMoreFrames: boolean }}
 */
export function decompressFirstZstdFrame(buf) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) {
    return { buffer: Buffer.alloc(0), hasMoreFrames: false };
  }

  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) {
      throw new Error(`Truncated zstd frame header at byte offset ${offset}`);
    }
    const magic = buf.readUInt32LE(offset);
    if (magic >= ZSTD_SKIPPABLE_MAGIC_MIN && magic <= ZSTD_SKIPPABLE_MAGIC_MAX) {
      if (offset + 8 > buf.length) throw new Error(`Truncated skippable zstd frame at ${offset}`);
      const skipSize = buf.readUInt32LE(offset + 4);
      const next = offset + 8 + skipSize;
      if (next > buf.length) throw new Error(`Truncated skippable zstd payload at ${offset}`);
      offset = next;
      continue;
    }

    if (magic !== ZSTD_FRAME_MAGIC_LE) {
      throw new Error(`Invalid zstd frame magic 0x${magic.toString(16)} at byte offset ${offset}`);
    }
    if (offset + 5 > buf.length) {
      throw new Error(`Truncated zstd frame header descriptor at byte offset ${offset}`);
    }

    const fhd = buf[offset + 4];
    const fcsFlag = (fhd >> 6) & 0x03;
    const singleSegment = (fhd >> 5) & 0x01;
    const checksumFlag = (fhd >> 2) & 0x01;
    const dictIdFlag = fhd & 0x03;
    const winBytes = singleSegment ? 0 : 1;
    const dictBytes = [0, 1, 2, 4][dictIdFlag];
    const fcsBytes = fcsFlag === 0 ? (singleSegment ? 1 : 0) : [0, 2, 4, 8][fcsFlag];

    let pos = offset + 5 + winBytes + dictBytes + fcsBytes;
    if (pos > buf.length) throw new Error(`Truncated zstd frame header fields at byte offset ${offset}`);

    let lastBlock = 0;
    while (!lastBlock) {
      if (pos + 3 > buf.length) throw new Error(`Truncated zstd block header at byte offset ${pos}`);
      const bh = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16);
      pos += 3;
      lastBlock = bh & 0x01;
      const blockType = (bh >> 1) & 0x03;
      const blockSize = bh >> 3;
      if (blockType === 3) throw new Error(`Corrupt zstd block at byte offset ${pos - 3}`);
      const payloadBytes = blockType === 1 ? 1 : blockSize;
      if (pos + payloadBytes > buf.length) throw new Error(`Truncated zstd block payload at byte offset ${pos}`);
      pos += payloadBytes;
    }
    if (checksumFlag) {
      if (pos + 4 > buf.length) throw new Error(`Truncated zstd content checksum at byte offset ${pos}`);
      pos += 4;
    }

    const frameSlice = buf.subarray(offset, pos);
    return {
      buffer: zlib.zstdDecompressSync(frameSlice),
      hasMoreFrames: pos < buf.length
    };
  }

  return { buffer: Buffer.alloc(0), hasMoreFrames: false };
}

/**
 * 按 RFC 8878 完整解压单帧或多帧串联 (concatenated frames) Zstd 数据。
 * Node.js 内置 zlib.zstdDecompressSync 在遇到串联多帧（如 DSH session.v4.jsonl.zstd）时
 * 仅解码第 1 帧即停止；本实现按帧头与块头精确切分并逐帧解压拼接，同时保留对截断/损坏帧的严格报错。
 *
 * @param {Buffer} buf
 * @returns {Buffer}
 */
export function decompressZstdAllFrames(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new TypeError('decompressZstdAllFrames expects a Buffer');
  }
  if (buf.length === 0) {
    return Buffer.alloc(0);
  }

  const outChunks = [];
  let offset = 0;

  while (offset < buf.length) {
    if (offset + 4 > buf.length) {
      throw new Error(`Truncated zstd frame header at byte offset ${offset}`);
    }
    const magic = buf.readUInt32LE(offset);

    // Skippable frame: 0x184D2A50 .. 0x184D2A5F + 4-byte LE size
    if (magic >= ZSTD_SKIPPABLE_MAGIC_MIN && magic <= ZSTD_SKIPPABLE_MAGIC_MAX) {
      if (offset + 8 > buf.length) {
        throw new Error(`Truncated skippable zstd frame header at byte offset ${offset}`);
      }
      const skipSize = buf.readUInt32LE(offset + 4);
      const nextOffset = offset + 8 + skipSize;
      if (nextOffset > buf.length) {
        throw new Error(`Truncated skippable zstd frame payload at byte offset ${offset}`);
      }
      offset = nextOffset;
      continue;
    }

    if (magic !== ZSTD_FRAME_MAGIC_LE) {
      throw new Error(`Invalid zstd frame magic 0x${magic.toString(16)} at byte offset ${offset}`);
    }
    if (offset + 5 > buf.length) {
      throw new Error(`Truncated zstd frame header descriptor at byte offset ${offset}`);
    }

    const fhd = buf[offset + 4];
    const fcsFlag = (fhd >> 6) & 0x03;
    const singleSegment = (fhd >> 5) & 0x01;
    const checksumFlag = (fhd >> 2) & 0x01;
    const dictIdFlag = fhd & 0x03;

    const winBytes = singleSegment ? 0 : 1;
    const dictBytes = [0, 1, 2, 4][dictIdFlag];
    const fcsBytes = fcsFlag === 0 ? (singleSegment ? 1 : 0) : [0, 2, 4, 8][fcsFlag];

    let pos = offset + 5 + winBytes + dictBytes + fcsBytes;
    if (pos > buf.length) {
      throw new Error(`Truncated zstd frame header fields at byte offset ${offset}`);
    }

    let lastBlock = 0;
    while (!lastBlock) {
      if (pos + 3 > buf.length) {
        throw new Error(`Truncated zstd block header at byte offset ${pos}`);
      }
      const bh = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16);
      pos += 3;
      lastBlock = bh & 0x01;
      const blockType = (bh >> 1) & 0x03;
      const blockSize = bh >> 3;
      if (blockType === 3) {
        throw new Error(`Corrupt zstd block (reserved block type 3) at byte offset ${pos - 3}`);
      }
      const payloadBytes = blockType === 1 ? 1 : blockSize;
      if (pos + payloadBytes > buf.length) {
        throw new Error(`Truncated zstd block payload at byte offset ${pos}`);
      }
      pos += payloadBytes;
    }

    if (checksumFlag) {
      if (pos + 4 > buf.length) {
        throw new Error(`Truncated zstd content checksum at byte offset ${pos}`);
      }
      pos += 4;
    }

    const frameSlice = buf.subarray(offset, pos);
    outChunks.push(zlib.zstdDecompressSync(frameSlice));
    offset = pos;
  }

  return Buffer.concat(outChunks);
}

const ZSTD_STREAM_INITIAL_CHUNK_BYTES = 8192;
const ZSTD_STREAM_CHUNK_BYTES = 32768;
const ZSTD_STREAM_OUT_BYTES = 32768;
const MAX_ZSTD_PREFIX_DECOMPRESSED_BYTES = 32 * 1024 * 1024;
const EMPTY_BUFFER = Buffer.alloc(0);
const SHARED_ZSTD_IN_BUF = Buffer.allocUnsafe(ZSTD_STREAM_CHUNK_BYTES);
const SHARED_ZSTD_OUT_BUF = Buffer.allocUnsafe(ZSTD_STREAM_OUT_BYTES);
let sharedZstdBuffersInUse = false;

function verifyZstdFrameStructureSync(fd, size) {
  const readAt = (pos, len) => {
    const buf = Buffer.allocUnsafe(len);
    let readTotal = 0;
    while (readTotal < len) {
      const n = fs.readSync(fd, buf, readTotal, len - readTotal, pos + readTotal);
      if (n <= 0) break;
      readTotal += n;
    }
    if (readTotal < len) {
      throw new Error(`Unexpected EOF reading ${len} bytes at offset ${pos}`);
    }
    return buf;
  };

  let offset = 0;
  let lastDataFrameStart = -1;
  let lastDataFrameEnd = -1;
  while (offset < size) {
    if (offset + 4 > size) {
      throw new Error(`Truncated zstd frame header at byte offset ${offset}`);
    }
    const magic = readAt(offset, 4).readUInt32LE(0);

    if (magic >= ZSTD_SKIPPABLE_MAGIC_MIN && magic <= ZSTD_SKIPPABLE_MAGIC_MAX) {
      if (offset + 8 > size) {
        throw new Error(`Truncated skippable zstd frame header at byte offset ${offset}`);
      }
      const skipSize = readAt(offset + 4, 4).readUInt32LE(0);
      const nextOffset = offset + 8 + skipSize;
      if (nextOffset > size) {
        throw new Error(`Truncated skippable zstd frame payload at byte offset ${offset}`);
      }
      offset = nextOffset;
      continue;
    }

    if (magic !== ZSTD_FRAME_MAGIC_LE) {
      throw new Error(`Invalid zstd frame magic 0x${magic.toString(16)} at byte offset ${offset}`);
    }
    if (offset + 5 > size) {
      throw new Error(`Truncated zstd frame header descriptor at byte offset ${offset}`);
    }

    const fhd = readAt(offset + 4, 1)[0];
    const fcsFlag = (fhd >> 6) & 0x03;
    const singleSegment = (fhd >> 5) & 0x01;
    const checksumFlag = (fhd >> 2) & 0x01;
    const dictIdFlag = fhd & 0x03;

    const winBytes = singleSegment ? 0 : 1;
    const dictBytes = [0, 1, 2, 4][dictIdFlag];
    const fcsBytes = fcsFlag === 0 ? (singleSegment ? 1 : 0) : [0, 2, 4, 8][fcsFlag];

    let pos = offset + 5 + winBytes + dictBytes + fcsBytes;
    if (pos > size) {
      throw new Error(`Truncated zstd frame header fields at byte offset ${offset}`);
    }

    let lastBlock = 0;
    while (!lastBlock) {
      if (pos + 3 > size) {
        throw new Error(`Truncated zstd block header at byte offset ${pos}`);
      }
      const bhBuf = readAt(pos, 3);
      const bh = bhBuf[0] | (bhBuf[1] << 8) | (bhBuf[2] << 16);
      pos += 3;
      lastBlock = bh & 0x01;
      const blockType = (bh >> 1) & 0x03;
      const blockSize = bh >> 3;
      if (blockType === 3) {
        throw new Error(`Corrupt zstd block (reserved block type 3) at byte offset ${pos - 3}`);
      }
      const payloadBytes = blockType === 1 ? 1 : blockSize;
      if (pos + payloadBytes > size) {
        throw new Error(`Truncated zstd block payload at byte offset ${pos}`);
      }
      pos += payloadBytes;
    }

    if (checksumFlag) {
      if (pos + 4 > size) {
        throw new Error(`Truncated zstd content checksum at byte offset ${pos}`);
      }
      pos += 4;
    }

    lastDataFrameStart = offset;
    lastDataFrameEnd = pos;
    offset = pos;
  }

  if (lastDataFrameStart >= 0 && lastDataFrameEnd - lastDataFrameStart <= 2 * 1024 * 1024) {
    zlib.zstdDecompressSync(readAt(lastDataFrameStart, lastDataFrameEnd - lastDataFrameStart));
  }
}

function readZstdPrefixLinesByFramesFallback(fd, size, maxLines) {
  const readAt = (pos, len) => {
    const buf = Buffer.allocUnsafe(len);
    let readTotal = 0;
    while (readTotal < len) {
      const n = fs.readSync(fd, buf, readTotal, len - readTotal, pos + readTotal);
      if (n <= 0) break;
      readTotal += n;
    }
    if (readTotal < len) {
      throw new Error(`Unexpected EOF reading ${len} bytes at offset ${pos}`);
    }
    return buf;
  };

  const lines = [];
  let offset = 0;
  while (offset < size && lines.length < maxLines) {
    if (offset + 4 > size) {
      throw new Error(`Truncated zstd frame header at byte offset ${offset}`);
    }
    const magic = readAt(offset, 4).readUInt32LE(0);

    if (magic >= ZSTD_SKIPPABLE_MAGIC_MIN && magic <= ZSTD_SKIPPABLE_MAGIC_MAX) {
      if (offset + 8 > size) {
        throw new Error(`Truncated skippable zstd frame header at byte offset ${offset}`);
      }
      const skipSize = readAt(offset + 4, 4).readUInt32LE(0);
      const nextOffset = offset + 8 + skipSize;
      if (nextOffset > size) {
        throw new Error(`Truncated skippable zstd frame payload at byte offset ${offset}`);
      }
      offset = nextOffset;
      continue;
    }

    if (magic !== ZSTD_FRAME_MAGIC_LE) {
      throw new Error(`Invalid zstd frame magic 0x${magic.toString(16)} at byte offset ${offset}`);
    }
    if (offset + 5 > size) {
      throw new Error(`Truncated zstd frame header descriptor at byte offset ${offset}`);
    }

    const fhd = readAt(offset + 4, 1)[0];
    const fcsFlag = (fhd >> 6) & 0x03;
    const singleSegment = (fhd >> 5) & 0x01;
    const checksumFlag = (fhd >> 2) & 0x01;
    const dictIdFlag = fhd & 0x03;

    const winBytes = singleSegment ? 0 : 1;
    const dictBytes = [0, 1, 2, 4][dictIdFlag];
    const fcsBytes = fcsFlag === 0 ? (singleSegment ? 1 : 0) : [0, 2, 4, 8][fcsFlag];

    let pos = offset + 5 + winBytes + dictBytes + fcsBytes;
    if (pos > size) {
      throw new Error(`Truncated zstd frame header fields at byte offset ${offset}`);
    }

    let lastBlock = 0;
    while (!lastBlock) {
      if (pos + 3 > size) {
        throw new Error(`Truncated zstd block header at byte offset ${pos}`);
      }
      const bhBuf = readAt(pos, 3);
      const bh = bhBuf[0] | (bhBuf[1] << 8) | (bhBuf[2] << 16);
      pos += 3;
      lastBlock = bh & 0x01;
      const blockType = (bh >> 1) & 0x03;
      const blockSize = bh >> 3;
      if (blockType === 3) {
        throw new Error(`Corrupt zstd block (reserved block type 3) at byte offset ${pos - 3}`);
      }
      const payloadBytes = blockType === 1 ? 1 : blockSize;
      if (pos + payloadBytes > size) {
        throw new Error(`Truncated zstd block payload at byte offset ${pos}`);
      }
      pos += payloadBytes;
    }

    if (checksumFlag) {
      if (pos + 4 > size) {
        throw new Error(`Truncated zstd content checksum at byte offset ${pos}`);
      }
      pos += 4;
    }

    const frameSlice = readAt(offset, pos - offset);
    const decompressed = zlib.zstdDecompressSync(frameSlice);
    const text = decompressed.toString('utf8').replace(/^\uFEFF/, '');
    let hasMoreInFrame = false;
    for (const line of text.split(/\r?\n/)) {
      if (line.trim() !== '') {
        if (lines.length >= maxLines) {
          hasMoreInFrame = true;
          break;
        }
        lines.push(line);
      }
    }
    offset = pos;
    if (lines.length >= maxLines) {
      return {
        lines: lines.slice(0, maxLines),
        hasMoreFrames: offset < size || hasMoreInFrame
      };
    }
  }

  return {
    lines: lines.slice(0, maxLines),
    hasMoreFrames: offset < size
  };
}

/**
 * 基于文件描述符的增量有界流式 Zstd 前缀行读取：
 * 仅按 32KB 分块读取与流式解压，一旦获得 maxLines 条非空 JSONL 行立即停止，
 * 避免对单帧数 MB~数十 MB 的 .jsonl.zst / .jsonl.zstd 全量读取、全帧解压及巨型字符串切分。
 *
 * @param {string} filePath
 * @param {number} [maxLines]
 * @param {fs.Stats | null} [existingStat]
 * @returns {{ lines: string[], hasMoreFrames: boolean }}
 */
export function readZstdPrefixLinesFromFile(filePath, maxLines = 4, existingStat = null) {
  const st = existingStat || fs.statSync(filePath);
  const size = st.size;
  if (size === 0) {
    return { lines: [], hasMoreFrames: false };
  }
  if (maxLines <= 0) {
    return { lines: [], hasMoreFrames: true };
  }

  const fd = fs.openSync(filePath, 'r');
  try {
    const canStreamSync =
      typeof zlib.createZstdDecompress === 'function' &&
      zlib.constants &&
      typeof zlib.constants.ZSTD_e_continue === 'number' &&
      typeof zlib.constants.ZSTD_e_end === 'number';

    if (!canStreamSync) {
      return readZstdPrefixLinesByFramesFallback(fd, size, maxLines);
    }

    const d = zlib.createZstdDecompress();
    if (!d?._handle || typeof d._handle.writeSync !== 'function' || !d._writeState) {
      try { d.close(); } catch {}
      return readZstdPrefixLinesByFramesFallback(fd, size, maxLines);
    }
    d.on('error', () => {});

    let streamErr = null;
    d._handle.onerror = (message, errno, code) => {
      streamErr = new Error(message || code || `ZSTD_ERROR_${errno}`);
      streamErr.errno = errno;
      streamErr.code = code;
    };

    const useSharedBuffers = !sharedZstdBuffersInUse;
    if (useSharedBuffers) sharedZstdBuffersInUse = true;
    const inBuf = useSharedBuffers ? SHARED_ZSTD_IN_BUF : Buffer.allocUnsafe(ZSTD_STREAM_CHUNK_BYTES);
    const outBuf = useSharedBuffers ? SHARED_ZSTD_OUT_BUF : Buffer.allocUnsafe(ZSTD_STREAM_OUT_BYTES);
    const lines = [];
    let carry = EMPTY_BUFFER;
    let isFirstOutputByte = true;
    let decompressedTotal = 0;
    let fileOffset = 0;
    let rem = 0;
    let inOff = 0;
    let stoppedEarly = false;
    let hitScanCap = false;
    let hasTrailingNonWs = false;
    let lastNeedDrain = false;

    const pushDecompressedSlice = (piece) => {
      decompressedTotal += piece.length;
      const combined = carry.length > 0 ? Buffer.concat([carry, piece]) : piece;
      let start = 0;
      while (start < combined.length) {
        const nl = combined.indexOf(0x0a, start);
        if (nl === -1) break;
        let lineBuf = combined.subarray(start, nl);
        if (isFirstOutputByte) {
          isFirstOutputByte = false;
          if (lineBuf.length >= 3 && lineBuf[0] === 0xef && lineBuf[1] === 0xbb && lineBuf[2] === 0xbf) {
            lineBuf = lineBuf.subarray(3);
          }
        }
        let lineStr = lineBuf.toString('utf8');
        if (lineStr.endsWith('\r')) lineStr = lineStr.slice(0, -1);
        if (lineStr.trim() !== '') {
          lines.push(lineStr);
          if (lines.length >= maxLines) {
            for (let i = nl + 1; i < combined.length; i++) {
              const b = combined[i];
              if (b !== 0x0a && b !== 0x0d && b !== 0x20 && b !== 0x09) {
                hasTrailingNonWs = true;
                break;
              }
            }
            carry = EMPTY_BUFFER;
            return true;
          }
        }
        start = nl + 1;
      }
      if (isFirstOutputByte && combined.length >= 3) {
        if (combined[0] === 0xef && combined[1] === 0xbb && combined[2] === 0xbf) {
          carry = Buffer.from(combined.subarray(3));
        } else {
          carry = Buffer.from(combined);
        }
        isFirstOutputByte = false;
      } else {
        carry = start < combined.length ? Buffer.from(combined.subarray(start)) : EMPTY_BUFFER;
      }
      return false;
    };

    try {
      while (fileOffset < size && !stoppedEarly && !hitScanCap && !streamErr) {
        const chunkTarget = fileOffset === 0 ? ZSTD_STREAM_INITIAL_CHUNK_BYTES : ZSTD_STREAM_CHUNK_BYTES;
        const toRead = Math.min(chunkTarget, size - fileOffset);
        let readBytes = 0;
        while (readBytes < toRead) {
          const n = fs.readSync(fd, inBuf, readBytes, toRead - readBytes, fileOffset + readBytes);
          if (n <= 0) break;
          readBytes += n;
        }
        if (readBytes <= 0) break;
        fileOffset += readBytes;

        inOff = 0;
        rem = readBytes;
        let needDrain = false;
        while ((rem > 0 || needDrain) && !stoppedEarly && !hitScanCap && !streamErr) {
          d._handle.writeSync(
            zlib.constants.ZSTD_e_continue,
            inBuf,
            inOff,
            rem,
            outBuf,
            0,
            outBuf.length
          );
          if (streamErr) throw streamErr;
          const availOut = d._writeState[0];
          const availIn = d._writeState[1];
          const produced = outBuf.length - availOut;
          const consumed = rem - availIn;
          inOff += consumed;
          rem = availIn;
          needDrain = availOut === 0;
          lastNeedDrain = needDrain;
          if (produced > 0) {
            stoppedEarly = pushDecompressedSlice(outBuf.subarray(0, produced));
            if (!stoppedEarly && decompressedTotal >= MAX_ZSTD_PREFIX_DECOMPRESSED_BYTES) {
              hitScanCap = true;
            }
          }
          if (consumed === 0 && produced === 0) {
            if (rem > 0) {
              throw new Error(`Zstd decompression stalled at byte offset ${fileOffset - rem}`);
            }
            break;
          }
        }
      }

      if (!stoppedEarly && !hitScanCap && !streamErr) {
        while (!stoppedEarly && !hitScanCap && !streamErr) {
          d._handle.writeSync(
            zlib.constants.ZSTD_e_end,
            EMPTY_BUFFER,
            0,
            0,
            outBuf,
            0,
            outBuf.length
          );
          if (streamErr) throw streamErr;
          const availOut = d._writeState[0];
          lastNeedDrain = availOut === 0;
          const produced = outBuf.length - availOut;
          if (produced > 0) {
            stoppedEarly = pushDecompressedSlice(outBuf.subarray(0, produced));
            if (!stoppedEarly && decompressedTotal >= MAX_ZSTD_PREFIX_DECOMPRESSED_BYTES) {
              hitScanCap = true;
            }
          }
          if (availOut > 0) break;
        }
        if (!stoppedEarly && carry.length > 0) {
          let tailBuf = carry;
          if (isFirstOutputByte && tailBuf.length >= 3 && tailBuf[0] === 0xef && tailBuf[1] === 0xbb && tailBuf[2] === 0xbf) {
            tailBuf = tailBuf.subarray(3);
          }
          let tailStr = tailBuf.toString('utf8');
          if (tailStr.endsWith('\r')) tailStr = tailStr.slice(0, -1);
          if (tailStr.trim() !== '') {
            lines.push(tailStr);
          }
        }
      }

      if (!stoppedEarly && !hitScanCap) {
        verifyZstdFrameStructureSync(fd, size);
      }

      return {
        lines: lines.slice(0, maxLines),
        hasMoreFrames: Boolean(
          hitScanCap || (stoppedEarly && (fileOffset < size || rem > 0 || lastNeedDrain || hasTrailingNonWs))
        )
      };
    } finally {
      if (useSharedBuffers) sharedZstdBuffersInUse = false;
      try {
        d.close();
      } catch {
        // ignore close cleanup errors
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}
