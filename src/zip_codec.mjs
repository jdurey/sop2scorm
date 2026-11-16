/**
 * Pure-JS Clean-Room PKWARE ZIP Codec (STORE method 0 + DEFLATE method 8).
 * Zero external dependencies. Supports `--reproducible` byte-identical archive output
 * across Linux, macOS, and Windows (fixed DOS timestamps + lexicographic entry order).
 *
 * Specification reference: PKWARE APPNOTE.TXT (ISO/IEC 21320-1 open profile).
 */

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8");

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : toUint8Array(bytes);
  let crc = 0xffffffff >>> 0;
  for (let i = 0; i < buf.length; i++) {
    crc = (CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function toUint8Array(input) {
  if (input instanceof Uint8Array) {
    return input;
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  return TEXT_ENCODER.encode(String(input ?? ""));
}

export function utf8Decode(bytes, stripBom = false) {
  const text = TEXT_DECODER.decode(bytes);
  if (stripBom && text.charCodeAt(0) === 0xfeff) {
    return text.slice(1);
  }
  return text;
}

export function utf8Encode(text) {
  return TEXT_ENCODER.encode(String(text ?? ""));
}

export function normalizeZipPath(rawPath) {
  const unified = String(rawPath ?? "")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "");
  const parts = unified.split("/");
  const safe = [];
  for (const seg of parts) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      throw new Error(`Unsafe relative path segment rejected in ZIP entry: ${rawPath}`);
    }
    safe.push(seg);
  }
  return safe.join("/");
}

function readU16LE(buf, offset) {
  return buf[offset] | (buf[offset + 1] << 8);
}

function readU32LE(buf, offset) {
  return (
    buf[offset] |
    (buf[offset + 1] << 8) |
    (buf[offset + 2] << 16) |
    (buf[offset + 3] << 24)
  ) >>> 0;
}

function writeU16LE(buf, offset, val) {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
}

function writeU32LE(buf, offset, val) {
  const u = val >>> 0;
  buf[offset] = u & 0xff;
  buf[offset + 1] = (u >>> 8) & 0xff;
  buf[offset + 2] = (u >>> 16) & 0xff;
  buf[offset + 3] = (u >>> 24) & 0xff;
}

async function runByteTransformStream(stream, inputBytes) {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();

  const writeTask = (async () => {
    if (inputBytes.byteLength > 0) {
      const payload =
        inputBytes.byteOffset === 0 && inputBytes.byteLength === inputBytes.buffer.byteLength
          ? inputBytes
          : inputBytes.slice();
      await writer.write(payload);
    }
    await writer.close();
  })();

  const readTask = (async () => {
    const chunks = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        chunks.push(value);
        total += value.byteLength;
      }
    }
    const out = new Uint8Array(total);
    let cursor = 0;
    for (const chunk of chunks) {
      out.set(chunk, cursor);
      cursor += chunk.byteLength;
    }
    return out;
  })();

  const [, output] = await Promise.all([writeTask, readTask]);
  return output;
}

export async function compressDeflateRaw(uncompressedBytes) {
  const input = toUint8Array(uncompressedBytes);
  if (input.byteLength === 0) {
    return new Uint8Array(0);
  }
  const cs = new CompressionStream("deflate-raw");
  return runByteTransformStream(cs, input);
}

export async function decompressDeflateRaw(compressedBytes) {
  const input = toUint8Array(compressedBytes);
  if (input.byteLength === 0) {
    return new Uint8Array(0);
  }
  const ds = new DecompressionStream("deflate-raw");
  return runByteTransformStream(ds, input);
}

function findEndOfCentralDirectory(buf) {
  if (buf.length < 22) {
    throw new Error("Invalid ZIP archive: file is smaller than 22-byte EOCD record.");
  }
  const minOffset = Math.max(0, buf.length - 65557);
  let fallbackCandidate = -1;
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (readU32LE(buf, i) === 0x06054b50) {
      const commentLen = readU16LE(buf, i + 20);
      if (i + 22 + commentLen === buf.length) {
        return i;
      }
      if (fallbackCandidate === -1) {
        fallbackCandidate = i;
      }
    }
  }
  if (fallbackCandidate !== -1) {
    return fallbackCandidate;
  }
  throw new Error("Invalid ZIP archive: End of Central Directory (0x06054b50) not found.");
}

export async function readZip(zipInput, options = {}) {
  const verifyCrc = options.verifyCrc !== false;
  const buf = toUint8Array(zipInput);
  const eocdOffset = findEndOfCentralDirectory(buf);

  const totalEntries = readU16LE(buf, eocdOffset + 10);
  const centralDirSize = readU32LE(buf, eocdOffset + 12);
  const centralDirOffset = readU32LE(buf, eocdOffset + 16);

  if (centralDirOffset === 0xffffffff || totalEntries === 0xffff) {
    throw new Error("ZIP64 extended headers exceed standard 4 GB archive bounds.");
  }
  if (centralDirOffset + centralDirSize > buf.length) {
    throw new Error("Invalid ZIP archive: Central Directory extends past end of buffer.");
  }

  const entries = [];
  const map = new Map();
  let cdCursor = centralDirOffset;

  for (let idx = 0; idx < totalEntries && cdCursor + 46 <= buf.length; idx++) {
    const sig = readU32LE(buf, cdCursor);
    if (sig !== 0x02014b50) {
      throw new Error(
        `Invalid Central Directory signature 0x${sig.toString(16)} at offset ${cdCursor}.`
      );
    }

    const flags = readU16LE(buf, cdCursor + 8);
    const method = readU16LE(buf, cdCursor + 10);
    const dosTime = readU16LE(buf, cdCursor + 12);
    const dosDate = readU16LE(buf, cdCursor + 14);
    const expectedCrc = readU32LE(buf, cdCursor + 16);
    const compressedSize = readU32LE(buf, cdCursor + 20);
    const uncompressedSize = readU32LE(buf, cdCursor + 24);
    const nameLen = readU16LE(buf, cdCursor + 28);
    const extraLen = readU16LE(buf, cdCursor + 30);
    const commentLen = readU16LE(buf, cdCursor + 32);
    const localHeaderOffset = readU32LE(buf, cdCursor + 42);

    const rawName = utf8Decode(buf.subarray(cdCursor + 46, cdCursor + 46 + nameLen));
    cdCursor += 46 + nameLen + extraLen + commentLen;

    if (rawName.endsWith("/")) {
      continue;
    }

    const cleanPath = normalizeZipPath(rawName);
    if (!cleanPath) {
      continue;
    }

    if ((flags & 0x0001) !== 0) {
      throw new Error(`Encrypted ZIP entry '${cleanPath}' is not supported.`);
    }

    const localSig = readU32LE(buf, localHeaderOffset);
    if (localSig !== 0x04034b50) {
      throw new Error(`Invalid Local File Header signature for '${cleanPath}'.`);
    }

    const localNameLen = readU16LE(buf, localHeaderOffset + 26);
    const localExtraLen = readU16LE(buf, localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compressedSize;

    const compressedSlice = buf.subarray(dataStart, dataEnd);
    let data;
    if (method === 0) {
      data = compressedSlice.slice();
    } else if (method === 8) {
      data = await decompressDeflateRaw(compressedSlice);
    } else {
      throw new Error(
        `Unsupported ZIP compression method ${method} on '${cleanPath}' (expected 0=STORE or 8=DEFLATE).`
      );
    }

    if (data.byteLength !== uncompressedSize) {
      throw new Error(
        `Uncompressed byte length mismatch on '${cleanPath}': expected ${uncompressedSize}, got ${data.byteLength}.`
      );
    }

    if (verifyCrc) {
      const actualCrc = crc32(data);
      if (actualCrc !== expectedCrc) {
        throw new Error(
          `CRC32 integrity check failed on '${cleanPath}': expected 0x${expectedCrc.toString(16)}, got 0x${actualCrc.toString(16)}.`
        );
      }
    }

    const entry = {
      path: cleanPath,
      method,
      dosTime,
      dosDate,
      crc32: expectedCrc,
      compressedSize,
      uncompressedSize,
      data
    };
    entries.push(entry);
    map.set(cleanPath, entry);
  }

  return {
    entries,
    map,
    has(filePath) {
      return map.has(normalizeZipPath(filePath));
    },
    getEntry(filePath) {
      return map.get(normalizeZipPath(filePath)) || null;
    },
    getBytes(filePath) {
      const found = map.get(normalizeZipPath(filePath));
      return found ? found.data : null;
    },
    getText(filePath, stripBom = true) {
      const found = map.get(normalizeZipPath(filePath));
      return found ? utf8Decode(found.data, stripBom) : null;
    },
    listPaths() {
      return entries.map((e) => e.path);
    }
  };
}

function normalizeCompressionMethod(methodHint, byteLength, fallbackMethod) {
  if (byteLength === 0) return 0;
  if (methodHint === 0 || methodHint === "store" || methodHint === "STORE") return 0;
  if (methodHint === 8 || methodHint === "deflate" || methodHint === "DEFLATE") return 8;
  return fallbackMethod === 0 ? 0 : 8;
}

export async function writeZip(inputEntries, options = {}) {
  const defaultMethod = options.defaultMethod === 0 ? 0 : 8;
  const reproducible = options.reproducible !== false;
  const dosTime = (12 << 11) | (0 << 5) | 0; // 12:00:00
  const dosDate = ((2026 - 1980) << 9) | (1 << 5) | 15; // 2026-01-15

  const deduped = new Map();
  for (const raw of inputEntries) {
    const cleanPath = normalizeZipPath(raw.path || raw.name || "");
    if (!cleanPath) continue;
    deduped.set(cleanPath, raw);
  }

  const orderedEntries = Array.from(deduped.entries());
  if (reproducible) {
    orderedEntries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }

  const prepared = [];
  for (const [cleanPath, raw] of orderedEntries) {
    const nameBytes = utf8Encode(cleanPath);
    const uncompressed = toUint8Array(raw.data);
    const checksum = crc32(uncompressed);
    const requestedMethod = normalizeCompressionMethod(
      raw.method,
      uncompressed.byteLength,
      defaultMethod
    );

    const method = requestedMethod;
    let payload = uncompressed;
    if (method === 8) {
      payload = await compressDeflateRaw(uncompressed);
    }

    prepared.push({
      path: cleanPath,
      nameBytes,
      method,
      crc32: checksum,
      compressedBytes: payload,
      uncompressedLength: uncompressed.byteLength,
      dosTime: reproducible ? dosTime : (typeof raw.dosTime === "number" ? raw.dosTime : dosTime),
      dosDate: reproducible ? dosDate : (typeof raw.dosDate === "number" ? raw.dosDate : dosDate)
    });
  }

  let localSectionBytes = 0;
  let centralSectionBytes = 0;
  for (const item of prepared) {
    localSectionBytes += 30 + item.nameBytes.byteLength + item.compressedBytes.byteLength;
    centralSectionBytes += 46 + item.nameBytes.byteLength;
  }

  const out = new Uint8Array(localSectionBytes + centralSectionBytes + 22);
  const localOffsets = new Array(prepared.length);
  let cursor = 0;

  for (let i = 0; i < prepared.length; i++) {
    const item = prepared[i];
    localOffsets[i] = cursor;
    const versionNeeded = 20;

    writeU32LE(out, cursor, 0x04034b50);
    writeU16LE(out, cursor + 4, versionNeeded);
    writeU16LE(out, cursor + 6, 0x0800);
    writeU16LE(out, cursor + 8, item.method);
    writeU16LE(out, cursor + 10, item.dosTime);
    writeU16LE(out, cursor + 12, item.dosDate);
    writeU32LE(out, cursor + 14, item.crc32);
    writeU32LE(out, cursor + 18, item.compressedBytes.byteLength);
    writeU32LE(out, cursor + 22, item.uncompressedLength);
    writeU16LE(out, cursor + 26, item.nameBytes.byteLength);
    writeU16LE(out, cursor + 28, 0);

    out.set(item.nameBytes, cursor + 30);
    out.set(item.compressedBytes, cursor + 30 + item.nameBytes.byteLength);
    cursor += 30 + item.nameBytes.byteLength + item.compressedBytes.byteLength;
  }

  const centralStart = cursor;
  for (let i = 0; i < prepared.length; i++) {
    const item = prepared[i];
    writeU32LE(out, cursor, 0x02014b50);
    writeU16LE(out, cursor + 4, 20);
    writeU16LE(out, cursor + 6, 20);
    writeU16LE(out, cursor + 8, 0x0800);
    writeU16LE(out, cursor + 10, item.method);
    writeU16LE(out, cursor + 12, item.dosTime);
    writeU16LE(out, cursor + 14, item.dosDate);
    writeU32LE(out, cursor + 16, item.crc32);
    writeU32LE(out, cursor + 20, item.compressedBytes.byteLength);
    writeU32LE(out, cursor + 24, item.uncompressedLength);
    writeU16LE(out, cursor + 28, item.nameBytes.byteLength);
    writeU16LE(out, cursor + 30, 0);
    writeU16LE(out, cursor + 32, 0);
    writeU16LE(out, cursor + 34, 0);
    writeU16LE(out, cursor + 36, 0);
    writeU32LE(out, cursor + 38, 0);
    writeU32LE(out, cursor + 42, localOffsets[i]);

    out.set(item.nameBytes, cursor + 46);
    cursor += 46 + item.nameBytes.byteLength;
  }

  writeU32LE(out, cursor, 0x06054b50);
  writeU16LE(out, cursor + 4, 0);
  writeU16LE(out, cursor + 6, 0);
  writeU16LE(out, cursor + 8, prepared.length);
  writeU16LE(out, cursor + 10, prepared.length);
  writeU32LE(out, cursor + 12, centralSectionBytes);
  writeU32LE(out, cursor + 16, centralStart);
  writeU16LE(out, cursor + 20, 0);

  return out;
}
