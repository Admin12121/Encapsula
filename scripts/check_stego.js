#!/usr/bin/env node
// Encapsula/scripts/check_stego.js
//
// Diagnostic script to inspect an encoded file for:
//  - appended payload using the marker <<ENCAPSULA_HIDDEN>>
//  - LSB-embedded payload (PNG/JPEG/BMP)
//  - DCT-embedded payload (JPEG)
//
// Usage:
//   node Encapsula/scripts/check_stego.js <encoded-file>
//
// Optional deps for full checks:
//   npm install pngjs jpeg-js
//
// The script is intentionally non-destructive and only reads the file.

const fs = require("fs");
const path = require("path");

function exitWith(msg, code = 1) {
  console.error(msg);
  process.exit(code);
}

if (process.argv.length < 3) {
  exitWith("Usage: node scripts/check_stego.js <encoded-file>");
}

const filePath = process.argv[2];
if (!fs.existsSync(filePath)) exitWith("File not found: " + filePath);

let buf;
try {
  buf = fs.readFileSync(filePath);
} catch (e) {
  exitWith("Failed to read file: " + e.message);
}

console.log("File:", filePath);
console.log("Size bytes:", buf.length);

const MARKER = Buffer.from("<<ENCAPSULA_HIDDEN>>", "utf8");

// 1) Generic append check (search from end to prefer appended sentinel)
const markerIndex = buf.lastIndexOf(MARKER);
console.log("\n[APPEND CHECK]");
if (markerIndex >= 0) {
  console.log("Append marker lastIndex:", markerIndex);
  const lenStart = markerIndex + MARKER.length;
  if (lenStart + 4 <= buf.length) {
    try {
      const declaredLen = buf.readUInt32BE(lenStart);
      const dataStart = lenStart + 4;
      const dataAvailable = Math.max(0, Math.min(declaredLen, buf.length - dataStart));
      console.log("Declared payload length (from append):", declaredLen);
      console.log("Payload bytes available after marker:", dataAvailable);
      if (dataAvailable > 0) {
        const sample = buf.slice(dataStart, dataStart + Math.min(16, dataAvailable));
        console.log("First payload bytes (hex):", sample.toString("hex"));
      }
    } catch (e) {
      console.log("Could not read declared length from appended marker:", e.message);
    }
  } else {
    console.log("Marker found but insufficient bytes to read length header.");
  }
} else {
  console.log("No append marker found.");
}

// Helpers to convert bit arrays -> Buffer
function bitsToBuffer(bits) {
  const bytelen = Math.floor(bits.length / 8);
  const out = Buffer.alloc(bytelen);
  for (let i = 0; i < bytelen; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | (bits[i * 8 + b] & 1);
    out[i] = v;
  }
  return out;
}

// 2) Try LSB extraction (PNG/JPEG/BMP). Requires pngjs and jpeg-js if you want full checks.
console.log("\n[LSB CHECK] (requires 'pngjs' and/or 'jpeg-js' to be installed)");
function tryLSB(buffer) {
  // PNG path
  try {
    const PNG = require("pngjs").PNG;
    const png = PNG.sync.read(buffer);
    const data = png.data; // RGBA
    const totalPixels = png.width * png.height;
    const capacityBits = totalPixels * 3;
    const readBits = (neededBits) => {
      const bits = [];
      let bitIdx = 0;
      for (let i = 0; i < data.length && bitIdx < neededBits; i += 4) {
        if (bitIdx < neededBits) (bits.push(data[i] & 1), bitIdx++);
        if (bitIdx < neededBits) (bits.push(data[i + 1] & 1), bitIdx++);
        if (bitIdx < neededBits) (bits.push(data[i + 2] & 1), bitIdx++);
      }
      return bits;
    };

    const lenBits = readBits(32);
    if (lenBits.length < 32) return null;
    let payloadLen = 0;
    for (let i = 0; i < 32; i++) payloadLen = (payloadLen << 1) | (lenBits[i] & 1);
    if (payloadLen <= 0 || payloadLen > Math.floor((capacityBits - 32) / 8)) return null;

    const needBits = 32 + payloadLen * 8;
    const collected = [];
    let bIdx = 0;
    for (let i = 0; i < data.length && bIdx < needBits; i += 4) {
      if (bIdx < needBits) (collected.push(data[i] & 1), bIdx++);
      if (bIdx < needBits) (collected.push(data[i + 1] & 1), bIdx++);
      if (bIdx < needBits) (collected.push(data[i + 2] & 1), bIdx++);
    }
    if (collected.length < needBits) return null;
    const payloadBits = collected.slice(32);
    return { method: "LSB (PNG)", payload: bitsToBuffer(payloadBits) };
  } catch (e) {
    // pngjs not present or not a PNG
  }

  // JPEG path (decoded RGBA)
  try {
    const jpeg = require("jpeg-js");
    const raw = jpeg.decode(buffer, { useTArray: true });
    if (!raw || !raw.data) return null;
    const width = raw.width;
    const height = raw.height;
    const data = Buffer.from(raw.data);
    const collected = [];
    for (let px = 0; px < width * height; px++) {
      const base = px * 4;
      collected.push(data[base] & 1);
      collected.push(data[base + 1] & 1);
      collected.push(data[base + 2] & 1);
    }
    if (collected.length < 32) return null;
    let payloadLen = 0;
    for (let i = 0; i < 32; i++) payloadLen = (payloadLen << 1) | (collected[i] & 1);
    if (payloadLen <= 0 || payloadLen > Math.floor((collected.length - 32) / 8)) return null;
    const payloadBits = collected.slice(32, 32 + payloadLen * 8);
    return { method: "LSB (JPEG)", payload: bitsToBuffer(payloadBits) };
  } catch (e) {
    // jpeg-js not present or decode failed
  }

  // BMP fallback (uncompressed BMP, 24 or 32bpp)
  try {
    if (buffer.slice(0, 2).toString("ascii") === "BM") {
      const pixelOffset = buffer.readUInt32LE(10);
      const bpp = buffer.readUInt16LE(28);
      if (bpp !== 24 && bpp !== 32) return null;
      const pixelData = Buffer.from(buffer.slice(pixelOffset));
      const totalPixels = Math.floor(pixelData.length / (bpp / 8));
      const collected = [];
      for (let px = 0; px < totalPixels; px++) {
        const base = px * (bpp / 8);
        // BMP pixel order: B,G,R
        collected.push(pixelData[base + 2] & 1); // R
        collected.push(pixelData[base + 1] & 1); // G
        collected.push(pixelData[base] & 1); // B
      }
      if (collected.length < 32) return null;
      let payloadLen = 0;
      for (let i = 0; i < 32; i++) payloadLen = (payloadLen << 1) | (collected[i] & 1);
      if (payloadLen <= 0 || payloadLen > Math.floor((collected.length - 32) / 8)) return null;
      const payloadBits = collected.slice(32, 32 + payloadLen * 8);
      return { method: "LSB (BMP)", payload: bitsToBuffer(payloadBits) };
    }
  } catch (e) {
    // ignore
  }

  return null;
}

try {
  const lsbResult = tryLSB(buf);
  if (lsbResult) {
    console.log("LSB extraction succeeded:", lsbResult.method);
    console.log("Extracted payload length:", lsbResult.payload.length);
    console.log("First 32 bytes of payload (hex):", lsbResult.payload.slice(0, 32).toString("hex"));
  } else {
    console.log("LSB extraction: no payload found (or required libs not installed).");
  }
} catch (e) {
  console.log("LSB extraction error:", e && e.message ? e.message : e);
}

// 3) Try DCT extraction (JPEG only). Requires jpeg-js.
console.log("\n[DCT CHECK] (requires 'jpeg-js' to be installed)");
function tryDCT(buffer) {
  try {
    const jpeg = require("jpeg-js");
    const raw = jpeg.decode(buffer, { useTArray: true });
    if (!raw || !raw.data) return null;
    const width = raw.width;
    const height = raw.height;
    const rgba = Buffer.from(raw.data);

    // Build Y channel (shifted by -128)
    const Y = Array.from({ length: height }, () => Array(width).fill(0));
    let idx = 0;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const r = rgba[idx++];
        const g = rgba[idx++];
        const b = rgba[idx++];
        idx++; // skip alpha if present
        const yc = 0.299 * r + 0.587 * g + 0.114 * b;
        Y[y][x] = yc - 128;
      }
    }

    const blocksX = Math.floor(width / 8);
    const blocksY = Math.floor(height / 8);
    const bits = [];
    if (blocksX <= 0 || blocksY <= 0) return null;

    function dct8(block) {
      const N = 8;
      const F = Array.from({ length: N }, () => Array(N).fill(0));
      for (let u = 0; u < N; u++) {
        for (let v = 0; v < N; v++) {
          let sum = 0;
          for (let x = 0; x < N; x++) {
            for (let y = 0; y < N; y++) {
              sum +=
                block[x][y] *
                Math.cos(((2 * x + 1) * u * Math.PI) / (2 * N)) *
                Math.cos(((2 * y + 1) * v * Math.PI) / (2 * N));
            }
          }
          const cu = u === 0 ? 1 / Math.sqrt(2) : 1;
          const cv = v === 0 ? 1 / Math.sqrt(2) : 1;
          F[u][v] = 0.25 * cu * cv * sum;
        }
      }
      return F;
    }

    const targetU = 1,
      targetV = 0;
    for (let by = 0; by < blocksY; by++) {
      for (let bx = 0; bx < blocksX; bx++) {
        const block = Array.from({ length: 8 }, () => Array(8).fill(0));
        for (let i = 0; i < 8; i++) {
          for (let j = 0; j < 8; j++) {
            block[i][j] = Y[by * 8 + i][bx * 8 + j];
          }
        }
        const F = dct8(block);
        const q = Math.round(F[targetU][targetV]);
        bits.push(q & 1);
      }
    }

    if (bits.length < 32) return null;
    let payloadLen = 0;
    for (let i = 0; i < 32; i++) payloadLen = (payloadLen << 1) | (bits[i] & 1);
    if (payloadLen <= 0 || payloadLen > Math.floor((bits.length - 32) / 8)) return null;
    const payloadBits = bits.slice(32, 32 + payloadLen * 8);
    return { method: "DCT (JPEG)", payload: bitsToBuffer(payloadBits) };
  } catch (e) {
    // jpeg-js missing or decode error
    return null;
  }
}

try {
  const dctResult = tryDCT(buf);
  if (dctResult) {
    console.log("DCT extraction succeeded:", dctResult.method);
    console.log("Extracted payload length:", dctResult.payload.length);
    console.log("First 32 bytes of payload (hex):", dctResult.payload.slice(0, 32).toString("hex"));
  } else {
    console.log("DCT extraction: no payload found (or jpeg-js not installed / not a JPEG).");
  }
} catch (e) {
  console.log("DCT extraction error:", e && e.message ? e.message : e);
}

console.log("\nDone.");
