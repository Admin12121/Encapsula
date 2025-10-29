import chalk from "chalk";
import termkit from "terminal-kit";
import * as path from "path";
import fs from "fs/promises";
import fssync from "fs";
import crypto from "crypto";
import { PNG } from "pngjs";
import { pickCarrierFile } from "../ui/filePicker";

const term = termkit.terminal;

type Screen = "upload" | "password" | "processing" | "complete";

interface UploadedFile {
  path: string;
  name: string;
  size?: number;
  ext?: string;
  buffer?: Buffer;
}

interface State {
  screen: Screen;
  uploadedFile: UploadedFile | null;
  inputBuffer: string;
  password: Buffer | null;
  progress: number;
  decodedMessage?: string | null;
  error?: string | null;
  outputPath: string;
  autoOutput: boolean;
  pathEntryMode: boolean;
}

let state: State = {
  screen: "upload",
  uploadedFile: null,
  inputBuffer: "",
  password: null,
  progress: 0,
  decodedMessage: null,
  error: null,
  outputPath: "",
  autoOutput: true,
  pathEntryMode: false,
};

// ===== Shared constants (must match Encode) =====
const MAGIC = Buffer.from("ECAP", "ascii");
const VERSION = 0x01;
const HEADER_SIZE = 60;

const FLAG_ENCRYPTED = 1 << 0;
const FLAG_RANDOMIZED = 1 << 1;

const KDF_SCRYPT = 1;
const TRAILER_SIG = Buffer.from("ECAPTR", "ascii");

// ===== Shared helpers =====
function secureWipeBuffer(buffer: Buffer | null) {
  if (buffer) buffer.fill(0);
}
function sleep(ms: number) { return new Promise((res) => setTimeout(res, ms)); }
function autoOutputPath(pth: string): string {
  if (!pth) return "";
  const dir = path.dirname(pth);
  const base = path.basename(pth);
  const ext = path.extname(base);
  const stem = ext ? base.slice(0, -ext.length) : base;
  return path.join(dir, `${stem}.dec.txt`);
}

// Header parse (matches Encode)
function parseHeader(h: Uint8Array) {
  if (h.length < HEADER_SIZE) throw new Error("Header too small");
  const b = Buffer.from(h);
  let o = 0;
  if (b.slice(0, 4).compare(MAGIC) !== 0) throw new Error("Not an Encapsula carrier (magic mismatch)");
  o += 4;
  const version = b[o++];
  if (version !== VERSION) throw new Error(`Unsupported version ${version}`);
  const flags = b[o++];
  const bitsPerChannel = b[o++] as 1 | 2;
  const channelsMask = b[o++];
  const payloadLen = b.readUInt32BE(o); o += 4;
  const kdf = b[o++];
  if (kdf !== KDF_SCRYPT) throw new Error("Unsupported KDF");
  const logN = b[o++], r = b[o++], p = b[o++];
  const salt = b.slice(o, o + 16); o += 16;
  const iv = b.slice(o, o + 12); o += 12;
  const tag = b.slice(o, o + 16); o += 16;

  const encrypted = (flags & FLAG_ENCRYPTED) !== 0;
  const randomized = (flags & FLAG_RANDOMIZED) !== 0;

  return { version, encrypted, randomized, bitsPerChannel, channelsMask, payloadLen, kdf, logN, r, p, salt, iv, tag };
}

// Derive key with a generous maxmem to avoid Node's memory-limit error.
async function deriveKeyFixed(
  password: string,
  salt: Buffer,
  logN: number,
  r: number,
  p: number,
): Promise<Buffer> {
  const N = 1 << logN;
  const key: any = await new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      32,
      {
        N,
        r,
        p,
        maxmem: 512 * 1024 * 1024, // 512MB budget for wide compatibility
      },
      (err, derived) => (err ? reject(err) : resolve(derived)),
    );
  });
  return key as Buffer;
}
function aesGcmDecrypt(key: Buffer, iv: Buffer, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(Buffer.from(tag));
  const p1 = decipher.update(Buffer.from(ciphertext));
  const p2 = decipher.final();
  return new Uint8Array(Buffer.concat([p1, p2]));
}

// PNG LSB randomized extract
function enumerateRGBByteIndices(pixels: Uint8Array): number[] {
  const idxs: number[] = [];
  for (let i = 0; i < pixels.length; i += 4) { idxs.push(i); idxs.push(i + 1); idxs.push(i + 2); }
  return idxs;
}
function readHeaderBits(pixels: Uint8Array): Uint8Array {
  const bits = HEADER_SIZE * 8;
  const idxs = enumerateRGBByteIndices(pixels);
  if (idxs.length < bits) throw new Error("Carrier too small for header");
  const out = new Uint8Array(HEADER_SIZE);
  for (let i = 0; i < bits; i++) {
    const p = idxs[i];
    const bit = pixels[p] & 1;
    const byteIndex = Math.floor(i / 8);
    const bitIndex = 7 - (i % 8);
    out[byteIndex] |= bit << bitIndex;
  }
  return out;
}
type BitPos = { byteIndex: number; plane: 0 | 1 };
class HmacPRNG {
  private key: Buffer;
  private counter = 0;
  private buf = Buffer.alloc(0);
  private ptr = 0;
  constructor(key: Buffer) { this.key = key; }
  private refill() {
    const h = crypto.createHmac("sha256", this.key);
    const blk = Buffer.allocUnsafe(4);
    blk.writeUInt32BE(this.counter++ >>> 0, 0);
    h.update(blk);
    this.buf = h.digest();
    this.ptr = 0;
  }
  nextByte(): number { if (this.ptr >= this.buf.length) this.refill(); return this.buf[this.ptr++]; }
  nextUint32(): number { let x = 0; for (let i = 0; i < 4; i++) x = (x << 8) | this.nextByte(); return x >>> 0; }
}
function buildPayloadPositions(pixels: Uint8Array, bitsPerChannel: 1 | 2): BitPos[] {
  const allRGB = enumerateRGBByteIndices(pixels);
  const headerBits = HEADER_SIZE * 8;
  const usable = allRGB.slice(headerBits);
  const positions: BitPos[] = [];
  for (const i of usable) {
    positions.push({ byteIndex: i, plane: 0 });
    if (bitsPerChannel === 2) positions.push({ byteIndex: i, plane: 1 });
  }
  return positions;
}
function shufflePositions(positions: BitPos[], prng: HmacPRNG) {
  for (let i = positions.length - 1; i > 0; i--) {
    const j = prng.nextUint32() % (i + 1);
    const t = positions[i]; positions[i] = positions[j]; positions[j] = t;
  }
}
function extractBits(pixels: Uint8Array, positions: BitPos[], byteCount: number): Uint8Array {
  const totalBits = byteCount * 8;
  if (positions.length < totalBits) {
    throw new Error(`Carrier capacity too small for extraction. Need ${totalBits} bits.`);
  }
  const out = new Uint8Array(byteCount);
  let cursor = 0;
  for (let i = 0; i < byteCount; i++) {
    let acc = 0;
    for (let b = 7; b >= 0; b--) {
      const pos = positions[cursor++];
      const mask = 1 << pos.plane;
      const v = (pixels as any)[pos.byteIndex] as number;
      const bit = (v & mask) >> pos.plane;
      acc |= (bit << b);
    }
    out[i] = acc;
  }
  return out;
}

// Container extractors
function isJpeg(buf: Buffer): boolean { return buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xd8; }
function isWebP(buf: Buffer): boolean {
  return buf.length >= 12 &&
    buf.slice(0, 4).toString("ascii") === "RIFF" &&
    buf.slice(8, 12).toString("ascii") === "WEBP";
}
function extractJpegAPP15(original: Buffer): Buffer | null {
  if (!isJpeg(original)) return null;
  let pos = 2;
  while (pos + 4 <= original.length && original[pos] === 0xff) {
    const code = original[pos + 1];
    if (code === 0xda || code === 0xd9) break;
    if (code >= 0xd0 && code <= 0xd7) { pos += 2; continue; }
    const segLen = original.readUInt16BE(pos + 2);
    if (segLen < 2 || pos + 2 + segLen > original.length) break;
    const payload = original.slice(pos + 4, pos + 2 + segLen);
    if (payload.length >= 4 && payload.slice(0, 4).compare(MAGIC) === 0) return payload;
    pos += 2 + segLen;
  }
  return null;
}
function extractWebPChunk(original: Buffer): Buffer | null {
  if (!isWebP(original)) return null;
  let pos = 12;
  while (pos + 8 <= original.length) {
    const fourcc = original.slice(pos, pos + 4).toString("ascii");
    const size = original.readUInt32LE(pos + 4);
    const dataStart = pos + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > original.length) break;
    if (fourcc === "ECAP") return original.slice(dataStart, dataEnd);
    pos = dataEnd + (size % 2);
  }
  return null;
}
function extractTrailer(original: Buffer): Buffer | null {
  const idx = original.lastIndexOf(TRAILER_SIG);
  if (idx < 0 || idx + TRAILER_SIG.length + 4 > original.length) return null;
  const len = original.readUInt32BE(idx + TRAILER_SIG.length);
  const start = idx + TRAILER_SIG.length + 4;
  const end = start + len;
  if (end > original.length) return null;
  return original.slice(start, end);
}

function bytesToTextSafe(b: Uint8Array): string {
  try { return new TextDecoder().decode(b); }
  catch { return Buffer.from(b).toString("hex"); }
}

// ===== Rendering =====
function renderUpload() {
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  if (!state.pathEntryMode) {
    lines.push("> Press Enter to Upload");
  } else {
    lines.push("Enter full file path and press Enter:");
    lines.push("");
    const shown = (state.inputBuffer || "").slice(0, 98);
    lines.push("┌" + "─".repeat(100) + "┐");
    lines.push("│ " + shown.padEnd(100) + " │");
    lines.push("└" + "─".repeat(100) + "┘");
    lines.push("");
    lines.push("ESC to cancel");
  }
  return lines.join("\n");
}
function renderPassword() {
  const vpWidth = Math.max(40, term.width || 80);
  const boxWidth = Math.min(72, Math.max(24, Math.floor(vpWidth * 0.35)));
  const masked = "*".repeat(state.inputBuffer.length || 0);
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push("Enter password (used during encoding):");
  lines.push("");
  lines.push("┌" + "─".repeat(boxWidth + 2) + "┐");
  lines.push("│ " + masked.slice(0, boxWidth).padEnd(boxWidth) + " │");
  lines.push("└" + "─".repeat(boxWidth + 2) + "┘");
  lines.push("");
  lines.push("Press ENTER when done");
  return lines.join("\n");
}
function renderProgressBlock() {
  const labels = ["Extracting", "Decrypting", "Finalizing"];
  const barWidth = Math.min(44, Math.max(24, Math.floor((term.width || 80) * 0.28)));
  const rows: string[] = [];
  const globalPct = Math.max(0, Math.min(100, Math.round(state.progress || 0)));

  for (let i = 0; i < labels.length; i++) {
    const segStart = i * (100 / labels.length);
    const segEnd = (i + 1) * (100 / labels.length);
    let localPct = 0;
    if (globalPct <= segStart) localPct = 0;
    else if (globalPct >= segEnd) localPct = 100;
    else localPct = Math.round(((globalPct - segStart) / (segEnd - segStart)) * 100);

    const filled = Math.round((localPct / 100) * barWidth);
    const eq = "=".repeat(filled);
    const coloredEq = chalk.hex("#FFA500")(eq);
    const bar = "[" + coloredEq + " ".repeat(Math.max(0, barWidth - filled)) + "]";
    rows.push(labels[i].padEnd(11) + " : " + bar + " " + String(localPct).padStart(3) + "%");
  }
  rows.push("");
  rows.push("Hidden message will be shown when extraction completes");
  return rows.join("\n");
}
function renderProcessing() {
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push("Processing...");
  lines.push("");
  lines.push(renderProgressBlock());
  lines.push("");
  return lines.join("\n");
}
function renderComplete() {
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push(renderProgressBlock());
  lines.push("");
  if (state.error) {
    lines.push(chalk.red.bold("Decoding failed"));
    lines.push("");
    lines.push(chalk.red(state.error));
    lines.push("");
    lines.push("Press any key to try again");
    return lines.join("\n");
  }

  lines.push(chalk.green.bold("✓ Decoding successful!"));
  lines.push("");
  lines.push(chalk.bold("Decrypted message:"));
  lines.push("");
  const msg = state.decodedMessage || "";
  const rows = msg.split("\n");
  rows.forEach((r) => lines.push(r));
  lines.push("");
  lines.push("Press any key to decode another file");
  return lines.join("\n");
}

// ===== Decoding core =====
async function processDecoding() {
  if (!state.uploadedFile) {
    state.error = "No file selected";
    state.screen = "complete";
    if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
    return;
  }

  state.screen = "processing";
  state.progress = 0;
  state.decodedMessage = null;
  state.error = null;

  try {
    const fileBuffer = state.uploadedFile.buffer || await fs.readFile(state.uploadedFile.path);

    for (let p = 0; p <= 100; p++) {
      state.progress = p;

      if (p === 66) {
        // Try PNG header-based extraction first (most robust)
        let blob: Buffer | null = null;
        try {
          const png = PNG.sync.read(fileBuffer) as any;
          const data: Uint8Array = png.data;
          const header = readHeaderBits(data);
          const meta = parseHeader(header);
          // derive key and positions
          const key = await deriveKeyFixed(
            (state.password || Buffer.alloc(0)).toString("utf8"),
            meta.salt,
            meta.logN,
            meta.r,
            meta.p,
          );
          const positions = buildPayloadPositions(data, meta.bitsPerChannel as 1 | 2);
          if (meta.randomized) {
            const prngKey = crypto.createHmac("sha256", key).update("ECAP-PERMUTE").digest();
            const prng = new HmacPRNG(prngKey);
            shufflePositions(positions, prng);
          }
          const ciphertext = extractBits(data, positions, meta.payloadLen);
          const plaintext = aesGcmDecrypt(key, meta.iv, ciphertext, meta.tag);
          state.decodedMessage = bytesToTextSafe(plaintext);
        } catch {
          // Containers: JPEG -> WebP -> Trailer
          try { blob = extractJpegAPP15(fileBuffer); } catch {}
          if (!blob) try { blob = extractWebPChunk(fileBuffer); } catch {}
          if (!blob) try { blob = extractTrailer(fileBuffer); } catch {}

          if (!blob || blob.length < HEADER_SIZE + 1) {
            state.error = "No embedded payload found or payload too small.";
            state.screen = "complete";
            if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
            return;
          }
          const meta = parseHeader(blob.slice(0, HEADER_SIZE));
          const ciphertext = blob.slice(HEADER_SIZE);
          const key = await deriveKeyFixed(
            (state.password || Buffer.alloc(0)).toString("utf8"),
            meta.salt,
            meta.logN,
            meta.r,
            meta.p,
          );
          const plaintext = aesGcmDecrypt(key, meta.iv, ciphertext, meta.tag);
          state.decodedMessage = bytesToTextSafe(plaintext);
        }
      }

      await sleep(30);
      if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
    }

    if (!state.decodedMessage) {
      state.error = "Failed to extract/decrypt.";
    }

    state.progress = 100;
    state.screen = "complete";
    secureWipeBuffer(state.password);
    state.password = null;
    if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
  } catch (e) {
    state.error = "Processing failed: " + (e as Error).message;
    state.screen = "complete";
    if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
  }
}

// ===== Input handling and rendering export =====
export function handleDecodeInput(key: string, data?: any): boolean {
  const isEnter =
    key === "ENTER" ||
    key === "RETURN" ||
    key === "KP_ENTER" ||
    (data && (data.codepoint === 13 || data.codepoint === 10));

  if (key === "ESCAPE" && state.screen !== "processing") {
    secureWipeBuffer(state.password);
    state = {
      screen: "upload",
      uploadedFile: null,
      inputBuffer: "",
      password: null,
      progress: 0,
      decodedMessage: null,
      error: null,
      outputPath: "",
      autoOutput: true,
      pathEntryMode: false,
    };
    if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
    return true;
  }

  if (state.screen === "upload") {
    if (!state.pathEntryMode && isEnter) {
      pickCarrierFile().then((picked) => {
        if (picked === "__PROMPT__") {
          state.pathEntryMode = true;
          state.inputBuffer = "";
          if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
          return;
        }
        if (picked) {
          try {
            const stats = fssync.statSync(picked);
            state.uploadedFile = {
              path: picked,
              name: path.basename(picked),
              size: stats.size,
              ext: path.extname(picked),
              buffer: fssync.readFileSync(picked),
            };
            state.screen = "password";
            state.inputBuffer = "";
            state.progress = 0;
            secureWipeBuffer(state.password);
            state.password = null;
            if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
          } catch {}
        }
      });
      return true;
    }

    if (state.pathEntryMode) {
      if (isEnter) {
        const pth = (state.inputBuffer || "").trim();
        if (pth && fssync.existsSync(pth)) {
          try {
            const stats = fssync.statSync(pth);
            state.uploadedFile = {
              path: pth,
              name: path.basename(pth),
              size: stats.size,
              ext: path.extname(pth),
              buffer: fssync.readFileSync(pth),
            };
            state.screen = "password";
            state.inputBuffer = "";
            state.pathEntryMode = false;
            if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
          } catch {}
          return true;
        } else {
          return true;
        }
      }
      if (key === "BACKSPACE" || key === "DELETE") {
        state.inputBuffer = state.inputBuffer.slice(0, -1);
        return true;
      }
      if (key && key.length === 1) {
        state.inputBuffer += key;
        return true;
      }
      return false;
    }
    return false;
  }

  if (state.screen === "password") {
    if (isEnter) {
      secureWipeBuffer(state.password);
      state.password = Buffer.from(state.inputBuffer, "utf8");
      state.inputBuffer = "";
      state.progress = 5;
      state.screen = "processing";
      setTimeout(() => {
        processDecoding().then(() => {
          if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
        });
      }, 80);
      if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
      return true;
    }
    if (key === "BACKSPACE" || key === "DELETE") {
      state.inputBuffer = state.inputBuffer.slice(0, -1);
      if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
      return true;
    }
    if (key && key.length === 1 && state.inputBuffer.length < 256) {
      state.inputBuffer += key;
      if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
      return true;
    }
    return false;
  }

  if (state.screen === "processing") {
    return true;
  }

  if (state.screen === "complete") {
    if (key && key.length > 0) {
      secureWipeBuffer(state.password);
      state = {
        screen: "upload",
        uploadedFile: null,
        inputBuffer: "",
        password: null,
        progress: 0,
        decodedMessage: null,
        error: null,
        outputPath: "",
        autoOutput: true,
        pathEntryMode: false,
      };
      if ((global as any).showSection) try { (global as any).showSection("Decode"); } catch {}
      return true;
    }
    return true;
  }
  return false;
}

export default function Decode(): string {
  switch (state.screen) {
    case "upload": return renderUpload();
    case "password": return renderPassword();
    case "processing": return renderProcessing();
    case "complete": return renderComplete();
    default: return renderUpload();
  }
}

export function getDecodeState() {
  return state;
}