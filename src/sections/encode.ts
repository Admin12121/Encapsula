import chalk from "chalk";
import termkit from "terminal-kit";
import * as path from "path";
import * as os from "os";
import fs from "fs/promises";
import fssync from "fs";
import crypto from "crypto";
import { PNG } from "pngjs";
import { pickCarrierFile } from "../ui/filePicker";

const term = termkit.terminal;

// Screens for step-by-step wizard
type Screen = "upload" | "message" | "password" | "processing" | "complete";

interface UploadedFile {
  path: string;
  name: string;
  size?: number;
  ext?: string;
}

interface State {
  screen: Screen;
  uploadedFile: UploadedFile | null;
  inputBuffer: string;
  message: string;
  password: Buffer | null;
  outputPath: string;
  progress: number;
  intermediateWritten: boolean;
  downloadedPath?: string;
  error?: string;
  pathEntryMode: boolean; // for Linux/macOS path typing UX
}

let state: State = {
  screen: "upload",
  uploadedFile: null,
  inputBuffer: "",
  message: "",
  password: null,
  outputPath: "",
  progress: 0,
  intermediateWritten: false,
  pathEntryMode: false,
};

// ===== Shared crypto/header constants (must match Decode) =====
const MAGIC = Buffer.from("ECAP", "ascii"); // 4
const VERSION = 0x01;

// Header: 60 bytes total
// magic(4) + ver(1) + flags(1) + bits(1) + channels(1) + payloadLen(4)
// + kdf(1) + logN(1) + r(1) + p(1) + salt(16) + iv(12) + tag(16)
const HEADER_SIZE = 60;

const FLAG_ENCRYPTED = 1 << 0; // always set
const FLAG_RANDOMIZED = 1 << 1; // PNG randomized payload

const CHANNELS_MASK_RGB = 0b00000111;

const KDF_SCRYPT = 1;
// Prefer strong params but be adaptive on low-memory boxes
const SCRYPT_LOGN_PREFERRED = 15; // 2^15
const SCRYPT_R = 8;
const SCRYPT_P = 1;

// ===== Utils =====
function secureWipeBuffer(buffer: Buffer | null) {
  if (buffer) buffer.fill(0);
}
function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}
function makeOutputPath(inPath: string) {
  const dir = path.dirname(inPath);
  const base = path.basename(inPath);
  const ext = path.extname(base);
  const name = ext ? base.slice(0, -ext.length) : base;
  return path.join(dir, `${name}_encoded${ext || ""}`);
}
function downloadToDownloads() {
  if (!state.outputPath || !fssync.existsSync(state.outputPath)) return null;
  try {
    const downloads = path.join(os.homedir(), "Downloads");
    if (!fssync.existsSync(downloads)) fssync.mkdirSync(downloads, { recursive: true });
    const dest = path.join(
      downloads,
      `${Date.now().toString(16)}_${path.basename(state.outputPath)}`,
    );
    fssync.copyFileSync(state.outputPath, dest);
    state.downloadedPath = dest;
    return dest;
  } catch (e) {
    state.error = "Download failed: " + (e as Error).message;
    return null;
  }
}

// ===== Header + crypto helpers =====
function u32be(n: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
function u32le(n: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}
function buildHeader(params: {
  encrypted: boolean;
  randomized: boolean;
  bitsPerChannel: 1 | 2;
  channelsMask: number;
  payloadLen: number;
  kdf: number;     // KDF id (scrypt)
  logN: number;    // effective logN used (adaptive)
  r: number;
  p: number;
  salt: Buffer;    // 16
  iv: Buffer;      // 12
  tag: Buffer;     // 16
}): Buffer {
  const {
    encrypted,
    randomized,
    bitsPerChannel,
    channelsMask,
    payloadLen,
    kdf, logN, r, p,
    salt,
    iv,
    tag,
  } = params;

  const flags =
    (encrypted ? FLAG_ENCRYPTED : 0) |
    (randomized ? FLAG_RANDOMIZED : 0);

  const out = Buffer.alloc(HEADER_SIZE, 0);
  let o = 0;
  MAGIC.copy(out, o); o += 4;
  out[o++] = VERSION;
  out[o++] = flags & 0xff;
  out[o++] = bitsPerChannel;
  out[o++] = channelsMask & 0xff;
  u32be(payloadLen).copy(out, o); o += 4;
  out[o++] = kdf & 0xff;
  out[o++] = logN & 0xff;
  out[o++] = r & 0xff;
  out[o++] = p & 0xff;
  if (salt.length !== 16) throw new Error("salt must be 16 bytes");
  salt.copy(out, o); o += 16;
  if (iv.length !== 12) throw new Error("iv must be 12 bytes");
  iv.copy(out, o); o += 12;
  if (tag.length !== 16) throw new Error("tag must be 16 bytes");
  tag.copy(out, o); o += 16;
  return out;
}

// Adaptive scrypt: try preferred logN, reduce if memory-limited.
// Always pass a generous maxmem so Node v22 doesn't reject.
async function deriveKeyAdaptive(
  password: string,
  salt: Buffer,
  preferredLogN: number,
  r: number,
  p: number,
): Promise<{ key: Buffer; logNUsed: number }> {
  for (let logN = preferredLogN; logN >= 12; logN--) {
    const N = 1 << logN;
    try {
      const key: any = await new Promise((resolve, reject) => {
        crypto.scrypt(
          password,
          salt,
          32,
          {
            N,
            r,
            p,
            maxmem: 512 * 1024 * 1024, // 512MB to avoid ERR_CRYPTO_INVALID_SCRYPT_PARAMS
          },
          (err, derived) => (err ? reject(err) : resolve(derived)),
        );
      });
      return { key: key as Buffer, logNUsed: logN };
    } catch (e: any) {
      const msg = (e && e.message) || "";
      // Try a lower N on memory-limit style errors; otherwise rethrow.
      if (
        e?.code === "ERR_CRYPTO_INVALID_SCRYPT_PARAMS" ||
        /memory limit/i.test(msg)
      ) {
        continue; // lower logN and retry
      }
      throw e;
    }
  }
  throw new Error("scrypt parameters not supported on this device (too little memory)");
}

function aesGcmEncrypt(key: Buffer, iv: Buffer, plaintext: Uint8Array): { ciphertext: Buffer, tag: Buffer } {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const c1 = cipher.update(Buffer.from(plaintext));
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  return { ciphertext: Buffer.concat([c1, c2]), tag };
}
function textToBytes(t: string): Uint8Array {
  return new TextEncoder().encode(t);
}

// ===== PNG LSB randomized =====
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
  nextByte(): number {
    if (this.ptr >= this.buf.length) this.refill();
    return this.buf[this.ptr++];
  }
  nextUint32(): number {
    let x = 0;
    for (let i = 0; i < 4; i++) x = (x << 8) | this.nextByte();
    return x >>> 0;
  }
}
function enumerateRGBByteIndices(pixels: Uint8Array): number[] {
  const idxs: number[] = [];
  for (let i = 0; i < pixels.length; i += 4) {
    idxs.push(i); idxs.push(i + 1); idxs.push(i + 2);
  }
  return idxs;
}
function writeHeaderBits(pixels: Uint8Array, header: Uint8Array) {
  const bits = HEADER_SIZE * 8;
  const idxs = enumerateRGBByteIndices(pixels);
  if (idxs.length < bits) throw new Error("Carrier too small for header");
  for (let i = 0; i < bits; i++) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = 7 - (i % 8);
    const bit = (header[byteIndex] >> bitIndex) & 1;
    const p = idxs[i];
    pixels[p] = (pixels[p] & ~1) | bit;
  }
}
type BitPos = { byteIndex: number; plane: 0 | 1 };
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
function embedBits(pixels: Uint8Array, positions: BitPos[], data: Uint8Array) {
  const totalBits = data.length * 8;
  if (positions.length < totalBits) {
    throw new Error(`Carrier capacity too small. Need ${totalBits} bits, have ${positions.length}.`);
  }
  let cursor = 0;
  for (let i = 0; i < data.length; i++) {
    for (let b = 7; b >= 0; b--) {
      const bit = (data[i] >> b) & 1;
      const pos = positions[cursor++];
      const mask = 1 << pos.plane;
      const v = pixels[pos.byteIndex];
      const nv = (v & ~mask) | (bit << pos.plane);
      pixels[pos.byteIndex] = nv;
    }
  }
}
function capacityBits(pixels: Uint8Array, bitsPerChannel: 1 | 2): number {
  const channels = (pixels.length / 4) * 3;
  const headerBits = HEADER_SIZE * 8;
  return channels * bitsPerChannel - headerBits;
}

// ===== JPEG APP15, WebP RIFF, Trailer backends =====
function isJpeg(buf: Buffer): boolean {
  return buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xd8;
}
function insertJpegAPP15(original: Buffer, blob: Buffer): Buffer {
  if (!isJpeg(original)) throw new Error("Not a JPEG file");
  const marker = Buffer.from([0xff, 0xef]); // APP15
  const maxPayload = 0xffff - 2;
  if (blob.length > maxPayload) {
    throw new Error(`Payload too large for one JPEG segment (${blob.length} > ${maxPayload}).`);
  }
  const len = Buffer.alloc(2);
  len.writeUInt16BE(blob.length + 2, 0);
  let pos = 2;
  while (pos + 4 <= original.length && original[pos] === 0xff) {
    const code = original[pos + 1];
    if (code === 0xda /* SOS */ || code === 0xd9 /* EOI */) break;
    if (code >= 0xd0 && code <= 0xd7) { pos += 2; continue; } // RSTn
    const segLen = original.readUInt16BE(pos + 2);
    if (segLen < 2) break;
    pos += 2 + segLen;
  }
  const before = original.slice(0, pos);
  const after = original.slice(pos);
  const segment = Buffer.concat([marker, len, blob]);
  return Buffer.concat([before, segment, after]);
}
function isWebP(buf: Buffer): boolean {
  return buf.length >= 12 &&
    buf.slice(0, 4).toString("ascii") === "RIFF" &&
    buf.slice(8, 12).toString("ascii") === "WEBP";
}
function insertWebPChunk(original: Buffer, blob: Buffer): Buffer {
  if (!isWebP(original)) throw new Error("Not a WebP file");
  const fourcc = Buffer.from("ECAP", "ascii");
  const size = u32le(blob.length);
  const pad = (blob.length % 2) ? Buffer.from([0]) : Buffer.alloc(0);
  const chunk = Buffer.concat([fourcc, size, blob, pad]);
  const body = original.slice(12);
  const newBody = Buffer.concat([body, chunk]);
  const newSize = newBody.length + 4;
  return Buffer.concat([
    Buffer.from("RIFF", "ascii"),
    u32le(newSize),
    Buffer.from("WEBP", "ascii"),
    newBody,
  ]);
}
function appendTrailer(original: Buffer, blob: Buffer): Buffer {
  return Buffer.concat([original, Buffer.from("ECAPTR", "ascii"), u32be(blob.length), blob]);
}
type CarrierKind = "png" | "jpeg" | "webp" | "pdf" | "other";
function detectCarrier(buf: Buffer, ext: string): CarrierKind {
  if (buf.length >= 8 && buf.slice(0, 8).toString("ascii") === "\x89PNG\r\n\x1a\n") return "png";
  if (isJpeg(buf)) return "jpeg";
  if (isWebP(buf)) return "webp";
  if (buf.slice(0, 5).toString("ascii") === "%PDF-") return "pdf";
  const e = (ext || "").toLowerCase();
  if (e === ".png") return "png";
  if (e === ".jpg" || e === ".jpeg") return "jpeg";
  if (e === ".webp") return "webp";
  if (e === ".pdf") return "pdf";
  return "other";
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
function renderMessage() {
  const vpWidth = Math.max(40, term.width || 80);
  const boxWidth = Math.min(96, Math.max(40, Math.floor(vpWidth * 0.6)));
  const boxHeight = Math.min(16, Math.max(6, Math.floor(((term.height || 24) - 8) / 2)));
  const currentBytes = Buffer.from(state.inputBuffer || "", "utf8").length;

  const raw = state.inputBuffer || "";
  const rows = raw.split("\n");
  const startRow = Math.max(0, rows.length - boxHeight);
  const visibleRows = rows.slice(startRow, startRow + boxHeight);

  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push(
    "Enter secret message " +
      chalk.hex("#f97316")(`(${currentBytes} b):`)
  );
  lines.push("");
  const top = "┌" + "─".repeat(boxWidth + 2) + "┐";
  const bottom = "└" + "─".repeat(boxWidth + 2) + "┘";
  lines.push(top);
  for (let i = 0; i < boxHeight; i++) {
    const r = visibleRows[i] || "";
    const clipped = r.slice(0, boxWidth);
    lines.push("│ " + clipped.padEnd(boxWidth) + " │");
  }
  lines.push(bottom);
  lines.push("");
  lines.push("Press Ctrl+S to finish — ENTER inserts newline");
  return lines.join("\n");
}
function renderPassword() {
  const vpWidth = Math.max(40, term.width || 80);
  const boxWidth = Math.min(72, Math.max(24, Math.floor(vpWidth * 0.35)));
  const masked = "*".repeat(state.inputBuffer.length || 0);
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push("Enter password (will not be stored):");
  lines.push("");
  lines.push("┌" + "─".repeat(boxWidth + 2) + "┐");
  lines.push("│ " + masked.slice(0, boxWidth).padEnd(boxWidth) + " │");
  lines.push("└" + "─".repeat(boxWidth + 2) + "┘");
  lines.push("");
  lines.push("Press ENTER when done");
  return lines.join("\n");
}
function renderProgressBlock() {
  const labels = ["Uploading", "Encrypting", "Finalizing"];
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
  rows.push("Find encoded file in your Downloads folder");
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
  lines.push(" ");
  return lines.join("\n");
}
function renderComplete() {
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push(renderProgressBlock());
  lines.push("");
  if (state.downloadedPath) {
    lines.push("");
    lines.push("Downloaded: " + chalk.hex("#FFA500")(state.downloadedPath));
  }
  if (state.error) {
    lines.push("");
    lines.push(chalk.red("Note: " + state.error));
  }
  lines.push("");
  lines.push("Press any key to start over");
  return lines.join("\n");
}

// ===== Core processing =====
async function embedAuto(fileBuffer: Buffer, ext: string, header: Buffer, ciphertext: Buffer, key: Buffer): Promise<Buffer> {
  const blob = Buffer.concat([header, ciphertext]);
  const kind = detectCarrier(fileBuffer, ext);

  switch (kind) {
    case "png": {
      const png = PNG.sync.read(fileBuffer) as any;
      const data: Uint8Array = png.data;
      const capBits = capacityBits(data, 1);
      if (capBits < ciphertext.length * 8) {
        throw new Error(`Carrier too small. Capacity: ${Math.floor(capBits / 8)} bytes; Need: ${ciphertext.length} bytes`);
      }
      // header then randomized payload
      writeHeaderBits(data, header);
      const positions = buildPayloadPositions(data, 1);
      const prngKey = crypto.createHmac("sha256", key).update("ECAP-PERMUTE").digest();
      const prng = new HmacPRNG(prngKey);
      shufflePositions(positions, prng);
      embedBits(data, positions, ciphertext);
      png.data = Buffer.from(data);
      const outBuf = PNG.sync.write(png as any);
      return Buffer.from(outBuf);
    }

    case "jpeg": {
      if (blob.length > 0xffff - 2) {
        throw new Error(`Message too large for a single JPEG chunk (~64KB max). Use a PNG carrier for larger data.`);
      }
      return insertJpegAPP15(fileBuffer, blob);
    }

    case "webp": {
      return insertWebPChunk(fileBuffer, blob);
    }

    case "pdf":
    case "other": {
      return appendTrailer(fileBuffer, blob);
    }
  }
}

// Main processing loop with animation
async function processEncoding() {
  if (!state.uploadedFile) {
    state.error = "No file selected";
    state.screen = "complete";
    return;
  }
  if (!state.message) {
    state.error = "Message is empty";
    state.screen = "complete";
    return;
  }
  state.screen = "processing";
  state.progress = 0;
  state.intermediateWritten = false;
  state.outputPath = makeOutputPath(state.uploadedFile.path);

  // Build crypto artifacts (adaptive scrypt)
  const plaintext = textToBytes(state.message);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  let key: Buffer;
  let logNUsed = SCRYPT_LOGN_PREFERRED;
  try {
    const res = await deriveKeyAdaptive(
      (state.password || Buffer.alloc(0)).toString("utf8"),
      salt,
      SCRYPT_LOGN_PREFERRED,
      SCRYPT_R,
      SCRYPT_P,
    );
    key = res.key;
    logNUsed = res.logNUsed;
  } catch (e: any) {
    state.error = "Key derivation failed: " + (e.message || String(e));
    state.screen = "complete";
    return;
  }

  const { ciphertext, tag } = aesGcmEncrypt(key, iv, plaintext);
  const header = buildHeader({
    encrypted: true,
    randomized: true,
    bitsPerChannel: 1,
    channelsMask: CHANNELS_MASK_RGB,
    payloadLen: plaintext.length,
    kdf: KDF_SCRYPT,
    logN: logNUsed,
    r: SCRYPT_R,
    p: SCRYPT_P,
    salt, iv, tag,
  });

  try {
    const fileBuffer = await fs.readFile(state.uploadedFile.path);
    for (let p = 0; p <= 100; p++) {
      state.progress = p;

      // At 66%, attempt an intermediate write so the user sees work happening
      if (p === 66 && !state.intermediateWritten) {
        try {
          const midBuf = await embedAuto(
            fileBuffer,
            state.uploadedFile.ext || path.extname(state.uploadedFile.path),
            header,
            ciphertext,
            key,
          );
          await fs.writeFile(state.outputPath, midBuf);
          state.intermediateWritten = true;
        } catch (e) {
          // Don't fail the whole run here; continue to final write at 100%
          state.error = "Intermediate write failed: " + (e as Error).message;
        }
      }

      await sleep(35);
      if ((global as any).showSection) {
        try { (global as any).showSection("Encode"); } catch {}
      }
    }

    // Final embedding
    try {
      const finalBuf = await embedAuto(
        fileBuffer,
        state.uploadedFile.ext || path.extname(state.uploadedFile.path),
        header,
        ciphertext,
        key,
      );
      await fs.writeFile(state.outputPath, finalBuf);
    } catch (e) {
      state.error = "Embedding failed: " + (e as Error).message;
      // As a last resort, append a trailer blob so the user still gets an output
      const fallback = appendTrailer(fileBuffer, Buffer.concat([header, ciphertext]));
      await fs.writeFile(state.outputPath, fallback);
    }

    downloadToDownloads();
    state.progress = 100;
    state.screen = "complete";
    secureWipeBuffer(state.password);
    state.password = null;
  } catch (e) {
    state.error = "Processing failed: " + (e as Error).message;
    state.screen = "complete";
  }
}

// ===== Input handling and rendering export =====
export function handleEncodeInput(key: string, data?: any): boolean {
  const isEnter =
    key === "ENTER" ||
    key === "RETURN" ||
    key === "KP_ENTER" ||
    (data && (data.codepoint === 13 || data.codepoint === 10));

  // Global escape resets to upload
  if (key === "ESCAPE" && state.screen !== "processing") {
    secureWipeBuffer(state.password);
    state = {
      screen: "upload",
      uploadedFile: null,
      inputBuffer: "",
      message: "",
      password: null,
      outputPath: "",
      progress: 0,
      intermediateWritten: false,
      pathEntryMode: false,
    };
    if ((global as any).showSection) {
      try { (global as any).showSection("Encode"); } catch {}
    }
    return true;
  }

  if (state.screen === "upload") {
    if (!state.pathEntryMode && isEnter) {
      pickCarrierFile().then((picked) => {
        if (picked === "__PROMPT__") {
          state.pathEntryMode = true;
          state.inputBuffer = "";
          if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
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
            };
            state.screen = "message";
            state.inputBuffer = "";
            state.progress = 0;
            secureWipeBuffer(state.password);
            state.password = null;
            if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
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
            };
            state.screen = "message";
            state.inputBuffer = "";
            state.pathEntryMode = false;
            if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
          } catch {}
          return true;
        } else {
          // keep prompting
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

  if (state.screen === "message") {
    const isSave = key === "CTRL_S" || (data && data.codepoint === 19);
    if (isSave) {
      state.message = state.inputBuffer;
      state.inputBuffer = "";
      state.progress = 33;
      state.screen = "password";
      if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
      return true;
    }
    if (isEnter) {
      state.inputBuffer += "\n";
      if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
      return true;
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

  if (state.screen === "password") {
    if (isEnter) {
      secureWipeBuffer(state.password);
      state.password = Buffer.from(state.inputBuffer, "utf8");
      state.inputBuffer = "";
      state.progress = 50;
      state.screen = "processing";
      setTimeout(() => {
        processEncoding().then(() => {
          if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
        });
      }, 80);
      if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
      return true;
    }
    if (key === "BACKSPACE" || key === "DELETE") {
      state.inputBuffer = state.inputBuffer.slice(0, -1);
      return true;
    }
    if (key && key.length === 1 && state.inputBuffer.length < 256) {
      state.inputBuffer += key;
      return true;
    }
    return false;
  }

  if (state.screen === "processing") {
    return true; // ignore keys during processing
  }

  if (state.screen === "complete") {
    if (key && key.length > 0) {
      secureWipeBuffer(state.password);
      state = {
        screen: "upload",
        uploadedFile: null,
        inputBuffer: "",
        message: "",
        password: null,
        outputPath: "",
        progress: 0,
        intermediateWritten: false,
        pathEntryMode: false,
      };
      if ((global as any).showSection) try { (global as any).showSection("Encode"); } catch {}
      return true;
    }
    return true;
  }

  return false;
}

export default function Encode(): string {
  switch (state.screen) {
    case "upload": return renderUpload();
    case "message": return renderMessage();
    case "password": return renderPassword();
    case "processing": return renderProcessing();
    case "complete": return renderComplete();
    default: return renderUpload();
  }
}

export function getEncodeState() {
  return state;
}