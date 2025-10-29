import chalk from "chalk";
import termkit from "terminal-kit";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { execFileSync } from "child_process";
import * as os from "os";

const term = termkit.terminal;

/*
  Encode section - now supports selectable real steganography methods:
  - LSB (Least Significant Bit) insertion into image pixel channels (PNG/JPEG/BMP when supported)
  - DCT coefficient manipulation for JPEG images (requires jpeg-js)

  Flow:
  - Upload -> Choose method -> Message -> Password -> Processing -> Complete
  - Message textarea supports multiple lines (ENTER inserts newline). Finish with Ctrl+S.
*/

// Types & State
type Screen =
  | "upload"
  | "method"
  | "message"
  | "password"
  | "processing"
  | "complete";

type Method = "lsb" | "dct" | null;

interface UploadedFile {
  path: string;
  name: string;
  size?: number;
  ext?: string;
}

interface State {
  screen: Screen;
  method: Method;
  uploadedFile: UploadedFile | null;
  message: string;
  password: Buffer | null;
  inputBuffer: string;
  outputPath: string;
  progress: number;
  intermediateWritten: boolean;
  downloadedPath?: string;
  error?: string;
}

let state: State = {
  screen: "upload",
  method: null,
  uploadedFile: null,
  message: "",
  password: null,
  inputBuffer: "",
  outputPath: "",
  progress: 0,
  intermediateWritten: false,
};

// Utility functions
function secureWipeBuffer(buffer: Buffer | null) {
  if (buffer) {
    buffer.fill(0);
  }
}

function stripAnsi(s: string) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function openFilePicker(): Promise<string | null> {
  return new Promise((resolve) => {
    const ps = `
Add-Type -AssemblyName System.Windows.Forms
$dlg = New-Object System.Windows.Forms.OpenFileDialog
$dlg.Title = "Select a file to encode"
$dlg.Filter = "All Files (*.*)|*.*"
$dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Console]::Write($dlg.FileName)
}
`.trim();
    const tmp = path.join(os.tmpdir(), `encap_open_${Date.now()}.ps1`);
    try {
      fs.writeFileSync(tmp, ps, "utf8");
      const out = execFileSync(
        "powershell.exe",
        ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp],
        {
          encoding: "utf8",
          windowsHide: true,
        },
      )
        .toString()
        .trim();
      try {
        fs.unlinkSync(tmp);
      } catch {}
      if (out && fs.existsSync(out)) resolve(out);
      else resolve(null);
    } catch {
      try {
        if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
      } catch {}
      resolve(null);
    }
  });
}

function makeOutputPath(inPath: string) {
  const dir = path.dirname(inPath);
  const base = path.basename(inPath);
  const ext = path.extname(base) || ".bin";
  const name = path.basename(base, ext);
  return path.join(dir, `${name}_encoded${ext}`);
}

function deriveKey(password: string, salt: Buffer) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha512");
}

function encryptMessage(message: string, password: Buffer) {
  const salt = crypto.randomBytes(32);
  const key = deriveKey(password.toString("utf8"), salt);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(message, "utf8"),
    cipher.final(),
  ]);
  return { salt, iv, encrypted };
}

function embedGeneric(fileBuffer: Buffer, data: Buffer) {
  const marker = Buffer.from("<<ENCAPSULA_HIDDEN>>", "utf8");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  return Buffer.concat([fileBuffer, marker, lenBuf, data, marker]);
}

function makePayload(messageBuffer: Buffer) {
  const version = Buffer.alloc(4);
  version.writeUInt32BE(1, 0);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(messageBuffer.length, 0);
  return Buffer.concat([version, len, messageBuffer]);
}

async function embedLSBImage(fileBuffer: Buffer, payload: Buffer, ext: string) {
  // LSB embedding into JPEG is not reliable because JPEG is lossy and
  // re-encoding will destroy bit-level LSB payloads. Refuse to attempt
  // LSB on JPEG hosts and instruct the caller to use DCT instead.
  const extLower = (ext || "").toLowerCase();
  const isJpegMagic = fileBuffer.slice(0, 2).toString("hex") === "ffd8";
  if (extLower === ".jpg" || extLower === ".jpeg" || isJpegMagic) {
    throw new Error(
      "LSB embedding into JPEG is not supported (JPEG is lossy). Use the 'dct' method for JPEG images.",
    );
  }

  const payloadWithHeader = makePayload(payload);
  // Convert to bits
  const bits: number[] = [];
  for (let i = 0; i < payloadWithHeader.length; i++) {
    const byte = payloadWithHeader[i];
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  }

  try {
    const PNG = require("pngjs").PNG as any;
    const png = PNG.sync.read(fileBuffer);
    const { width, height, data } = png;
    const capacity = width * height * 3;
    if (bits.length + 32 > capacity) {
      throw new Error("Not enough capacity in PNG image for payload");
    }
    const lenBits: number[] = [];
    const payloadLen = payloadWithHeader.length;
    for (let i = 31; i >= 0; i--) lenBits.push((payloadLen >> i) & 1);
    const allBits = lenBits.concat(bits);

    let bitIdx = 0;
    for (let i = 0; i < data.length && bitIdx < allBits.length; i += 4) {
      // R
      if (bitIdx < allBits.length) {
        data[i] = (data[i] & 0xfe) | allBits[bitIdx++];
      }
      // G
      if (bitIdx < allBits.length) {
        data[i + 1] = (data[i + 1] & 0xfe) | allBits[bitIdx++];
      }
      // B
      if (bitIdx < allBits.length) {
        data[i + 2] = (data[i + 2] & 0xfe) | allBits[bitIdx++];
      }
    }
    const out = PNG.sync.write({ width, height, data });
    return out as Buffer;
  } catch (e) {
    // PNG support not available or failed; fall through to JPEG/BMP attempts
  }

  try {
    const jpeg = require("jpeg-js") as any;
    const raw = jpeg.decode(fileBuffer, { useTArray: true }) as {
      width: number;
      height: number;
      data: Buffer | Uint8Array;
    };
    if (!raw || !raw.data) throw new Error("Failed to decode JPEG");
    const { width, height } = raw;
    const data = Buffer.from(raw.data);
    const stride = 4;
    const capacity = width * height * 3;
    if (bits.length + 32 > capacity) {
      throw new Error("Not enough capacity in JPEG image for payload");
    }
    const lenBits: number[] = [];
    const payloadLen = payloadWithHeader.length;
    for (let i = 31; i >= 0; i--) lenBits.push((payloadLen >> i) & 1);
    const allBits = lenBits.concat(bits);

    let bitIdx = 0;
    for (let px = 0; px < width * height && bitIdx < allBits.length; px++) {
      const base = px * stride;
      // R
      if (bitIdx < allBits.length) {
        data[base] = (data[base] & 0xfe) | allBits[bitIdx++];
      }
      // G
      if (bitIdx < allBits.length) {
        data[base + 1] = (data[base + 1] & 0xfe) | allBits[bitIdx++];
      }
      // B
      if (bitIdx < allBits.length) {
        data[base + 2] = (data[base + 2] & 0xfe) | allBits[bitIdx++];
      }
      // skip alpha channel if present
    }
    const encoded = jpeg.encode({ data, width, height }, 90);
    return Buffer.from(encoded.data);
  } catch (e) {
    // jpeg-js not available or failed
  }

  try {
    if (fileBuffer.slice(0, 2).toString("ascii") === "BM") {
      const pixelOffset = fileBuffer.readUInt32LE(10);
      const dibHeaderSize = fileBuffer.readUInt32LE(14);
      const width = fileBuffer.readInt32LE(18);
      const height = fileBuffer.readInt32LE(22);
      const bpp = fileBuffer.readUInt16LE(28);
      if (bpp !== 24 && bpp !== 32)
        throw new Error("Unsupported BMP bpp for LSB");
      const pixelData = Buffer.from(fileBuffer.slice(pixelOffset));
      const capacity = Math.floor((pixelData.length / (bpp / 8)) * 3);
      if (bits.length + 32 > capacity)
        throw new Error("Not enough capacity in BMP image for payload");

      const lenBits: number[] = [];
      const payloadLen = payloadWithHeader.length;
      for (let i = 31; i >= 0; i--) lenBits.push((payloadLen >> i) & 1);
      const allBits = lenBits.concat(bits);

      let bitIdx = 0;
      const bytesPerPixel = bpp / 8;
      for (
        let px = 0;
        px < pixelData.length && bitIdx < allBits.length;
        px += bytesPerPixel
      ) {
        for (let c = 0; c < 3 && bitIdx < allBits.length; c++) {
          const idx = px + c;
          pixelData[idx] = (pixelData[idx] & 0xfe) | allBits[bitIdx++];
        }
      }
      const out = Buffer.concat([fileBuffer.slice(0, pixelOffset), pixelData]);
      return out;
    }
  } catch (e) {
    // ignore
  }

  // If none of above worked, fallback to generic append (not real stego)
  throw new Error(
    "No supported image libraries available for LSB embedding. Install 'pngjs' or 'jpeg-js' to enable real LSB embedding, or choose a different host file.",
  );
}

async function embedDCTInJpeg(fileBuffer: Buffer, payload: Buffer) {
  const jpeg = require("jpeg-js") as any;
  const raw = jpeg.decode(fileBuffer, { useTArray: true }) as {
    width: number;
    height: number;
    data: Buffer | Uint8Array;
  };
  if (!raw || !raw.data)
    throw new Error("Failed to decode JPEG for DCT embedding");
  const { width, height } = raw;
  const data = Buffer.from(raw.data); // RGBA

  const yChannel = new Float32Array(width * height);
  const cbChannel = new Float32Array(width * height);
  const crChannel = new Float32Array(width * height);

  for (let i = 0, pix = 0; i < width * height; i++, pix += 4) {
    const r = data[pix];
    const g = data[pix + 1];
    const b = data[pix + 2];
    // ITU-R BT.601 conversion
    const y = 0.299 * r + 0.587 * g + 0.114 * b;
    const cb = -0.168736 * r - 0.331264 * g + 0.5 * b + 128;
    const cr = 0.5 * r - 0.418688 * g - 0.081312 * b + 128;
    yChannel[i] = y;
    cbChannel[i] = cb;
    crChannel[i] = cr;
  }

  // Build payload bits
  const payloadWithHeader = makePayload(payload);
  const bits: number[] = [];
  for (let i = 0; i < payloadWithHeader.length; i++) {
    const byte = payloadWithHeader[i];
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  }
  // We'll store payload length (32 bits) then bits
  const lenBits: number[] = [];
  const payloadLen = payloadWithHeader.length;
  for (let i = 31; i >= 0; i--) lenBits.push((payloadLen >> i) & 1);
  const allBits = lenBits.concat(bits);

  // DCT helpers (8x8)
  function dct8(block: number[][]) {
    const N = 8;
    const F: number[][] = Array.from({ length: 8 }, () => Array(8).fill(0));
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
  function idct8(F: number[][]) {
    const N = 8;
    const block: number[][] = Array.from({ length: 8 }, () => Array(8).fill(0));
    for (let x = 0; x < N; x++) {
      for (let y = 0; y < N; y++) {
        let sum = 0;
        for (let u = 0; u < N; u++) {
          for (let v = 0; v < N; v++) {
            const cu = u === 0 ? 1 / Math.sqrt(2) : 1;
            const cv = v === 0 ? 1 / Math.sqrt(2) : 1;
            sum +=
              cu *
              cv *
              F[u][v] *
              Math.cos(((2 * x + 1) * u * Math.PI) / (2 * N)) *
              Math.cos(((2 * y + 1) * v * Math.PI) / (2 * N));
          }
        }
        block[x][y] = 0.25 * sum;
      }
    }
    return block;
  }

  let bitIdx = 0;
  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);
  if (blocksX * blocksY * 1 < allBits.length) {
    throw new Error("Image too small for DCT embedding of this payload");
  }

  for (let by = 0; by < blocksY && bitIdx < allBits.length; by++) {
    for (let bx = 0; bx < blocksX && bitIdx < allBits.length; bx++) {
      // extract 8x8 block for Y channel
      const block: number[][] = Array.from({ length: 8 }, () =>
        Array(8).fill(0),
      );
      for (let i = 0; i < 8; i++) {
        for (let j = 0; j < 8; j++) {
          const px = bx * 8 + j;
          const py = by * 8 + i;
          block[i][j] = yChannel[py * width + px] - 128; // shift
        }
      }
      const F = dct8(block);
      const targetU = 1,
        targetV = 0;
      let coeff = F[targetU][targetV];

      const q = Math.round(coeff);
      const desiredBit = allBits[bitIdx++];
      let newQ = (q & ~1) | desiredBit;
      if (newQ !== q) {
        F[targetU][targetV] = newQ;
      } else {
        F[targetU][targetV] = q;
      }
      const inv = idct8(F);
      for (let i = 0; i < 8; i++) {
        for (let j = 0; j < 8; j++) {
          const px = bx * 8 + j;
          const py = by * 8 + i;
          const val = inv[i][j] + 128;
          const clamped = Math.max(0, Math.min(255, Math.round(val)));
          yChannel[py * width + px] = clamped;
        }
      }
    }
  }

  for (let i = 0, pix = 0; i < width * height; i++, pix += 4) {
    const y = yChannel[i];
    const cb = cbChannel[i] - 128;
    const cr = crChannel[i] - 128;
    let r = y + 1.402 * cr;
    let g = y - 0.344136 * cb - 0.714136 * cr;
    let b = y + 1.772 * cb;
    r = Math.max(0, Math.min(255, Math.round(r)));
    g = Math.max(0, Math.min(255, Math.round(g)));
    b = Math.max(0, Math.min(255, Math.round(b)));
    data[pix] = r;
    data[pix + 1] = g;
    data[pix + 2] = b;
  }

  const encoded = jpeg.encode({ data, width, height }, 90);
  return Buffer.from(encoded.data);
}

async function embedDataToFile(
  fileBuffer: Buffer,
  ext: string,
  method: Method,
  payload: Buffer,
) {
  if (!method) throw new Error("No steganography method selected");
  if (method === "lsb") {
    // Prevent attempting LSB embedding on JPEG hosts; LSB is only safe on
    // lossless formats (PNG/BMP). Provide a clear error so the caller
    // and UI can present the right guidance.
    const maybeIsJpeg =
      (ext || "").toLowerCase() === ".jpg" ||
      (ext || "").toLowerCase() === ".jpeg" ||
      fileBuffer.slice(0, 2).toString("hex") === "ffd8";
    if (maybeIsJpeg) {
      throw new Error(
        "LSB embedding is not supported for JPEG images. Use 'dct' method for JPEG hosts.",
      );
    }
    return await embedLSBImage(fileBuffer, payload, ext);
  } else if (method === "dct") {
    const maybeIsJpeg =
      ext.toLowerCase() === ".jpg" ||
      ext.toLowerCase() === ".jpeg" ||
      fileBuffer.slice(0, 2).toString("hex") === "ffd8";
    if (!maybeIsJpeg)
      throw new Error(
        "DCT embedding is currently only supported for JPEG images",
      );
    return await embedDCTInJpeg(fileBuffer, payload);
  }
  throw new Error("Unsupported steganography method");
}

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

async function processEncoding() {
  if (!state.uploadedFile) {
    state.error = "No file selected";
    state.screen = "complete";
    return;
  }
  if (!state.method) {
    state.error = "No steganography method selected";
    state.screen = "complete";
    return;
  }

  state.screen = "processing";
  state.progress = 0;
  state.intermediateWritten = false;
  state.outputPath = makeOutputPath(state.uploadedFile.path);

  try {
    const fileBuffer = fs.readFileSync(state.uploadedFile.path);

    const { salt, iv, encrypted } = encryptMessage(
      state.message,
      state.password || Buffer.alloc(0),
    );
    const payload = Buffer.concat([salt, iv, encrypted]);

    for (let p = 0; p <= 100; p++) {
      state.progress = p;

      if (p === 66 && !state.intermediateWritten) {
        try {
          // Attempt an intermediate write using stego method
          const midBuf = await embedDataToFile(
            fileBuffer,
            state.uploadedFile.ext || path.extname(state.uploadedFile.path),
            state.method,
            payload,
          ).catch((e) => {
            // If embedding fails during intermediate, write generic fallback
            return embedGeneric(fileBuffer, payload);
          });
          fs.writeFileSync(state.outputPath, midBuf);
          state.intermediateWritten = true;
        } catch (e) {
          state.error =
            "Failed to write intermediate file: " + (e as Error).message;
        }
      }
      await sleep(40);

      if ((global as any).showSection) {
        try {
          (global as any).showSection("Encode");
        } catch {}
      }
    }

    // Final embedding
    try {
      const finalBuf = await embedDataToFile(
        fileBuffer,
        state.uploadedFile.ext || path.extname(state.uploadedFile.path),
        state.method,
        payload,
      );
      fs.writeFileSync(state.outputPath, finalBuf);
    } catch (e) {
      // If embedding failed, fallback to generic append
      state.error =
        "Embedding failed, using fallback append: " + (e as Error).message;
      const final = embedGeneric(fileBuffer, payload);
      fs.writeFileSync(state.outputPath, final);
    }

    try {
      const dest = downloadToDownloads();
      if (!dest) {
        // couldn't copy to Downloads; the encoded file remains at state.outputPath
      }
    } catch (e) {
      state.error = "Failed to copy to Downloads: " + (e as Error).message;
    }

    state.progress = 100;
    state.screen = "complete";
    secureWipeBuffer(state.password);
    state.password = null;
  } catch (e) {
    state.error = "Processing failed: " + (e as Error).message;
    state.screen = "complete";
  }
}

function downloadToDownloads() {
  if (!state.outputPath || !fs.existsSync(state.outputPath)) return null;
  try {
    const downloads = path.join(os.homedir(), "Downloads");
    if (!fs.existsSync(downloads)) fs.mkdirSync(downloads, { recursive: true });
    const dest = path.join(downloads, path.basename(state.outputPath));
    fs.copyFileSync(state.outputPath, dest);
    state.downloadedPath = dest;
    return dest;
  } catch (e) {
    state.error = "Download failed: " + (e as Error).message;
    return null;
  }
}

function renderUpload() {
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push("> Press Enter to Upload");
  lines.push("");
  return lines.join("\n");
}

function renderMethodSelection() {
  const marker = "[[LEFT_ALIGN]]\n";
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  const hint = chalk.dim(" » Space to select. Enter to submit.");
  lines.push(
    "                        Which method would you like to use? " + hint,
  );
  lines.push("");
  const sel = state.method || "lsb";
  const lsbMark = sel === "lsb" ? chalk.hex("#f97316")("(*)") : "( )";
  const dctMark = sel === "dct" ? chalk.hex("#f97316")("(*)") : "( )";
  lines.push("                        " + lsbMark + " LSB Insertion");
  lines.push(
    "                        " + dctMark + " DCT Coefficient Manipulation",
  );
  lines.push("");
  return marker + lines.join("\n");
}

function renderMessage() {
  const vpWidth = Math.max(40, term.width || 80);
  const boxWidth = Math.min(96, Math.max(40, Math.floor(vpWidth * 0.6)));
  const boxHeight = Math.min(
    16,
    Math.max(6, Math.floor((term.height || 24 - 8) / 2)),
  );

  const currentBytes = Buffer.from(state.inputBuffer || "", "utf8").length;

  let capacityBytes: number | null = null;
  if (state.uploadedFile && state.method) {
    try {
      const fileBuffer = fs.readFileSync(state.uploadedFile.path);
      const ext = (state.uploadedFile.ext || "").toLowerCase();
      if (state.method === "lsb") {
        try {
          const PNG = require("pngjs").PNG as any;
          const png = PNG.sync.read(fileBuffer);
          const capacityBits = png.width * png.height * 3;
          capacityBytes = Math.max(0, Math.floor((capacityBits - 32) / 8));
        } catch {
          try {
            const jpeg = require("jpeg-js") as any;
            const raw = jpeg.decode(fileBuffer, { useTArray: true }) as {
              width: number;
              height: number;
            };
            const capacityBits = raw.width * raw.height * 3;
            capacityBytes = Math.max(0, Math.floor((capacityBits - 32) / 8));
          } catch {
            // fallback to conservative estimate based on file size
            capacityBytes = Math.max(0, Math.floor(fileBuffer.length / 16));
          }
        }
      } else if (state.method === "dct") {
        // DCT embedding (JPEG) - 1 bit per 8x8 block (approx)
        try {
          // eslint-disable-next-line @typescript-eslint/no-var-requires
          const jpeg = require("jpeg-js") as any;
          const raw = jpeg.decode(fileBuffer, { useTArray: true }) as {
            width: number;
            height: number;
          };
          const blocksX = Math.floor(raw.width / 8);
          const blocksY = Math.floor(raw.height / 8);
          const capacityBits = blocksX * blocksY; // 1 bit per block
          capacityBytes = Math.max(0, Math.floor(capacityBits / 8));
        } catch {
          // unable to decode; fallback conservative
          capacityBytes = Math.max(0, Math.floor(fileBuffer.length / 64));
        }
      }
    } catch {
      capacityBytes = null;
    }
  }

  const raw = state.inputBuffer || "";
  const rows = raw.split("\n");
  const startRow = Math.max(0, rows.length - boxHeight);
  const visibleRows = rows.slice(startRow, startRow + boxHeight);

  const lines: string[] = [];
  lines.push("");
  lines.push("");
  // Show live byte count and capacity (if known)
  if (capacityBytes === null) {
    lines.push(
      "Enter secret message " +
        chalk.hex("#f97316")(`(${currentBytes} / ? b):`),
    );
  } else {
    lines.push(
      "Enter secret message " +
        chalk.hex("#f97316")(`(${currentBytes} / ${capacityBytes} b):`),
    );
  }
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
  lines.push("Enter password :");
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
  const barWidth = Math.min(
    44,
    Math.max(24, Math.floor((term.width || 80) * 0.28)),
  );
  const rows: string[] = [];

  const globalPct = Math.max(0, Math.min(100, Math.round(state.progress || 0)));

  for (let i = 0; i < labels.length; i++) {
    const segStart = i * (100 / labels.length);
    const segEnd = (i + 1) * (100 / labels.length);
    let localPct = 0;
    if (globalPct <= segStart) localPct = 0;
    else if (globalPct >= segEnd) localPct = 100;
    else
      localPct = Math.round(
        ((globalPct - segStart) / (segEnd - segStart)) * 100,
      );

    const filled = Math.round((localPct / 100) * barWidth);
    const equals = "=".repeat(filled);
    const coloredEquals = chalk.hex("#FFA500")(equals);
    const bar =
      "[" + coloredEquals + " ".repeat(Math.max(0, barWidth - filled)) + "]";
    rows.push(
      labels[i].padEnd(11) +
        " : " +
        bar +
        " " +
        String(localPct).padStart(3) +
        "%",
    );
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
    lines.push("");
    lines.push(
      chalk.yellow(
        "If embedding failed due to missing libraries, install 'pngjs' and/or 'jpeg-js' and try again.",
      ),
    );
  }
  lines.push("");
  lines.push("Press any key to start over");
  return lines.join("\n");
}

export function handleEncodeInput(key: string, data?: any): boolean {
  // Robust Enter detection: some terminals/clients send different key names or embed the enter
  // as a codepoint or as '\r' / '\n'. Accept a wider set of possibilities so ENTER works
  // reliably on the method selection screen and elsewhere.
  const isEnter =
    key === "ENTER" ||
    key === "RETURN" ||
    key === "KP_ENTER" ||
    key === "CR" ||
    key === "LF" ||
    key === "\r" ||
    key === "\n" ||
    key === "ENTER_KEY" ||
    (data &&
      (data.key === "Enter" ||
        data.key === "RETURN" ||
        data.key === "EnterKey" ||
        data.codepoint === 13 ||
        data.codepoint === 10));

  if (key === "ESCAPE") {
    secureWipeBuffer(state.password);
    state = {
      screen: "upload",
      method: null,
      uploadedFile: null,
      message: "",
      password: null,
      inputBuffer: "",
      outputPath: "",
      progress: 0,
      intermediateWritten: false,
    };
    if ((global as any).showSection)
      try {
        (global as any).showSection("Encode");
      } catch {}
    return true;
  }

  if (state.screen === "upload" && isEnter) {
    openFilePicker().then((filePath) => {
      if (filePath) {
        try {
          const stats = fs.statSync(filePath);
          state.uploadedFile = {
            path: filePath,
            name: path.basename(filePath),
            size: stats.size,
            ext: path.extname(filePath),
          };
          state.screen = "method";
          state.inputBuffer = "";
          state.progress = 0;
          secureWipeBuffer(state.password);
          state.password = null;
          if ((global as any).showSection)
            try {
              (global as any).showSection("Encode");
            } catch {}
        } catch {
          // ignore
        }
      } else {
        // user cancelled
      }
    });
    return true;
  }

  if (state.screen === "method") {
    // Normalize key and accept many representations so ENTER reliably confirms selection.
    // Some terminals provide different properties (data.key, data.code, data.keyCode, charCode, codepoint).
    const normalizedKey =
      typeof key === "string" && key ? key.toString().toUpperCase() : "";
    const dataKey =
      data && (data.key || data.name || data.code)
        ? String(data.key || data.name || data.code)
        : null;

    // Broad enter detection: normalize multiple possible signals for Enter/Return
    const isEnterLocal =
      // explicit normalized key names
      normalizedKey === "ENTER" ||
      normalizedKey === "RETURN" ||
      normalizedKey === "KP_ENTER" ||
      normalizedKey === "ENTER_KEY" ||
      normalizedKey === "RETURN_KEY" ||
      // control characters
      normalizedKey === "CR" ||
      normalizedKey === "LF" ||
      normalizedKey === "\r" ||
      normalizedKey === "\n" ||
      normalizedKey === "\u000d" ||
      normalizedKey === "\u000a" ||
      // data.key variants (some terminals set data.key)
      (data &&
        (data.key === "Enter" ||
          data.key === "RETURN" ||
          data.key === "EnterKey" ||
          data.key === "Return")) ||
      // data.code variants (e.g., 'Enter')
      (data && (data.code === "Enter" || data.code === "NumpadEnter")) ||
      // numeric code variants
      (data &&
        (data.keyCode === 13 ||
          data.which === 13 ||
          data.charCode === 13 ||
          data.codepoint === 13 ||
          data.codepoint === 10)) ||
      // fallback: single-character key whose charCode is CR or LF
      (typeof key === "string" &&
        key.length === 1 &&
        (key.charCodeAt(0) === 13 || key.charCodeAt(0) === 10));

    if (normalizedKey === "1") {
      // set selection to LSB (do not auto-confirm)
      state.method = "lsb";
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    } else if (normalizedKey === "2") {
      // set selection to DCT (do not auto-confirm)
      state.method = "dct";
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    } else if (normalizedKey === " " || normalizedKey === "SPACE") {
      // Toggle selection between LSB and DCT without advancing to message screen
      if (state.method === "lsb") state.method = "dct";
      else state.method = "lsb";
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    } else if (isEnterLocal) {
      // Confirm selection (default to LSB if none chosen)
      if (!state.method) state.method = "lsb";
      state.screen = "message";
      state.inputBuffer = "";
      state.progress = 0;
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    } else if (normalizedKey === "ESCAPE") {
      state.method = null;
      state.screen = "upload";
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
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
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    }

    if (isEnter) {
      state.inputBuffer = state.inputBuffer + "\n";
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    }

    if (key === "BACKSPACE" || key === "DELETE") {
      state.inputBuffer = state.inputBuffer.slice(0, -1);
      return true;
    }

    if (key.length === 1) {
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
          if ((global as any).showSection)
            try {
              (global as any).showSection("Encode");
            } catch {}
        });
      }, 80);
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    }
    if (key === "BACKSPACE" || key === "DELETE") {
      state.inputBuffer = state.inputBuffer.slice(0, -1);
      return true;
    }
    if (key.length === 1 && state.inputBuffer.length < 256) {
      state.inputBuffer += key;
      return true;
    }
    return false;
  }

  if (state.screen === "processing") {
    if (
      (key === "d" || key === "D") &&
      (state.intermediateWritten || state.progress >= 100)
    ) {
      const dest = downloadToDownloads();
      if (dest && (global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    }
    return true; // ignore other keys while processing
  }

  if (state.screen === "complete") {
    if (key === "d" || key === "D") {
      const dest = downloadToDownloads();
      if (dest && (global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    }
    if (key && key.length > 0) {
      secureWipeBuffer(state.password);
      state = {
        screen: "upload",
        method: null,
        uploadedFile: null,
        message: "",
        password: null,
        inputBuffer: "",
        outputPath: "",
        progress: 0,
        intermediateWritten: false,
      };
      if ((global as any).showSection)
        try {
          (global as any).showSection("Encode");
        } catch {}
      return true;
    }
    return true;
  }

  return false;
}

export default function Encode(): string {
  switch (state.screen) {
    case "upload":
      return renderUpload();
    case "method":
      return renderMethodSelection();
    case "message":
      return renderMessage();
    case "password":
      return renderPassword();
    case "processing":
      return renderProcessing();
    case "complete":
      return renderComplete();
    default:
      return renderUpload();
  }
}

export function getEncodeState() {
  return state;
}
