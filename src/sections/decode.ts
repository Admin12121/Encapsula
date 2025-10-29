import chalk from "chalk";
import termkit from "terminal-kit";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { execFileSync } from "child_process";
import * as os from "os";

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
  decryptedMessage?: string | null;
  error?: string | null;
}

let state: State = {
  screen: "upload",
  uploadedFile: null,
  inputBuffer: "",
  password: null,
  progress: 0,
};

function secureWipeBuffer(buffer: Buffer | null) {
  if (buffer) {
    buffer.fill(0);
  }
}

function deriveKey(password: string, salt: Buffer) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha512");
}

export function decryptPayload(payload: Buffer, password: Buffer) {
  if (payload.length < 48) throw new Error("Payload too short"); // 32 bytes salt + 16 bytes IV
  const salt = payload.slice(0, 32);
  const iv = payload.slice(32, 48);
  const encrypted = payload.slice(48);
  const key = deriveKey(password.toString("utf8"), salt);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const out = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return out.toString("utf8");
}

export function extractGeneric(fileBuffer: Buffer): Buffer | null {
  try {
    const marker = Buffer.from("<<ENCAPSULA_HIDDEN>>", "utf8");
    // Prefer the last occurrence of the marker so appended payloads at EOF are detected
    // and accidental occurrences earlier in the file do not cause incorrect extraction.
    const startIndex = fileBuffer.lastIndexOf(marker);
    if (startIndex === -1) return null;

    const lengthStart = startIndex + marker.length;
    if (lengthStart + 4 > fileBuffer.length) return null;
    const dataLength = fileBuffer.readUInt32BE(lengthStart);
    if (dataLength <= 0 || dataLength > 10 * 1024 * 1024) return null;

    const dataStart = lengthStart + 4;
    const dataEnd = dataStart + dataLength;
    if (dataEnd > fileBuffer.length) return null;

    return fileBuffer.slice(dataStart, dataEnd);
  } catch {
    return null;
  }
}

/*
  LSB extractor: reconstructs a sequence of bits from R,G,B LSBs in pixel order
  Supports PNG (pngjs), JPEG (jpeg-js decoded RGBA), and simple BMP uncompressed.
  Embedding format used by embedLSBImage: first 32 bits = payload byte length (big-endian),
  followed by payload bytes (which for LSB/DCT embedding contains version+len+payload).
*/
export function extractLSB(fileBuffer: Buffer): Buffer | null {
  try {
    // PNG path
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const PNG = require("pngjs").PNG as any;
      const png = PNG.sync.read(fileBuffer);
      const { width, height, data } = png; // data is RGBA
      const totalPixels = width * height;
      const capacityBits = totalPixels * 3;
      // Read bits sequentially from R,G,B channels
      const readBits = (neededBits: number) => {
        const bits: number[] = [];
        let bitIdx = 0;
        for (let i = 0; i < data.length && bitIdx < neededBits; i += 4) {
          if (bitIdx < neededBits) (bits.push(data[i] & 1), bitIdx++);
          if (bitIdx < neededBits) (bits.push(data[i + 1] & 1), bitIdx++);
          if (bitIdx < neededBits) (bits.push(data[i + 2] & 1), bitIdx++);
        }
        return bits;
      };

      // Get length (first 32 bits)
      const lenBits = readBits(32);
      if (lenBits.length < 32) return null;
      let payloadLen = 0;
      for (let i = 0; i < 32; i++)
        payloadLen = (payloadLen << 1) | (lenBits[i] & 1);
      if (payloadLen <= 0 || payloadLen > Math.floor((capacityBits - 32) / 8))
        return null;

      // Read payloadLen * 8 bits (starting after the first 32)
      const allBits: number[] = [];
      // Instead of re-reading the first 32 again, iterate and collect starting from 0 but skip 32 bits
      let needBits = payloadLen * 8 + 32;
      let collected: number[] = [];
      let bIdx = 0;
      for (let i = 0; i < data.length && bIdx < needBits; i += 4) {
        if (bIdx < needBits) (collected.push(data[i] & 1), bIdx++);
        if (bIdx < needBits) (collected.push(data[i + 1] & 1), bIdx++);
        if (bIdx < needBits) (collected.push(data[i + 2] & 1), bIdx++);
      }
      if (collected.length < needBits) return null;
      const payloadBits = collected.slice(32); // skip first 32 length bits
      const bytes = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        let val = 0;
        for (let b = 0; b < 8; b++)
          val = (val << 1) | (payloadBits[i * 8 + b] & 1);
        bytes[i] = val;
      }
      return bytes;
    } catch (e) {
      // fall through to JPEG/BMP
    }

    try {
      // JPEG path (decode to RGBA using jpeg-js)
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const jpeg = require("jpeg-js") as any;
      const raw = jpeg.decode(fileBuffer, { useTArray: true }) as {
        width: number;
        height: number;
        data: Buffer | Uint8Array;
      };
      if (!raw || !raw.data) throw new Error("Failed to decode JPEG");
      const { width, height } = raw;
      const data = Buffer.from(raw.data);
      const totalPixels = width * height;
      const capacityBits = totalPixels * 3;

      // read as above
      const needLenBits = 32;
      const collectedAll: number[] = [];
      for (let px = 0; px < width * height; px++) {
        const base = px * 4;
        collectedAll.push(data[base] & 1);
        collectedAll.push(data[base + 1] & 1);
        collectedAll.push(data[base + 2] & 1);
      }
      if (collectedAll.length < 32) return null;
      let payloadLen = 0;
      for (let i = 0; i < 32; i++)
        payloadLen = (payloadLen << 1) | (collectedAll[i] & 1);
      if (payloadLen <= 0 || payloadLen > Math.floor((capacityBits - 32) / 8))
        return null;
      const needBits = 32 + payloadLen * 8;
      if (collectedAll.length < needBits) return null;
      const payloadBits = collectedAll.slice(32, 32 + payloadLen * 8);
      const bytes = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        let val = 0;
        for (let b = 0; b < 8; b++)
          val = (val << 1) | (payloadBits[i * 8 + b] & 1);
        bytes[i] = val;
      }
      return bytes;
    } catch (e) {
      // fall through to BMP
    }

    // BMP fallback (simple uncompressed BMP 24/32bpp)
    try {
      if (fileBuffer.slice(0, 2).toString("ascii") === "BM") {
        const pixelOffset = fileBuffer.readUInt32LE(10);
        const bpp = fileBuffer.readUInt16LE(28);
        const bytesPerPixel = bpp / 8;
        if (bpp !== 24 && bpp !== 32) return null;
        const pixelData = Buffer.from(fileBuffer.slice(pixelOffset));
        const totalPixels = Math.floor(pixelData.length / bytesPerPixel);
        const capacityBits = totalPixels * 3;
        const collectedAll: number[] = [];
        for (let px = 0; px < totalPixels; px++) {
          const base = px * bytesPerPixel;
          // BMP order B,G,R
          collectedAll.push(pixelData[base + 2] & 1);
          collectedAll.push(pixelData[base + 1] & 1);
          collectedAll.push(pixelData[base] & 1);
        }
        if (collectedAll.length < 32) return null;
        let payloadLen = 0;
        for (let i = 0; i < 32; i++)
          payloadLen = (payloadLen << 1) | (collectedAll[i] & 1);
        if (payloadLen <= 0 || payloadLen > Math.floor((capacityBits - 32) / 8))
          return null;
        const needBits = 32 + payloadLen * 8;
        if (collectedAll.length < needBits) return null;
        const payloadBits = collectedAll.slice(32, 32 + payloadLen * 8);
        const bytes = Buffer.alloc(payloadLen);
        for (let i = 0; i < payloadLen; i++) {
          let val = 0;
          for (let b = 0; b < 8; b++)
            val = (val << 1) | (payloadBits[i * 8 + b] & 1);
          bytes[i] = val;
        }
        return bytes;
      }
    } catch (e) {
      // ignore
    }

    return null;
  } catch (e) {
    return null;
  }
}

/*
  DCT extractor (JPEG only):
  - Mirror the embedding process: iterate 8x8 Y blocks left-to-right, top-to-bottom
  - For each block compute DCT and read LSB of rounded coefficient at target (u=1,v=0)
  - First 32 bits represent payload length in bytes (big-endian), then read that many bytes.
*/
export function extractDCT(fileBuffer: Buffer): Buffer | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const jpeg = require("jpeg-js") as any;
    const raw = jpeg.decode(fileBuffer, { useTArray: true }) as {
      width: number;
      height: number;
      data: Buffer | Uint8Array;
    };
    if (!raw || !raw.data) return null;
    const { width, height } = raw;
    const rgba = Buffer.from(raw.data);

    // build Y channel
    const Y: number[][] = Array.from({ length: height }, () =>
      Array(width).fill(0),
    );
    let idx = 0;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const r = rgba[idx++];
        const g = rgba[idx++];
        const b = rgba[idx++];
        idx++;
        const yc = 0.299 * r + 0.587 * g + 0.114 * b;
        Y[y][x] = yc - 128; // shift to center
      }
    }

    const blocksX = Math.floor(width / 8);
    const blocksY = Math.floor(height / 8);
    const capacityBits = blocksX * blocksY;
    if (capacityBits < 32) return null; // at least should hold length

    // DCT helper (same as encoder)
    function dct8(block: number[][]) {
      const N = 8;
      const F: number[][] = Array.from({ length: N }, () => Array(N).fill(0));
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

    // read bits from blocks
    const bits: number[] = [];
    const targetU = 1,
      targetV = 0;
    for (let by = 0; by < blocksY; by++) {
      for (let bx = 0; bx < blocksX; bx++) {
        // extract 8x8 block
        const block: number[][] = Array.from({ length: 8 }, () =>
          Array(8).fill(0),
        );
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

    // need at least 32 bits for length
    if (bits.length < 32) return null;
    let payloadLen = 0;
    for (let i = 0; i < 32; i++) payloadLen = (payloadLen << 1) | (bits[i] & 1);
    if (payloadLen <= 0 || payloadLen > Math.floor((bits.length - 32) / 8)) {
      // if declared length not sensible, abort
      return null;
    }

    const neededBits = 32 + payloadLen * 8;
    if (bits.length < neededBits) return null;
    const payloadBits = bits.slice(32, 32 + payloadLen * 8);
    const bytes = Buffer.alloc(payloadLen);
    for (let i = 0; i < payloadLen; i++) {
      let val = 0;
      for (let b = 0; b < 8; b++)
        val = (val << 1) | (payloadBits[i * 8 + b] & 1);
      bytes[i] = val;
    }
    return bytes;
  } catch (e) {
    return null;
  }
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

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

function renderUpload() {
  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push("> Press Enter to Upload");
  lines.push("");
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
    const eq = "=".repeat(filled);
    const coloredEq = chalk.hex("#FFA500")(eq);
    const bar =
      "[" + coloredEq + " ".repeat(Math.max(0, barWidth - filled)) + "]";
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
  const msg = state.decryptedMessage || "";
  const rows = msg.split("\n");
  rows.forEach((r) => lines.push(r));
  lines.push("");
  lines.push("Press any key to decode another file");
  return lines.join("\n");
}

async function processDecoding() {
  if (!state.uploadedFile) {
    state.error = "No file selected";
    state.screen = "complete";
    if ((global as any).showSection) {
      try {
        (global as any).showSection("Decode");
      } catch {}
    }
    return;
  }

  state.screen = "processing";
  state.progress = 0;
  state.decryptedMessage = null;
  state.error = null;

  try {
    const fileBuffer =
      state.uploadedFile.buffer || fs.readFileSync(state.uploadedFile.path);

    for (let p = 0; p <= 100; p++) {
      state.progress = p;

      if (p === 66) {
        // Try extractors in order and attempt decryption for each result.
        // Continue to next extractor if extraction or decryption fails.
        const extractorList: {
          name: string;
          fn: (buf: Buffer) => Buffer | null;
        }[] = [
          // Check for appended payload first (fast, reliable fallback)
          { name: "APPEND", fn: extractGeneric },
          { name: "DCT", fn: extractDCT },
          { name: "LSB", fn: extractLSB },
        ];

        const attempts: string[] = [];
        const errors: string[] = [];
        let success = false;

        for (const extractor of extractorList) {
          attempts.push(extractor.name);
          let extracted: Buffer | null = null;
          try {
            extracted = extractor.fn(fileBuffer);
          } catch (er) {
            extracted = null;
          }

          if (!extracted || extracted.length === 0) {
            errors.push(`${extractor.name}: no payload extracted`);
            continue;
          }

          let payloadBuf: Buffer | null = null;
          let declaredLen: number | null = null;
          if (extracted.length >= 8) {
            try {
              const version = extracted.readUInt32BE(0);
              const maybeLen = extracted.readUInt32BE(4);
              declaredLen = maybeLen;
              // If version is 1 and length is sensible, unwrap the payload
              if (
                version === 1 &&
                Number.isFinite(maybeLen) &&
                maybeLen > 0 &&
                maybeLen <= 10 * 1024 * 1024 &&
                extracted.length >= 8 + maybeLen
              ) {
                // Wrapped payload: version(4) + len(4) + [salt+iv+encrypted]
                payloadBuf = extracted.slice(8, 8 + maybeLen);
              } else {
                // Unwrapped payload (generic append): salt+iv+encrypted directly
                payloadBuf = extracted;
              }
            } catch {
              payloadBuf = extracted;
            }
          } else {
            payloadBuf = extracted;
          }

          if (!payloadBuf || payloadBuf.length < 48) {
            errors.push(
              `${extractor.name}: extracted payload too small (extractedLen=${extracted.length}, declaredLen=${
                declaredLen === null ? "n/a" : declaredLen
              }, payloadLen=${payloadBuf ? payloadBuf.length : 0})`,
            );
            continue;
          }

          // Try decrypting this candidate payload
          try {
            const decrypted = decryptPayload(
              payloadBuf,
              state.password || Buffer.alloc(0),
            );
            state.decryptedMessage =
              `[detected: ${extractor.name}]\n` + decrypted;
            state.error = null;
            success = true;
            break; // done
          } catch (e) {
            errors.push(`${extractor.name}: decryption failed`);
            // continue to next extractor
            continue;
          }
        }

        if (!success) {
          state.error = `Failed to extract/decrypt (tried: ${attempts.join(
            ", ",
          )}). Details: ${errors.join("; ")}`;
          state.screen = "complete";
          if ((global as any).showSection) {
            try {
              (global as any).showSection("Decode");
            } catch {}
          }
          return;
        }
      }

      await sleep(30);

      if ((global as any).showSection) {
        try {
          (global as any).showSection("Decode");
        } catch {}
      }
    }

    state.progress = 100;
    state.screen = "complete";
    secureWipeBuffer(state.password);
    state.password = null;
    if ((global as any).showSection) {
      try {
        (global as any).showSection("Decode");
      } catch {}
    }
  } catch (e) {
    state.error = "Processing failed: " + (e as Error).message;
    state.screen = "complete";
    if ((global as any).showSection) {
      try {
        (global as any).showSection("Decode");
      } catch {}
    }
  }
}

export function handleDecodeInput(key: string, data?: any): boolean {
  const isEnter =
    key === "ENTER" ||
    key === "RETURN" ||
    key === "KP_ENTER" ||
    (data && (data.codepoint === 13 || data.codepoint === 10));

  if (key === "ESCAPE") {
    secureWipeBuffer(state.password);
    state = {
      screen: "upload",
      uploadedFile: null,
      inputBuffer: "",
      password: null,
      progress: 0,
    };
    if ((global as any).showSection) {
      try {
        (global as any).showSection("Decode");
      } catch {}
    }
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
            buffer: fs.readFileSync(filePath),
          };
          state.screen = "password";
          state.inputBuffer = "";
          state.progress = 0;
          secureWipeBuffer(state.password);
          state.password = null;
          if ((global as any).showSection) {
            try {
              (global as any).showSection("Decode");
            } catch {}
          }
        } catch {
          state.error = "Failed to read selected file";
          if ((global as any).showSection) {
            try {
              (global as any).showSection("Decode");
            } catch {}
          }
        }
      } else {
        // user cancelled the dialog - do nothing (same as Encode)
      }
    });
    return true;
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
          if ((global as any).showSection) {
            try {
              (global as any).showSection("Decode");
            } catch {}
          }
        });
      }, 80);
      if ((global as any).showSection) {
        try {
          (global as any).showSection("Decode");
        } catch {}
      }
      return true;
    }
    if (key === "BACKSPACE" || key === "DELETE") {
      state.inputBuffer = state.inputBuffer.slice(0, -1);
      if ((global as any).showSection) {
        try {
          (global as any).showSection("Decode");
        } catch {}
      }
      return true;
    }
    if (key.length === 1 && state.inputBuffer.length < 256) {
      state.inputBuffer += key;
      if ((global as any).showSection) {
        try {
          (global as any).showSection("Decode");
        } catch {}
      }
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
      };
      if ((global as any).showSection) {
        try {
          (global as any).showSection("Decode");
        } catch {}
      }
      return true;
    }
    return true;
  }

  return false;
}

export default function Decode(): string {
  switch (state.screen) {
    case "upload":
      return renderUpload();
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

export function getDecodeState() {
  return state;
}
