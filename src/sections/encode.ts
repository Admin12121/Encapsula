import chalk from "chalk";
import termkit from "terminal-kit";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { execFileSync } from "child_process";
import * as os from "os";

const term = termkit.terminal;

/*
  Encode section
  - Upload -> Message (multi-line textarea) -> Password -> Processing -> Complete
  - Message textarea supports multiple lines (ENTER inserts newline). Finish with Ctrl+S.
  - Progress block laid out as three vertical lines:
      Uploading: [...]
      Encrypting: [...]
      Finalizing: [...]
    and a centered "Press D to Download the file" below (the host frame centers blocks).
*/

// Types & State
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
  uploadedFile: null,
  message: "",
  password: null,
  inputBuffer: "",
  outputPath: "",
  progress: 0,
  intermediateWritten: false,
};

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

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

async function processEncoding() {
  if (!state.uploadedFile) {
    state.error = "No file selected";
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
          const mid = embedGeneric(fileBuffer, payload);
          fs.writeFileSync(state.outputPath, mid);
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

    const final = embedGeneric(fileBuffer, payload);
    fs.writeFileSync(state.outputPath, final);

    try {
      const dest = downloadToDownloads();
      if (!dest) {
        // couldn't copy to Downloads; the encoded file remains at state.outputPath
        // state.downloadedPath will remain undefined in this case
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

function renderMessage() {
  const vpWidth = Math.max(40, term.width || 80);
  const boxWidth = Math.min(96, Math.max(40, Math.floor(vpWidth * 0.6)));
  const boxHeight = Math.min(
    16,
    Math.max(6, Math.floor((term.height || 24 - 8) / 2)),
  );

  const raw = state.inputBuffer || "";
  const rows = raw.split("\n");
  const startRow = Math.max(0, rows.length - boxHeight);
  const visibleRows = rows.slice(startRow, startRow + boxHeight);

  const lines: string[] = [];
  lines.push("");
  lines.push("");
  lines.push("Enter secret message (Ctrl+S to finish):");
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
  lines.push("");
  lines.push("Press any key to start over");
  return lines.join("\n");
}

export function handleEncodeInput(key: string, data?: any): boolean {
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
          state.screen = "message";
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
