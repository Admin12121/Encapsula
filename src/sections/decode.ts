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
  password: string;
  progress: number; 
  decryptedMessage?: string | null;
  error?: string | null;
}

let state: State = {
  screen: "upload",
  uploadedFile: null,
  inputBuffer: "",
  password: "",
  progress: 0,
};


function deriveKey(password: string) {
  const salt = crypto.createHash("sha256").update("encapsula-salt").digest();
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha512");
}

function decryptPayload(payload: Buffer, password: string) {
  if (payload.length < 16) throw new Error("Payload too short");
  const iv = payload.slice(0, 16);
  const encrypted = payload.slice(16);
  const key = deriveKey(password);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const out = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return out.toString("utf8");
}

function extractGeneric(fileBuffer: Buffer): Buffer | null {
  try {
    const marker = Buffer.from("<<ENCAPSULA_HIDDEN>>", "utf8");
    const startIndex = fileBuffer.indexOf(marker);
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
        const extracted = extractGeneric(fileBuffer);
        if (!extracted || extracted.length < 16) {
          state.error = "No hidden data found or data corrupted";
          state.screen = "complete";
          if ((global as any).showSection) {
            try {
              (global as any).showSection("Decode");
            } catch {}
          }
          return;
        }

        try {
          const decrypted = decryptPayload(extracted, state.password || "");
          state.decryptedMessage = decrypted;
          state.error = null;
        } catch (e) {
          state.error = "Incorrect password or corrupted data";
          state.decryptedMessage = null;
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
    state.password = "";
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
    state = {
      screen: "upload",
      uploadedFile: null,
      inputBuffer: "",
      password: "",
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
      state.password = state.inputBuffer;
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
      state = {
        screen: "upload",
        uploadedFile: null,
        inputBuffer: "",
        password: "",
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
