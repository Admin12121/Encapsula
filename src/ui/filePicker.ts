import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";

/**
 * Open a native Windows file picker using PowerShell + Windows.Forms.
 * Returns the selected absolute path, or null if canceled.
 */
export async function pickFileWindows(): Promise<string | null> {
  const ps = `
Add-Type -AssemblyName System.Windows.Forms
$dlg = New-Object System.Windows.Forms.OpenFileDialog
$dlg.Title = "Select a file"
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
      { encoding: "utf8", windowsHide: true },
    )
      .toString()
      .trim();
    try { fs.unlinkSync(tmp); } catch {}
    if (out && fs.existsSync(out)) return out;
    return null;
  } catch {
    try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch {}
    return null;
  }
}

/**
  Returns:
    - a real absolute path when selected (Windows)
    - the string "__PROMPT__" when the caller should show a path input prompt (Linux/macOS)
    - null if user canceled
*/
export async function pickCarrierFile(): Promise<string | null> {
  if (process.platform === "win32") {
    return await pickFileWindows();
  }
  return "__PROMPT__";
}