import termkit from "terminal-kit";
import { COLORS } from "./data";

const term = termkit.terminal;

export async function startupProgress() {
  term.clear();

  const steps = [
    "Initializing portfolio...",
    "Loading terminal interface...",
    "Setting up navigation...",
    "Loading sections...",
    "Ready to launch!",
  ];

  const barWidth = Math.min(60, term.width - 8);
  const baseY = Math.floor(term.height / 2) - 2;

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const xStep = Math.floor((term.width - step.length) / 2);
    term.moveTo(1, baseY).eraseLine();
    term.moveTo(xStep, baseY);
    term.colorRgbHex(COLORS.secondary, step);

    const filled = Math.floor(((i + 1) / steps.length) * barWidth);
    const bar = "█".repeat(filled) + "^R░".repeat(barWidth - filled);
    const xBar = Math.floor((term.width - barWidth) / 2);
    term.moveTo(1, baseY + 2).eraseLine();
    term.moveTo(xBar, baseY + 2);
    term.colorRgbHex(COLORS.primary, bar);

    await new Promise((r) => setTimeout(r, 600));
  }

  await new Promise((r) => setTimeout(r, 700));
  term.clear();
}

export async function exitProgress() {
  term.fullscreen(false);
  term.clear();

  const steps = [
    "Closing connections",
    "Saving state",
    "Clearing cache",
    "Finalizing shutdown",
  ];

  const barWidth = Math.min(50, term.width - 8);
  const baseY = Math.floor(term.height / 2) - 2;

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const xStep = Math.floor((term.width - step.length) / 2);
    term.moveTo(1, baseY).eraseLine();
    term.moveTo(xStep, baseY);
    term.colorRgbHex(COLORS.secondary, step);

    const filled = Math.floor(((i + 1) / steps.length) * barWidth);
    const bar = "█".repeat(filled) + "^R░".repeat(barWidth - filled);
    const xBar = Math.floor((term.width - barWidth) / 2);
    term.moveTo(1, baseY + 2).eraseLine();
    term.moveTo(xBar, baseY + 2);
    term.colorRgbHex(COLORS.primary, bar);

    await new Promise((r) => setTimeout(r, 700));
  }

  term.clear();
  process.exit();
}
