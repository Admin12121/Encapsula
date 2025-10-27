#!/usr/bin/env node

import * as termkit from "terminal-kit";
import {
  initTerminal,
  drawTaskbar,
  handleTerminalInput,
  setSelectedTab,
  getSelectedTab,
  getViewport,
} from "./terminal";

import showHome from "./sections/home";
import Encode, { handleEncodeInput } from "./sections/encode";
import Decode, { handleDecodeInput } from "./sections/decode";
import { FULL_NAME } from "./data";
import { startupProgress, exitProgress } from "./loader";

const term = termkit.terminal;
const tabs: string[] = [">_", "Encode", "Decode"];
let selected: number = 0;

function stripAnsi(str: string): string {
  return str.replace(
    /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g,
    "",
  );
}

function drawInstructions(): void {
  const vp = getViewport();
  const instruction = "Tab: Navigate    Ctrl+Click: Open Link    ESC: Exit";
  const visible = stripAnsi(instruction);
  const pad = Math.max(0, Math.floor((vp.width - visible.length) / 2));
  const y = vp.y + vp.height - 1;

  term.moveTo(vp.x, y);
  term(" ".repeat(vp.width));

  term.moveTo(vp.x + pad, y);
  term.gray(instruction);
}

async function main(): Promise<void> {
  term.clear();
  await startupProgress();

  initTerminal(tabs, selected);
  showSection(tabs[selected]);
  drawInstructions();
  term.grabInput(true);

  term.on("key", (name: string, matches: any[], data: any) => {
    if (name === "TAB") {
      selected = (selected + 1) % tabs.length;
      setSelectedTab(selected);
      drawTaskbar();
      showSection(tabs[selected]);
      return;
    }

    if (name === "SHIFT_TAB") {
      selected = (selected - 1 + tabs.length) % tabs.length;
      setSelectedTab(selected);
      drawTaskbar();
      showSection(tabs[selected]);
      return;
    }
    if (tabs[selected] === "Encode") {
      const handled = handleEncodeInput(name, data);
      if (handled) {
        showSection(tabs[selected]);
        return;
      }
    }
    if (tabs[selected] === "Decode") {
      const handled = handleDecodeInput(name, data);
      if (handled) {
        showSection(tabs[selected]);
        return;
      }
    }
    if (name === "ESCAPE" || name === "CTRL_C") {
      exitProgress();
      return;
    }
    if (tabs[selected] !== "Encode" && tabs[selected] !== "Decode") {
      handleTerminalInput(name);
    }
  });

  term.on("resize", () => {
    term.clear();
    drawTaskbar();
    showSection(tabs[getSelectedTab()]);
    drawInstructions();
  });
}

function showSection(name: string): void {
  term.clear();
  drawTaskbar();

  const firstname = FULL_NAME.split(" ")[0];
  term.windowTitle(`${name} | ${firstname}'s Portfolio`);

  let content: string;
  switch (name) {
    case ">_":
      content = showHome();
      break;
    case "Encode":
      content = Encode();
      break;
    case "Decode":
      content = Decode();
      break;
    default:
      term.red("Unknown section");
      return;
  }

  let rawLines = content.toString().split("\n");
  while (rawLines.length > 0 && rawLines[0].trim() === "") rawLines.shift();
  while (rawLines.length > 0 && rawLines[rawLines.length - 1].trim() === "")
    rawLines.pop();

  const lines: string[] = [];
  for (const ln of rawLines) {
    if (ln.trim() === "") {
      if (lines.length === 0 || lines[lines.length - 1].trim() === "") continue;
      lines.push("");
    } else {
      lines.push(ln);
    }
  }
  if (lines.length === 0) lines.push("");

  const vp = getViewport();

  const frameTop = vp.y + 1;
  const frameBottom = vp.y + vp.height - 2;

  const topY = frameTop + 1;
  const contentBottom = frameBottom - 1;
  const maxLines = Math.max(0, contentBottom - topY + 1);
  const totalLines = lines.length;
  const displayLines = Math.min(totalLines, maxLines);

  const startLineIndex =
    totalLines > maxLines ? Math.floor((totalLines - maxLines) / 2) : 0;
  const verticalPad = Math.max(0, Math.floor((maxLines - displayLines) / 2));
  const startY = topY + verticalPad;
  const innerWidth = Math.max(10, vp.width - 4);

  const visibleLens: number[] = [];
  for (let i = 0; i < displayLines; i++) {
    const raw = lines[startLineIndex + i] || "";
    const visible = stripAnsi(raw);
    visibleLens.push(Math.min(visible.length, innerWidth));
  }

  const maxVisible = visibleLens.length > 0 ? Math.max(...visibleLens) : 0;
  const leftAnchor =
    vp.x + 2 + Math.max(0, Math.floor((innerWidth - maxVisible) / 2));

  for (let i = 0; i < displayLines; i++) {
    let raw = lines[startLineIndex + i] || "";
    let visible = stripAnsi(raw);

    if (visible.length > innerWidth) {
      visible = visible.slice(0, innerWidth);
      raw = visible;
    }

    const extraPad = Math.max(0, Math.floor((maxVisible - visible.length) / 2));
    const x = leftAnchor + extraPad;
    term.moveTo(x, startY + i);
    term(raw);
  }

  drawInstructions();
}

(global as any).showSection = showSection;

main().catch(console.error);
