import termkit from "terminal-kit";
import { processCommand } from "./commands";
import { FULL_NAME } from "../data";

const term = termkit.terminal;

interface OutputEntry {
  type: "output" | "command";
  text: string;
}

function stripAnsi(str: string): string {
  return str.replace(
    /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g,
    "",
  );
}

const outputHistory: OutputEntry[] = [];
let inputText: string = "";
let commandHistory: string[] = [];
let historyPosition: number = -1;
let tabs: string[] = [];
let selected: number = 0;

export function initTerminal(
  availableTabs: string[],
  initialTab: number,
): void {
  tabs = availableTabs;
  selected = initialTab;
  term.fullscreen(true);
  term.clear();
  outputHistory.push({
    type: "output",
    text: `Type 'help' for available commands.`,
  });
  drawTaskbar();
}

export function setSelectedTab(index: number): void {
  selected = index;
}

export function getSelectedTab(): number {
  return selected;
}

export function getViewport() {
  const maxW = 120;
  const maxH = 40;

  const width = Math.min(term.width, maxW);
  const height = Math.min(term.height, maxH);

  const x = Math.floor((term.width - width) / 2) + 1;
  const y = Math.floor((term.height - height) / 2) + 1;

  return { x, y, width, height };
}


function drawFrame(): void {
  const vp = getViewport();
  const tabRowY = vp.y;
  const topY = tabRowY + 1;

  const leftX = vp.x;
  const rightX = leftX + vp.width - 1;

  const bottomY = vp.y + vp.height - 2;
  term.moveTo(leftX, topY).gray("┌" + "─".repeat(Math.max(0, vp.width - 2)) + "┐");

  for (let y = topY + 1; y < bottomY; y++) {
    term.moveTo(leftX, y).gray("│");
    term.moveTo(rightX, y).gray("│");
  }

  term.moveTo(leftX, bottomY).gray("└" + "─".repeat(Math.max(0, vp.width - 2)) + "┘");
}

export function drawTaskbar(): void {
  const vp = getViewport();
  const leftPad = Math.max(0, vp.x - 1);
  if (leftPad > 0) {
    term.moveTo(1, vp.y);
    term(" ".repeat(leftPad));
  }

  term.moveTo(vp.x, vp.y);
  term(" ".repeat(vp.width));

  const rightPad = Math.max(0, term.width - (vp.x + vp.width - 1));
  if (rightPad > 0) {
    term.moveTo(vp.x + vp.width, vp.y);
    term(" ".repeat(rightPad));
  }

  const showProjectName = tabs[selected] !== ">_";

  let leftOccupied = vp.x;

  if (showProjectName) {
    const leftText = ` ${FULL_NAME} `;
    term.moveTo(vp.x, vp.y);
    term.bold(leftText);

    leftOccupied = vp.x + stripAnsi(leftText).length;
  }

  const sep = "   ";
  const tokens = tabs.map((tab, i) => ({
    text: ` ${tab} `,
    selected: i === selected,
  }));

  const totalTabsLen =
    tokens.reduce((sum, t) => sum + t.text.length, 0) +
    sep.length * Math.max(0, tokens.length - 1);

  const minGap = 2;
  const rightPadding = 1;

  let startX = Math.max(
    vp.x,
    vp.x + vp.width - totalTabsLen - rightPadding,
  );

  const minStartAfterLeft = leftOccupied + minGap;
  if (startX < minStartAfterLeft) {
    startX = minStartAfterLeft;
  }

  if (startX + totalTabsLen > vp.x + vp.width - rightPadding) {
    startX = Math.max(vp.x, vp.x + vp.width - totalTabsLen - rightPadding);
  }

  let x = startX;
  tokens.forEach((t, idx) => {
    term.moveTo(x, vp.y);

    if (t.selected) {
      term.bgBrightYellow.black(t.text);
      term.styleReset();
    } else {
      term.white(t.text);
    }

    x += t.text.length;

    if (idx < tokens.length - 1) {
      term.moveTo(x, vp.y);
      term.gray(sep);
      x += sep.length;
    }
  });
  drawFrame();
}


export function drawTerminal(): void {
  const terminalStartY = term.height - 15;
  const terminalWidth = term.width;
  term.moveTo(1, terminalStartY).eraseLine();
  term.red("┌─ Terminal ");
  term.gray("─".repeat(terminalWidth - 13) + "┐");

  for (let i = terminalStartY + 1; i < term.height - 3; i++) {
    term.moveTo(1, i).eraseLine();
    term.gray("│");
    term.column(terminalWidth).gray("│");
  }

  let currentLine = terminalStartY + 1;
  const maxLine = term.height - 4;

  for (let i = 0; i < outputHistory.length; i++) {
    if (currentLine >= maxLine) break;
    const output = outputHistory[i];
    if (output.type === "command") {
      term.moveTo(3, currentLine);
      term("> " + output.text);
      currentLine++;
    } else {
      const lines = wordWrap(output.text, terminalWidth - 6);
      for (let j = 0; j < lines.length; j++) {
        if (currentLine >= maxLine) break;
        term.moveTo(3, currentLine);
        term.white(lines[j]);
        currentLine++;
      }
      if (i < outputHistory.length - 1) currentLine++;
    }
  }

  term.moveTo(1, term.height - 3).eraseLine();
  term.gray("├");
  term.gray("─".repeat(terminalWidth - 2));
  term.gray("┤");

  term.moveTo(1, term.height - 2).eraseLine();
  term.gray("│ ");
  term.red("vicky@portfolio:~$ ");
  if (inputText.length === 0) {
    term.gray("type your command here...");
  } else {
    term.white(inputText);
  }
  term.column(terminalWidth).gray("│");

  term.moveTo(1, term.height - 1).eraseLine();
  term.moveTo(1, term.height - 1);
  term.gray("└" + "─".repeat(terminalWidth - 2) + "┘");
}

interface CommandResult {
  action?: "clear" | "changeTab" | "exit";
  tab?: string;
}

export function handleTerminalInput(key: string): void {
  switch (key) {
    case "ENTER":
      processTerminalCommand();
      // drawTerminal();
      break;
    case "BACKSPACE":
    case "DELETE":
      if (inputText.length > 0) {
        inputText = inputText.slice(0, -1);
        // drawTerminal();
      }
      break;
    case "UP":
      if (commandHistory.length > 0) {
        historyPosition =
          historyPosition < 0
            ? commandHistory.length - 1
            : Math.max(0, historyPosition - 1);
        inputText = commandHistory[historyPosition];
        // drawTerminal();
      }
      break;
    case "DOWN":
      if (commandHistory.length > 0 && historyPosition >= 0) {
        historyPosition++;
        if (historyPosition >= commandHistory.length) {
          historyPosition = -1;
          inputText = "";
        } else {
          inputText = commandHistory[historyPosition];
        }
        // drawTerminal();
      }
      break;
    default:
      if (key.length === 1) {
        inputText += key;
        // drawTerminal();
      }
  }
}

function processTerminalCommand(): void {
  if (!inputText.trim()) return;
  outputHistory.length = 0;
  outputHistory.push({
    type: "output",
    text: `Type 'help' for available commands.`,
  });
  outputHistory.push({ type: "command", text: inputText });
  commandHistory.push(inputText);
  const result: string | CommandResult | null = processCommand(inputText);

  if (typeof result === "object" && result && result.action) {
    switch (result.action) {
      case "clear":
        clearTerminalOutput();
        break;
      case "changeTab":
        if (result.tab) {
          const idx = tabs.indexOf(result.tab);
          if (idx >= 0) {
            selected = idx;
            drawTaskbar();
            const globalAny = global as any;
            if (typeof globalAny.showSection === "function") {
              globalAny.showSection(result.tab);
            }
          }
        }
        break;
      case "exit":
        exitApp();
        break;
    }
  } else if (result && typeof result === "string") {
    outputHistory.push({ type: "output", text: result });
  }
  inputText = "";
  historyPosition = -1;
}

function clearTerminalOutput(): void {
  outputHistory.length = 0;
  outputHistory.push({
    type: "output",
    text: `Type 'help' for available commands.`,
  });
}

function exitApp(): void {
  term.fullscreen(false);
  term.clear();
  term.magenta.bold("\nGoodbye!\n\n");
  process.exit();
}

export function wordWrap(text: string, maxWidth: number): string[] {
  if (!text) return [""];
  const lines = text.split("\n").map((line) => wrapLine(line, maxWidth));
  return lines.flat();
}

export function wrapLine(line: string, maxWidth: number): string[] {
  const words = line.split(" ");
  const wrapped: string[] = [];
  let current = "";
  for (const word of words) {
    if ((current + word).length + 1 > maxWidth) {
      wrapped.push(current.trim());
      current = word + " ";
    } else {
      current += word + " ";
    }
  }
  if (current.trim()) wrapped.push(current.trim());
  return wrapped;
}
