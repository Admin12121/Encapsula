import open from "open";
import { ABOUT, CONTACTS, FULL_NAME, COLORS } from "../data";

export interface CommandResult {
  action?: "clear" | "changeTab" | "exit";
  tab?: string;
}

export function processCommand(command: string): string | CommandResult | null {
  const cmd = command.trim().toLowerCase();
  const parts: string[] = cmd.split(" ");

  switch (parts[0]) {
    case "hello":
    case "hi":
      return `Hello, I'm ${FULL_NAME}. Type 'help' to see available commands.`;

    case "about":
      return getWhoami();

    case "help":
      return getHelp();

    case "whoami":
      return getWhoami();

    case "clear":
    case "cls":
      return { action: "clear" };

    case "open":
      return handleOpen(parts[1]);

    case "ls":
    case "list":
      return listCommands();

    case "about":
      return { action: "changeTab", tab: "About" };
  
    case "blogs":
    case "proj":
      return { action: "changeTab", tab: "Blogs" };

    case "home":
      return { action: "changeTab", tab: "Home" };

    case "exit":
    case "quit":
      return { action: "exit" };

    case "chat":
      return Chat();

    default:
      if (cmd.length === 0) {
        return "";
      }
      return `Command not found: ${cmd}. Type 'help' for available commands.`;
  }
}

function Chat() {
  open(`https://discord.com/users/${CONTACTS.discordId}`);
  return "Opening Discord profile in browser...";
}

function handleOpen(target?: string) {
  if (!target) {
    return "Usage: open [resume|github|linkedin|x]";
  }

  switch (target) {
    case "resume":
      open(`https://${CONTACTS.resume}`);
      return "Opening resume in browser...";

    case "github":
      open(`https://github.com/${CONTACTS.github}`);
      return "Opening GitHub profile in browser...";

    case "linkedin":
      open(`https://linkedin.com/in/${CONTACTS.linkedin}`);
      return "Opening LinkedIn profile in browser...";
      
    default:
      return `Cannot open '${target}'. Valid options are: resume, github, linkedin, x`;
  }
}

function getWhoami() {
  return ABOUT;
}

function getHelp() {
  return [
    "whoami          Display my information",
    "open [option]   Open website in browser (resume, github, linkedin, x)",
    "clear           Clear the terminal",
    "list            List all available commands",
    "[Tabs]          Go to specific tab (eg. skills, experience, projects, home)",
    "exit            Exit the application",
    "chat            Chat with me",
  ].join("\n");
}

function listCommands() {
  return "Available commands: help, whoami, open, clear, list, about, blogs, home, exit, chat";
}
