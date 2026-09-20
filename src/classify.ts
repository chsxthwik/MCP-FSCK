export type Capability = "exec" | "network" | "fs-read" | "fs-write" | "secrets";

export const CAPABILITIES: Capability[] = ["exec", "network", "fs-read", "fs-write", "secrets"];

export interface ClassifiedTool {
  name: string;
  capabilities: Capability[];
}

/**
 * Keywords that hint at a capability. `name` tokens count double: a tool
 * called run_command is exec even if its description is empty, while a
 * mere mention of "run" in the description is not enough on its own.
 */
const KEYWORDS: Record<Capability, string[]> = {
  exec: [
    "shell", "terminal", "command", "commands", "execute", "exec", "run", "runs",
    "process", "repl", "bash", "zsh", "spawn", "subprocess",
  ],
  network: [
    "fetch", "http", "https", "url", "urls", "web", "webhook", "request", "download",
    "upload", "browser", "curl", "internet", "send", "socket", "email", "mail", "slack",
    "post", "remote",
  ],
  "fs-read": [
    "readfile", "listdir", "readdir", "directory", "directories", "filesystem",
  ],
  "fs-write": [
    "writefile", "createfile", "deletefile", "mkdir", "rmdir", "filesystem",
  ],
  secrets: [
    "credential", "credentials", "secret", "secrets", "token", "password", "apikey",
    "api_key", "keychain", "keystore", "ssh", "gpg", "privatekey", "auth", "vault",
  ],
};

/**
 * Weak fs keywords — "search", "find", "read", "write" — only count when the
 * tool also mentions a filesystem anchor. Otherwise `search_issues` or
 * `read_aloud` look like file access and trigger phantom exfil combos.
 */
const FS_WEAK: Record<"fs-read" | "fs-write", string[]> = {
  "fs-read": ["read", "list", "ls", "glob", "grep", "search", "cat", "stat", "tree", "find", "open", "load", "get"],
  "fs-write": ["write", "create", "delete", "remove", "move", "rename", "edit", "patch", "append", "truncate", "modify", "save", "update"],
};

const FS_ANCHORS = new Set([
  "file", "files", "filename", "filepath", "dir", "directory", "directories",
  "folder", "path", "paths", "filesystem", "disk", "workspace", "fs",
]);

function tokenize(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** Tokens plus adjacent-pair joins, so "api"+"key" can match the keyword api_key. */
function candidates(tokens: string[]): string[] {
  const out = [...tokens];
  for (let i = 0; i + 1 < tokens.length; i += 1) {
    out.push(`${tokens[i]}${tokens[i + 1]}`);
  }
  return out;
}

function scoreCapability(capability: Capability, nameTokens: string[], descTokens: string[]): number {
  let score = 0;
  const keywords = KEYWORDS[capability]!.map((kw) => kw.replace(/_/g, ""));
  const nameCandidates = candidates(nameTokens);
  const descCandidates = candidates(descTokens);
  const weak = capability === "fs-read" || capability === "fs-write" ? FS_WEAK[capability] : [];
  const hasAnchor = [...nameTokens, ...descTokens].some((tok) => FS_ANCHORS.has(tok));
  const effectiveKeywords = hasAnchor ? [...keywords, ...weak] : keywords;
  for (const kw of effectiveKeywords) {
    if (nameCandidates.some((tok) => tok === kw)) {
      score += 2;
    }
    for (const tok of descCandidates) {
      if (tok === kw) {
        score += 1;
      }
    }
  }
  return score;
}

const THRESHOLD: Record<Capability, number> = {
  exec: 2,
  network: 2,
  "fs-read": 2,
  "fs-write": 2,
  secrets: 2,
};

/** Classify a tool's capabilities from its name and description. */
export function classifyTool(name: string, description?: string): ClassifiedTool {
  const nameTokens = tokenize(name);
  const descTokens = description ? tokenize(description).slice(0, 120) : [];
  const capabilities: Capability[] = [];
  for (const cap of CAPABILITIES) {
    if (scoreCapability(cap, nameTokens, descTokens) >= THRESHOLD[cap]) {
      capabilities.push(cap);
    }
  }
  return { name, capabilities };
}

export function shortList(items: string[], max = 4): string {
  const shown = items.slice(0, max).map((t) => `\u201C${t}\u201D`);
  const rest = items.length - shown.length;
  const suffix = rest > 0 ? ` (+${rest} more)` : "";
  return shown.join(", ") + suffix;
}
