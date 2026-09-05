import { existsSync, realpathSync, readFileSync, statSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { parseConfigFile } from "./parse.js";
import type { ConfigFile } from "./types.js";

export interface DiscoveryResult {
  configs: ConfigFile[];
}

interface Candidate {
  client: string;
  paths: string[];
}

function claudeDesktopPath(): string {
  const p = platform();
  if (p === "darwin") {
    return join(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (p === "win32") {
    const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return join(appData, "Claude", "claude_desktop_config.json");
  }
  return join(homedir(), ".config", "Claude", "claude_desktop_config.json");
}

function vscodeUserPaths(): string[] {
  const p = platform();
  const out: string[] = [];
  const variants = ["Code", "Code - OSS", "Code - Insiders", "Cursor", "VSCodium"];
  for (const v of variants) {
    if (p === "darwin") {
      out.push(join(homedir(), "Library", "Application Support", v, "User", "mcp.json"));
    } else if (p === "win32") {
      const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
      out.push(join(appData, v, "User", "mcp.json"));
    } else {
      out.push(join(homedir(), ".config", v, "User", "mcp.json"));
    }
  }
  return out;
}

/**
 * Well-known MCP config locations across supported clients, for the current
 * user and platform, plus project-level configs relative to `cwd`.
 */
export function candidateConfigFiles(cwd: string): Candidate[] {
  const home = homedir();
  return [
    { client: "claude-desktop", paths: [claudeDesktopPath()] },
    { client: "claude-code", paths: [join(home, ".claude.json")] },
    { client: "claude-code-project", paths: [join(cwd, ".mcp.json")] },
    { client: "cursor", paths: [join(home, ".cursor", "mcp.json")] },
    { client: "cursor-project", paths: [join(cwd, ".cursor", "mcp.json")] },
    { client: "vscode-project", paths: [join(cwd, ".vscode", "mcp.json")] },
    { client: "vscode-user", paths: vscodeUserPaths() },
    { client: "windsurf", paths: [join(home, ".codeium", "windsurf", "mcp_config.json")] },
  ];
}

function dedupeRealpath(paths: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of paths) {
    let key: string;
    try {
      key = realpathSync(p);
    } catch {
      key = resolve(p);
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

/** Locate and parse every known MCP config. Non-existent files are reported with exists=false. */
export function discoverConfigs(cwd: string = process.cwd()): DiscoveryResult {
  const configs: ConfigFile[] = [];
  const seen = new Set<string>();
  for (const candidate of candidateConfigFiles(cwd)) {
    for (const path of dedupeRealpath(candidate.paths)) {
      if (seen.has(path)) continue;
      seen.add(path);
      if (!existsSync(path)) {
        configs.push({ path, client: candidate.client, exists: false, servers: [] });
        continue;
      }
      let contents: string | null = null;
      let error: string | undefined;
      try {
        // refuse to read special files (fifos etc.)
        if (!statSync(path).isFile()) {
          error = "not a regular file";
        } else {
          contents = readFileSync(path, "utf8");
        }
      } catch (err) {
        error = `unreadable: ${(err as Error).message}`;
      }
      const cfg = parseConfigFile(path, candidate.client, contents !== null, contents);
      if (error !== undefined && cfg.error === undefined) cfg.error = error;
      configs.push(cfg);
    }
  }
  return { configs };
}

/** Parse config files explicitly passed by the user on the command line. */
export function loadExplicitConfigs(paths: string[]): ConfigFile[] {
  return paths.map((path) => {
    if (!existsSync(path)) {
      return { path, client: "explicit", exists: false, servers: [] } satisfies ConfigFile;
    }
    let contents: string | null = null;
    let error: string | undefined;
    try {
      contents = readFileSync(path, "utf8");
    } catch (err) {
      error = `unreadable: ${(err as Error).message}`;
    }
    const cfg = parseConfigFile(path, "explicit", contents !== null, contents);
    if (error !== undefined && cfg.error === undefined) cfg.error = error;
    return cfg;
  });
}
