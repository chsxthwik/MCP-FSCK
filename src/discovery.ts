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

function editorConfigDir(editor: string): string {
  const p = platform();
  if (p === "darwin") {
    return join(homedir(), "Library", "Application Support", editor, "User");
  }
  if (p === "win32") {
    const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return join(appData, editor, "User");
  }
  return join(homedir(), ".config", editor, "User");
}

function vscodeUserPaths(): string[] {
  const variants = ["Code", "Code - OSS", "Code - Insiders", "Cursor", "VSCodium"];
  return variants.map((v) => join(editorConfigDir(v), "mcp.json"));
}

/** Cline / Roo Code / Kilo Code store MCP settings in the editor's globalStorage. */
function vscodeForkExtensionMcpPaths(): Array<{ client: string; path: string }> {
  const editors = ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"];
  const extensions: Array<[string, string, string]> = [
    ["cline", "saoudrizwan.claude-dev", "cline_mcp_settings.json"],
    ["cline", "cline.cline", "cline_mcp_settings.json"],
    ["roo-code", "rooveterinaryinc.roo-cline", "mcp_settings.json"],
    ["kilo-code", "kilocode.Kilo-Code", "mcp_settings.json"],
  ];
  const out: Array<{ client: string; path: string }> = [];
  for (const editor of editors) {
    for (const [client, extId, file] of extensions) {
      out.push({ client, path: join(editorConfigDir(editor), "globalStorage", extId, "settings", file) });
    }
  }
  return out;
}

function zedSettingsPaths(): string[] {
  const p = platform();
  if (p === "win32") {
    const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return [join(appData, "Zed", "settings.json")];
  }
  const xdg = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
  const paths = [join(xdg, "zed", "settings.json")];
  if (p === "darwin") {
    paths.push(join(homedir(), "Library", "Application Support", "Zed", "settings.json"));
  }
  return paths;
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
    { client: "gemini-cli", paths: [join(home, ".gemini", "settings.json"), join(cwd, ".gemini", "settings.json")] },
    { client: "codex", paths: [join(home, ".codex", "config.toml"), join(cwd, ".codex", "config.toml")] },
    { client: "junie", paths: [join(home, ".junie", "mcp", "mcp.json")] },
    { client: "zed", paths: zedSettingsPaths() },
    { client: "zed-project", paths: [join(cwd, ".zed", "settings.json")] },
    ...vscodeForkExtensionMcpPaths().map(({ client, path }) => ({ client, paths: [path] })),
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
