import { existsSync, realpathSync, readFileSync, readdirSync, statSync } from "node:fs";
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

/** `mcp.json` in a VS Code-style user dir, plus each profile's copy. */
export function mcpJsonUnderUserDir(userDir: string): string[] {
  const out = [join(userDir, "mcp.json")];
  try {
    for (const entry of readdirSync(join(userDir, "profiles"), { withFileTypes: true })) {
      if (entry.isDirectory()) out.push(join(userDir, "profiles", entry.name, "mcp.json"));
    }
  } catch {
    // the editor has no profiles directory
  }
  return out;
}

function vscodeUserPaths(): string[] {
  const variants = ["Code", "Code - OSS", "Code - Insiders", "Cursor", "VSCodium"];
  return variants.flatMap((variant) => mcpJsonUnderUserDir(editorConfigDir(variant)));
}

function claudeCodePaths(): string[] {
  const paths = [join(homedir(), ".claude.json")];
  const override = process.env.CLAUDE_CONFIG_DIR;
  if (override !== undefined && override.trim() !== "") paths.push(join(override, ".claude.json"));
  return paths;
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
    { client: "claude-code", paths: claudeCodePaths() },
    { client: "claude-code-project", paths: [join(cwd, ".mcp.json")] },
    { client: "cursor", paths: [join(home, ".cursor", "mcp.json")] },
    { client: "cursor-project", paths: [join(cwd, ".cursor", "mcp.json")] },
    { client: "vscode-project", paths: [join(cwd, ".vscode", "mcp.json")] },
    { client: "vscode-user", paths: vscodeUserPaths() },
    { client: "windsurf", paths: [join(home, ".codeium", "windsurf", "mcp_config.json")] },
    { client: "gemini-cli", paths: [join(home, ".gemini", "settings.json"), join(cwd, ".gemini", "settings.json")] },
    { client: "codex", paths: [join(home, ".codex", "config.toml"), join(cwd, ".codex", "config.toml")] },
    { client: "junie", paths: [join(home, ".junie", "mcp", "mcp.json")] },
    { client: "amazon-q", paths: [join(home, ".aws", "amazonq", "mcp.json")] },
    { client: "amazon-q-project", paths: [join(cwd, ".amazonq", "mcp.json")] },
    { client: "zed", paths: zedSettingsPaths() },
    { client: "zed-project", paths: [join(cwd, ".zed", "settings.json")] },
    ...vscodeForkExtensionMcpPaths().map(({ client, path }) => ({ client, paths: [path] })),
  ];
}

/** Locate and parse every known MCP config that exists on disk. */
export function discoverConfigs(cwd: string = process.cwd()): DiscoveryResult {
  const configs: ConfigFile[] = [];
  const seen = new Set<string>();
  for (const candidate of candidateConfigFiles(cwd)) {
    for (const path of candidate.paths) {
      if (!existsSync(path)) continue;
      let key: string;
      try {
        key = realpathSync(path);
      } catch {
        key = resolve(path);
      }
      if (seen.has(key)) continue;
      seen.add(key);
      let contents: string | null = null;
      let error: string | undefined;
      try {
        if (!statSync(path).isFile()) {
          error = "not a regular file";
        } else {
          contents = readFileSync(path, "utf8");
        }
      } catch (err) {
        error = `unreadable: ${(err as Error).message}`;
      }
      const cfg = parseConfigFile(path, candidate.client, contents, true);
      if (error !== undefined) cfg.error = error;
      configs.push(cfg);
    }
  }
  return { configs };
}

/** Parse config files explicitly passed by the user on the command line. */
export function loadExplicitConfigs(paths: string[]): ConfigFile[] {
  return paths.map((path) => {
    if (!existsSync(path)) {
      return { path, client: "explicit", exists: false, servers: [], error: "file not found" } satisfies ConfigFile;
    }
    let contents: string | null = null;
    let error: string | undefined;
    try {
      if (!statSync(path).isFile()) {
        error = "not a regular file";
      } else {
        contents = readFileSync(path, "utf8");
      }
    } catch (err) {
      error = `unreadable: ${(err as Error).message}`;
    }
    const cfg = parseConfigFile(path, "explicit", contents, true);
    if (error !== undefined) cfg.error = error;
    return cfg;
  });
}
