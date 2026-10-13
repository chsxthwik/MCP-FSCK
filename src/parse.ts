import { z } from "zod";
import { parseTomlSubset } from "./toml.js";
import { parseTolerantJson } from "./util.js";
import type { ConfigFile, ParsedServer, SkippedServer, Transport } from "./types.js";

/** Values configs write that are not strings (ports, booleans) still parse. */
const scalar = z.union([z.string(), z.number(), z.boolean()]).transform((v) => String(v));
const stringRecord = z.record(z.string(), scalar);

const serverEntry = z
  .object({
    type: z.string().optional(),
    command: z.string().optional(),
    args: z.array(scalar).optional(),
    env: stringRecord.optional(),
    cwd: z.string().optional(),
    url: z.string().optional(),
    headers: stringRecord.optional(),
  })
  .passthrough();

export interface ParseOutcome {
  servers: ParsedServer[];
  skipped: SkippedServer[];
  error?: string;
}

function normalizeTransport(entry: z.infer<typeof serverEntry>): Transport | null {
  if (entry.url !== undefined) {
    const t = entry.type;
    if (t === "sse") return "sse";
    return "http";
  }
  if (entry.command !== undefined) return "stdio";
  return null;
}

function uniqueName(base: string, taken: Set<string>): string {
  if (!taken.has(base)) {
    taken.add(base);
    return base;
  }
  let n = 2;
  while (taken.has(`${base} #${n}`)) n += 1;
  const name = `${base} #${n}`;
  taken.add(name);
  return name;
}

function disabledName(name: string, scopeHint?: string): string {
  return scopeHint !== undefined ? `${name} @ ${scopeHint}` : name;
}

function isDisabledEntry(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record["enabled"] === false || record["disabled"] === true;
}

function pushNamedServers(
  servers: ParsedServer[],
  skipped: SkippedServer[],
  taken: Set<string>,
  map: Record<string, unknown>,
  path: string,
  client: string,
  scopeHint?: string,
): void {
  for (const [name, value] of Object.entries(map)) {
    if (isDisabledEntry(value)) {
      skipped.push({ name: disabledName(name, scopeHint), reason: "disabled" });
      continue;
    }
    const parsed = serverEntry.safeParse(value);
    if (!parsed.success) continue;
    const entry = parsed.data;
    const transport = normalizeTransport(entry);
    if (transport === null) continue;
    const base = scopeHint !== undefined ? `${name} @ ${scopeHint}` : name;
    servers.push(toServer(uniqueName(base, taken), { ...entry, transport }, path, client, value));
  }
}

function toServer(
  name: string,
  entry: { command?: string; args?: string[]; env?: Record<string, string>; cwd?: string; url?: string; headers?: Record<string, string>; transport: Transport },
  path: string,
  client: string,
  raw: unknown,
): ParsedServer {
  return {
    name,
    transport: entry.transport,
    command: entry.command,
    args: entry.args,
    env: entry.env,
    cwd: entry.cwd,
    url: entry.url,
    headers: entry.headers,
    source: path,
    client,
    raw,
  };
}

/**
 * Zed settings use `context_servers` with a nested command object:
 *   "context_servers": { "x": { "command": { "path": "npx", "args": [...], "env": {} } } }
 * (command may also be a bare string; `enabled: false` disables the entry.)
 */
function zedEntryToEntry(value: unknown): z.infer<typeof serverEntry> | "skip" | null {
  if (value === null || typeof value !== "object") return null;
  const obj = value as Record<string, unknown>;
  if (obj["enabled"] === false) return "skip";
  const commandField = obj["command"];
  let command: string | undefined;
  let args: string[] | undefined;
  let env: Record<string, string> | undefined;
  if (typeof commandField === "string") {
    command = commandField;
  } else if (commandField !== null && typeof commandField === "object") {
    const c = commandField as Record<string, unknown>;
    const path = c["path"] ?? c["command"];
    if (typeof path === "string") command = path;
    if (Array.isArray(c["args"])) args = c["args"].map(String);
    if (c["env"] !== null && typeof c["env"] === "object") {
      env = Object.fromEntries(Object.entries(c["env"] as Record<string, unknown>).map(([k, v]) => [k, String(v)]));
    }
  }
  const url = typeof obj["url"] === "string" ? obj["url"] : (typeof obj["server_url"] === "string" ? obj["server_url"] : undefined);
  if (command === undefined && url === undefined) return null;
  return {
    type: url !== undefined ? "http" : "stdio",
    command,
    args,
    env,
    url,
    headers: obj["headers"] !== null && typeof obj["headers"] === "object"
      ? Object.fromEntries(Object.entries(obj["headers"] as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
      : undefined,
  };
}

/**
 * Parse the contents of one client config file. Supports the common shapes:
 *   { "mcpServers": { name: {...} } }      (Claude, Cursor, Windsurf, Gemini, Junie, Cline/Roo)
 *   { "servers":    { name: {...} } }      (VS Code mcp.json)
 *   { "context_servers": { name: {...} } } (Zed settings.json)
 *   Codex CLI: TOML [mcp_servers.name] tables (client "codex").
 */
export function parseConfigContents(path: string, client: string, text: string): ParseOutcome {
  if (client === "codex" || path.endsWith(".toml")) {
    return parseCodexContents(path, client, text);
  }

  let root: unknown;
  try {
    root = parseTolerantJson(text);
  } catch (err) {
    return { servers: [], skipped: [], error: `not valid JSON: ${(err as Error).message}` };
  }
  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    return { servers: [], skipped: [], error: "top level is not a JSON object" };
  }
  const obj = root as Record<string, unknown>;

  const zedMap = obj["context_servers"];
  if (zedMap !== null && typeof zedMap === "object" && !Array.isArray(zedMap)) {
    const servers: ParsedServer[] = [];
    const skipped: SkippedServer[] = [];
    for (const [name, value] of Object.entries(zedMap as Record<string, unknown>)) {
      const entry = zedEntryToEntry(value);
      if (entry === "skip") {
        skipped.push({ name, reason: "disabled" });
        continue;
      }
      if (entry === null) continue;
      const transport = normalizeTransport(entry);
      if (transport === null) continue;
      servers.push(toServer(name, { ...entry, transport }, path, client, value));
    }
    return { servers, skipped };
  }

  const taken = new Set<string>();
  const servers: ParsedServer[] = [];
  const skipped: SkippedServer[] = [];
  let error: string | undefined;
  const top = (obj["mcpServers"] as unknown) ?? (obj["servers"] as unknown) ?? null;
  if (top !== null) {
    if (typeof top !== "object" || Array.isArray(top)) {
      error = '"mcpServers"/"servers" is not an object';
    } else {
      // `enabled = false` / `disabled = true` are recorded as skipped, not scanned.
      pushNamedServers(servers, skipped, taken, top as Record<string, unknown>, path, client);
    }
  }

  // Claude Code stores per-project servers in ~/.claude.json under
  // projects.<absolute path>.mcpServers, separate from the user-level map.
  const projects = obj["projects"];
  if (projects !== null && typeof projects === "object" && !Array.isArray(projects)) {
    for (const [projectPath, project] of Object.entries(projects as Record<string, unknown>)) {
      if (project === null || typeof project !== "object" || Array.isArray(project)) continue;
      const nested = (project as Record<string, unknown>)["mcpServers"];
      if (nested === null || typeof nested !== "object" || Array.isArray(nested)) continue;
      const hint = projectPath.split(/[/\\]/).filter(Boolean).pop() ?? "project";
      pushNamedServers(servers, skipped, taken, nested as Record<string, unknown>, path, client, hint);
    }
  }
  return { servers, skipped, error };
}

/**
 * Codex CLI's config.toml uses [mcp_servers.<name>] tables:
 *   command = "npx", args = [...], env = {..} / [mcp_servers.<name>.env],
 *   url = "https://…", http_headers / bearer_token_env_var for remotes.
 * Credential references (bearer_token_env_var, env_http_headers) stay on
 * `raw` and are resolved by deep mode at request time.
 */
export function parseCodexContents(path: string, client: string, text: string): ParseOutcome {
  let root: Record<string, unknown>;
  try {
    root = parseTomlSubset(text);
  } catch (err) {
    return { servers: [], skipped: [], error: `not valid TOML: ${(err as Error).message}` };
  }
  const map = root["mcp_servers"];
  if (map === undefined) return { servers: [], skipped: [] };
  if (map === null || typeof map !== "object" || Array.isArray(map)) {
    return { servers: [], skipped: [], error: '"mcp_servers" is not a table' };
  }
  const servers: ParsedServer[] = [];
  const skipped: SkippedServer[] = [];
  for (const [name, value] of Object.entries(map as Record<string, unknown>)) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
    const v = value as Record<string, unknown>;
    if (v["enabled"] === false) {
      skipped.push({ name, reason: "disabled" });
      continue;
    }
    const entry = {
      type: typeof v["url"] === "string" ? "http" : "stdio",
      command: typeof v["command"] === "string" ? v["command"] : undefined,
      args: Array.isArray(v["args"]) ? v["args"].map(String) : undefined,
      env:
        v["env"] !== null && typeof v["env"] === "object"
          ? Object.fromEntries(Object.entries(v["env"] as Record<string, unknown>).map(([k, x]) => [k, String(x)]))
          : undefined,
      cwd: typeof v["cwd"] === "string" ? v["cwd"] : undefined,
      url: typeof v["url"] === "string" ? v["url"] : undefined,
      headers:
        v["http_headers"] !== null && typeof v["http_headers"] === "object"
          ? Object.fromEntries(Object.entries(v["http_headers"] as Record<string, unknown>).map(([k, x]) => [k, String(x)]))
          : undefined,
    };
    const transport = normalizeTransport(entry);
    if (transport === null) continue;
    servers.push(toServer(name, { ...entry, transport }, path, client, value));
  }
  return { servers, skipped };
}

export function parseConfigFile(path: string, client: string, contents: string | null, exists = contents !== null): ConfigFile {
  if (!exists) {
    return { path, client, exists: false, servers: [] };
  }
  if (contents === null) {
    return { path, client, exists: true, servers: [], error: "unreadable" };
  }
  const outcome = parseConfigContents(path, client, contents);
  return {
    path,
    client,
    exists: true,
    servers: outcome.servers,
    ...(outcome.skipped.length > 0 ? { skipped: outcome.skipped } : {}),
    error: outcome.error,
  };
}
