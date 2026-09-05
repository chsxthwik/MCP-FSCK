import { z } from "zod";
import { parseTolerantJson } from "./util.js";
import type { ConfigFile, ParsedServer, Transport } from "./types.js";

const stringRecord = z.record(z.string(), z.string());

const serverEntry = z
  .object({
    type: z.string().optional(),
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: stringRecord.optional(),
    cwd: z.string().optional(),
    url: z.string().optional(),
    headers: stringRecord.optional(),
  })
  .passthrough();

export interface ParseOutcome {
  servers: ParsedServer[];
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

/**
 * Parse the contents of one client config file. Supports the common shapes:
 *   { "mcpServers": { name: {...} } }   (Claude Desktop/Code, Cursor, Windsurf)
 *   { "servers":    { name: {...} } }   (VS Code mcp.json)
 */
export function parseConfigContents(path: string, client: string, text: string): ParseOutcome {
  let root: unknown;
  try {
    root = parseTolerantJson(text);
  } catch (err) {
    return { servers: [], error: `not valid JSON: ${(err as Error).message}` };
  }
  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    return { servers: [], error: "top level is not a JSON object" };
  }
  const obj = root as Record<string, unknown>;
  const map =
    (obj["mcpServers"] as unknown) ??
    (obj["servers"] as unknown) ??
    null;
  if (map === null) return { servers: [] };
  if (typeof map !== "object" || Array.isArray(map)) {
    return { servers: [], error: '"mcpServers"/"servers" is not an object' };
  }

  const servers: ParsedServer[] = [];
  for (const [name, value] of Object.entries(map as Record<string, unknown>)) {
    const parsed = serverEntry.safeParse(value);
    if (!parsed.success) {
      // keep scanning siblings; skip entries we cannot make sense of
      continue;
    }
    const entry = parsed.data;
    const transport = normalizeTransport(entry);
    if (transport === null) continue;
    servers.push({
      name,
      transport,
      command: entry.command,
      args: entry.args,
      env: entry.env,
      cwd: entry.cwd,
      url: entry.url,
      headers: entry.headers,
      source: path,
      client,
      raw: value,
    });
  }
  return { servers };
}

export function parseConfigFile(path: string, client: string, exists: boolean, contents: string | null): ConfigFile {
  if (!exists || contents === null) {
    return { path, client, exists: false, servers: [] };
  }
  const outcome = parseConfigContents(path, client, contents);
  return { path, client, exists: true, servers: outcome.servers, error: outcome.error };
}
