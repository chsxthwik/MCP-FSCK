import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { createInterface } from "node:readline";
import type { DeepResult, DeepTool, ParsedServer } from "./types.js";

const PROTOCOL_VERSION = "2024-11-05";

/**
 * A deliberately minimal MCP client: it only ever calls `initialize` and
 * `tools/list`, never executes any tool. Deep mode exists to read metadata,
 * not to drive servers.
 */

function minimalEnv(extra?: Record<string, string>): NodeJS.ProcessEnv {
  const base: Record<string, string> = {};
  for (const key of ["PATH", "HOME", "LANG", "TMPDIR", "SYSTEMROOT", "COMSPEC", "USERPROFILE", "APPDATA"]) {
    const value = process.env[key];
    if (value !== undefined) base[key] = value;
  }
  return { ...base, ...extra };
}

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

function tryParseMessage(line: string): JsonRpcMessage | null {
  const trimmed = line.trim();
  if (trimmed.length === 0 || !trimmed.startsWith("{")) return null;
  try {
    return JSON.parse(trimmed) as JsonRpcMessage;
  } catch {
    return null;
  }
}

function extractTools(result: unknown): DeepTool[] {
  if (result === null || typeof result !== "object") return [];
  const tools = (result as Record<string, unknown>)["tools"];
  if (!Array.isArray(tools)) return [];
  const out: DeepTool[] = [];
  for (const entry of tools) {
    if (entry === null || typeof entry !== "object") continue;
    const obj = entry as Record<string, unknown>;
    if (typeof obj["name"] !== "string") continue;
    out.push({
      name: obj["name"],
      description: typeof obj["description"] === "string" ? obj["description"] : undefined,
      inputSchema: obj["inputSchema"],
    });
  }
  return out;
}

function enumerateStdio(server: ParsedServer, timeoutMs: number): Promise<DeepResult> {
  return new Promise((resolve) => {
    const base: DeepResult = { server: server.name, source: server.source, status: "ok", tools: [] };
    if (server.command === undefined) {
      resolve({ ...base, status: "error", error: "no command defined" });
      return;
    }

    let settled = false;
    let stdout: NodeJS.ReadableStream | null = null;
    const finish = (status: DeepResult["status"], error?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
      resolve({ ...base, status, error, tools: base.tools });
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(server.command, server.args ?? [], {
        env: minimalEnv(server.env),
        cwd: server.cwd ?? tmpdir(),
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      resolve({ ...base, status: "error", error: (err as Error).message });
      return;
    }

    const timer = setTimeout(
      () => finish("timeout", `no response within ${timeoutMs}ms — use --timeout to adjust`),
      timeoutMs,
    );

    const send = (message: object) => {
      child.stdin?.write(`${JSON.stringify(message)}\n`);
    };

    child.on("error", (err: Error) => finish("error", err.message));
    child.on("spawn", () => {
      send({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: "mcp-fsck", version: "0.1.0" },
        },
      });
    });

    child.stderr?.on("data", () => {
      /* drain stderr: many servers log noise there */
    });

    if (child.stdout) {
      stdout = child.stdout;
      const rl = createInterface({ input: stdout });
      rl.on("line", (line: string) => {
        const message = tryParseMessage(line);
        if (message === null || message.id === undefined) return;
        if (message.id === 1) {
          send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
          send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
          return;
        }
        if (message.id === 2) {
          if (message.error !== undefined) {
            const errObj = message.error as Record<string, unknown> | undefined;
            finish("error", `tools/list rejected: ${String(errObj?.["message"] ?? "unknown error")}`);
            return;
          }
          base.tools = extractTools(message.result);
          finish("ok");
        }
      });
    }
  });
}

async function enumerateHttp(server: ParsedServer, timeoutMs: number): Promise<DeepResult> {
  const base: DeepResult = { server: server.name, source: server.source, status: "ok", tools: [] };
  if (server.url === undefined) {
    return { ...base, status: "error", error: "no url defined" };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const rpc = async (body: object): Promise<JsonRpcMessage> => {
      const response = await fetch(server.url!, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...(server.headers ?? {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await response.text();
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} from ${server.url}`);
      }
      // streamable-HTTP servers may answer as SSE; tolerate both shapes
      const jsonLine = text
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l.startsWith("{") || l.startsWith("data:"));
      const payload = jsonLine?.startsWith("data:")
        ? jsonLine.slice(5).trim()
        : jsonLine ?? text;
      return JSON.parse(payload) as JsonRpcMessage;
    };

    await rpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "mcp-fsck", version: "0.1.0" },
      },
    });
    const listResponse = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    if (listResponse.error !== undefined) {
      const errObj = listResponse.error as Record<string, unknown> | undefined;
      return { ...base, status: "error", error: `tools/list rejected: ${String(errObj?.["message"] ?? "unknown error")}` };
    }
    return { ...base, status: "ok", tools: extractTools(listResponse.result) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const aborted = controller.signal.aborted;
    return {
      ...base,
      status: aborted ? "timeout" : "error",
      error: aborted ? `no response within ${timeoutMs}ms — use --timeout to adjust` : message,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function enumerateTools(server: ParsedServer, timeoutMs: number): Promise<DeepResult> {
  if (server.transport === "stdio") return enumerateStdio(server, timeoutMs);
  return enumerateHttp(server, timeoutMs);
}

/** Run promises with bounded concurrency, preserving input order. */
export async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index]!);
    }
  });
  await Promise.all(workers);
  return results;
}

export const CLIENT_INFO = { name: "mcp-fsck", version: "0.1.0" };
export const DEFAULT_TIMEOUT_MS = 10_000;
