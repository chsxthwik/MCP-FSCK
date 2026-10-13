import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { isCredentialHeaderName, isLocalHostname } from "./util.js";
import type { DeepResult, DeepTool, ParsedServer } from "./types.js";

const PROTOCOL_VERSION = "2024-11-05";
const MAX_BYTES = 2_000_000;

/**
 * A deliberately minimal MCP client: it only ever calls `initialize` and
 * `tools/list`, never executes any tool. Deep mode exists to read metadata,
 * not to drive servers.
 *
 * Stdio accepts both newline-delimited JSON and legacy Content-Length frames.
 * HTTP speaks streamable HTTP (session header included). SSE uses the classic
 * endpoint event. Credentials are not sent to non-local plain HTTP servers.
 */

export const DEFAULT_TIMEOUT_MS = 10_000;

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

export function tryParseMessage(text: string): JsonRpcMessage | null {
  const trimmed = text.trim();
  if (trimmed.length === 0 || !trimmed.startsWith("{")) return null;
  try {
    return JSON.parse(trimmed) as JsonRpcMessage;
  } catch {
    return null;
  }
}

function sameId(id: unknown, expected: number): boolean {
  return id === expected || id === String(expected);
}

function errorText(error: unknown): string {
  if (error !== null && typeof error === "object" && "message" in error) {
    return String((error as { message?: unknown }).message ?? "unknown error");
  }
  return "unknown error";
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

export interface StdioTake {
  buffer: Buffer;
  messages: JsonRpcMessage[];
  error?: string;
}

/** Pull complete JSON-RPC messages out of a stdio byte buffer. Leaves a partial tail in `buffer`. */
export function takeStdioMessages(buffer: Buffer): StdioTake {
  const messages: JsonRpcMessage[] = [];
  let buf = buffer;
  while (buf.length > 0) {
    if (buf.length > MAX_BYTES) {
      return { buffer: buf, messages, error: "server output exceeded 2MB" };
    }
    const prefix = buf.subarray(0, Math.min(buf.length, 64)).toString("utf8");
    if (/^\s*Content-Length:/i.test(prefix)) {
      const crlf = buf.indexOf("\r\n\r\n");
      const lf = buf.indexOf("\n\n");
      let headerEnd = -1;
      let sep = 4;
      if (crlf !== -1 && (lf === -1 || crlf <= lf)) {
        headerEnd = crlf;
        sep = 4;
      } else if (lf !== -1) {
        headerEnd = lf;
        sep = 2;
      }
      if (headerEnd === -1) break;
      const header = buf.subarray(0, headerEnd).toString("utf8");
      const match = /Content-Length:\s*(\d+)/i.exec(header);
      if (match === null) return { buffer: buf, messages, error: "stdio frame is missing Content-Length" };
      const len = Number(match[1]);
      if (!Number.isFinite(len) || len < 0 || len > MAX_BYTES) {
        return { buffer: buf, messages, error: "stdio Content-Length is not usable" };
      }
      const start = headerEnd + sep;
      if (buf.length < start + len) break;
      const body = buf.subarray(start, start + len).toString("utf8");
      buf = Buffer.from(buf.subarray(start + len));
      const message = tryParseMessage(body);
      if (message) messages.push(message);
      continue;
    }
    const nl = buf.indexOf(0x0a);
    if (nl === -1) break;
    const line = buf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
    buf = Buffer.from(buf.subarray(nl + 1));
    if (line.trim() === "") continue;
    const message = tryParseMessage(line);
    if (message) messages.push(message);
  }
  if (buf.length > MAX_BYTES) return { buffer: buf, messages, error: "server output exceeded 2MB" };
  return { buffer: buf, messages };
}

function killChild(child: ChildProcess): void {
  const pid = child.pid;
  try {
    child.stdin?.destroy();
  } catch {
    // already closed
  }
  if (pid === undefined) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-pid, "SIGKILL");
      return;
    } catch {
      // not a process-group leader
    }
  }
  try {
    child.kill("SIGKILL");
  } catch {
    // already gone
  }
}

function initializeParams(clientVersion: string): object {
  return {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "mcp-fsck", version: clientVersion },
  };
}

function enumerateStdio(server: ParsedServer, timeoutMs: number, clientVersion: string): Promise<DeepResult> {
  return new Promise((resolve) => {
    const base: DeepResult = { server: server.name, source: server.source, status: "ok", tools: [] };
    if (server.command === undefined || server.command.trim() === "") {
      resolve({ ...base, status: "error", error: "no command defined" });
      return;
    }

    let settled = false;
    let child: ChildProcess | undefined;
    const finish = (status: DeepResult["status"], error?: string, tools: DeepTool[] = []) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child !== undefined) killChild(child);
      resolve({ ...base, status, error, tools });
    };

    const timer = setTimeout(
      () => finish("timeout", `no response within ${timeoutMs}ms — use --timeout to adjust`),
      timeoutMs,
    );

    try {
      child = spawn(server.command, server.args ?? [], {
        env: minimalEnv(server.env),
        cwd: server.cwd ?? tmpdir(),
        stdio: ["pipe", "pipe", "pipe"],
        detached: process.platform !== "win32",
        windowsHide: true,
      });
    } catch (err) {
      finish("error", (err as Error).message);
      return;
    }

    const send = (message: object) => {
      if (settled) return;
      try {
        child?.stdin?.write(`${JSON.stringify(message)}\n`);
      } catch {
        // close/error reports the failure
      }
    };

    let pending: Buffer = Buffer.alloc(0);
    let sawInitialize = false;

    const onMessage = (message: JsonRpcMessage) => {
      if (sameId(message.id, 1)) {
        if (message.error !== undefined) {
          finish("error", `initialize rejected: ${errorText(message.error)}`);
          return;
        }
        if (sawInitialize) return;
        sawInitialize = true;
        send({ jsonrpc: "2.0", method: "notifications/initialized" });
        send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
        return;
      }
      if (sameId(message.id, 2)) {
        if (message.error !== undefined) {
          finish("error", `tools/list rejected: ${errorText(message.error)}`);
          return;
        }
        finish("ok", undefined, extractTools(message.result));
      }
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      if (settled) return;
      pending = Buffer.concat([pending, chunk]);
      const taken = takeStdioMessages(pending);
      pending = taken.buffer;
      if (taken.error !== undefined) {
        finish("error", taken.error);
        return;
      }
      for (const message of taken.messages) onMessage(message);
    });
    child.stderr?.on("data", () => {
      /* drain stderr: many servers log noise there */
    });
    child.on("error", (err: Error) => finish("error", err.message));
    child.on("close", () => {
      if (!settled) finish("error", "server exited before tools/list completed");
    });
    child.on("spawn", () => {
      send({ jsonrpc: "2.0", id: 1, method: "initialize", params: initializeParams(clientVersion) });
    });
  });
}

/**
 * Effective request headers. Codex configs reference credentials
 * indirectly — `bearer_token_env_var` names an env var holding the token,
 * `env_http_headers` maps header names to env var names — so resolve them
 * here, at request time. Keeping resolved values out of `server.headers`
 * matters: static rules would otherwise report an env-var reference (the
 * recommended practice) as a stored credential.
 */
export function resolvedHeaders(server: ParsedServer): Record<string, string> {
  const headers: Record<string, string> = { ...(server.headers ?? {}) };
  const raw = server.raw;
  if (raw === null || typeof raw !== "object") return headers;
  const r = raw as Record<string, unknown>;
  const envHeaders = r["env_http_headers"];
  if (envHeaders !== null && typeof envHeaders === "object") {
    for (const [name, envVar] of Object.entries(envHeaders as Record<string, unknown>)) {
      if (typeof envVar !== "string") continue;
      const value = process.env[envVar];
      if (value !== undefined && value !== "") headers[name] = value;
    }
  }
  const bearerVar = r["bearer_token_env_var"];
  if (typeof bearerVar === "string" && headers["Authorization"] === undefined) {
    const token = process.env[bearerVar];
    if (token !== undefined && token !== "") headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export interface DeepRequest {
  url: string;
  headers: Record<string, string>;
  /** True when credential headers or URL userinfo were removed. */
  withheld: boolean;
}

/** Drop credential headers and URL userinfo when the target is non-local plain HTTP. */
export function prepareDeepRequest(server: ParsedServer): DeepRequest {
  const headers: Record<string, string> = { ...resolvedHeaders(server) };
  const rawUrl = server.url ?? "";
  let url = rawUrl;
  let withheld = false;
  try {
    const parsed = new URL(rawUrl);
    const plain = parsed.protocol === "http:" || parsed.protocol === "ws:";
    const remote = !isLocalHostname(parsed.hostname);
    if (plain && remote) {
      if (parsed.username !== "" || parsed.password !== "") {
        parsed.username = "";
        parsed.password = "";
        url = parsed.toString();
        withheld = true;
      }
      for (const name of Object.keys(headers)) {
        if (isCredentialHeaderName(name)) {
          delete headers[name];
          withheld = true;
        }
      }
    }
  } catch {
    // unparseable URLs fail later with a clear error
  }
  return { url, headers, withheld };
}

function isWebSocket(server: ParsedServer): boolean {
  const url = server.url ?? "";
  if (url.startsWith("ws:") || url.startsWith("wss:")) return true;
  const raw = server.raw;
  if (raw === null || typeof raw !== "object") return false;
  const type = (raw as Record<string, unknown>)["type"];
  return type === "ws" || type === "websocket";
}

const WITHHELD_NOTE = "credentials were not sent to a non-local plain HTTP server";

function collectMessages(text: string): JsonRpcMessage[] {
  const out: JsonRpcMessage[] = [];
  const whole = tryParseMessage(text);
  if (whole) out.push(whole);
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    const payload = trimmed.startsWith("data:") ? trimmed.slice(5).trim() : trimmed;
    const message = tryParseMessage(payload);
    if (message) out.push(message);
  }
  return out;
}

function findMessage(text: string, id: number): JsonRpcMessage | null {
  return collectMessages(text).find((message) => sameId(message.id, id)) ?? null;
}

async function readRpcMessage(response: Response, id: number, signal: AbortSignal): Promise<JsonRpcMessage> {
  const body = response.body;
  if (body === null) {
    const found = findMessage(await response.text(), id);
    if (found) return found;
    throw new Error("response did not include the JSON-RPC result");
  }
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      if (buf.length > MAX_BYTES) throw new Error("response exceeded 2MB");
      const found = findMessage(buf, id);
      if (found) return found;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const fallback = collectMessages(buf).find((message) => sameId(message.id, id));
  if (fallback) return fallback;
  if (buf.trim() === "") throw new Error("empty MCP response");
  throw new Error("response did not include the JSON-RPC result");
}

export interface SseEvent {
  event: string;
  data: string;
}

/** Split a buffer into complete SSE events. `rest` is the incomplete tail. */
export function pullSseEvents(buffer: string): { events: SseEvent[]; rest: string } {
  const events: SseEvent[] = [];
  let rest = buffer;
  while (rest.length > 0) {
    const match = /\r?\n\r?\n/.exec(rest);
    if (match === null || match.index === undefined) break;
    const raw = rest.slice(0, match.index);
    rest = rest.slice(match.index + match[0].length);
    let event = "message";
    const data: string[] = [];
    for (const line of raw.split(/\r?\n/)) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    }
    if (data.length > 0) events.push({ event, data: data.join("\n") });
  }
  return { events, rest };
}

async function enumerateHttp(server: ParsedServer, timeoutMs: number, clientVersion: string): Promise<DeepResult> {
  const base: DeepResult = { server: server.name, source: server.source, status: "ok", tools: [] };
  if (server.url === undefined) return { ...base, status: "error", error: "no url defined" };
  if (isWebSocket(server)) {
    return { ...base, status: "error", error: "websocket MCP servers are not enumerated; static checks still ran" };
  }
  const prepared = prepareDeepRequest(server);
  const warning = prepared.withheld ? WITHHELD_NOTE : undefined;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let sessionId: string | undefined;

  const rpc = async (id: number | undefined, method: string, params: unknown): Promise<JsonRpcMessage> => {
    const headers: Record<string, string> = {
      ...prepared.headers,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": PROTOCOL_VERSION,
    };
    if (sessionId !== undefined) headers["Mcp-Session-Id"] = sessionId;
    const body: Record<string, unknown> = { jsonrpc: "2.0", method, params };
    if (id !== undefined) body["id"] = id;
    const response = await fetch(prepared.url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const sid = response.headers.get("mcp-session-id");
    if (sid !== null && sid !== "") sessionId = sid;
    if (!response.ok && response.status !== 202) {
      throw new Error(`HTTP ${response.status} from ${prepared.url}`);
    }
    if (id === undefined) {
      await response.body?.cancel().catch(() => undefined);
      return { jsonrpc: "2.0" };
    }
    return readRpcMessage(response, id, controller.signal);
  };

  try {
    const init = await rpc(1, "initialize", initializeParams(clientVersion));
    if (init.error !== undefined) {
      return { ...base, status: "error", error: `initialize rejected: ${errorText(init.error)}`, warning };
    }
    await rpc(undefined, "notifications/initialized", {});
    const list = await rpc(2, "tools/list", {});
    if (list.error !== undefined) {
      return { ...base, status: "error", error: `tools/list rejected: ${errorText(list.error)}`, warning };
    }
    return { ...base, status: "ok", tools: extractTools(list.result), warning };
  } catch (err) {
    const aborted = controller.signal.aborted;
    const message = err instanceof Error ? err.message : String(err);
    return {
      ...base,
      status: aborted ? "timeout" : "error",
      error: aborted ? `no response within ${timeoutMs}ms — use --timeout to adjust` : message,
      warning,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function enumerateSse(server: ParsedServer, timeoutMs: number, clientVersion: string): Promise<DeepResult> {
  const base: DeepResult = { server: server.name, source: server.source, status: "ok", tools: [] };
  if (server.url === undefined) return { ...base, status: "error", error: "no url defined" };
  const prepared = prepareDeepRequest(server);
  const warning = prepared.withheld ? WITHHELD_NOTE : undefined;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const messages: JsonRpcMessage[] = [];
  let endpoint: string | undefined;
  const waiters: Array<() => void> = [];
  const wake = () => {
    const pending = waiters.splice(0, waiters.length);
    for (const fn of pending) fn();
  };
  const waitFor = (ready: () => boolean) =>
    new Promise<void>((resolve, reject) => {
      if (ready()) {
        resolve();
        return;
      }
      const onWake = () => {
        if (controller.signal.aborted) {
          cleanup();
          reject(new DOMException("aborted", "AbortError"));
          return;
        }
        if (!ready()) {
          waiters.push(onWake);
          return;
        }
        cleanup();
        resolve();
      };
      const onAbort = () => onWake();
      const cleanup = () => {
        controller.signal.removeEventListener("abort", onAbort);
        const index = waiters.indexOf(onWake);
        if (index !== -1) waiters.splice(index, 1);
      };
      controller.signal.addEventListener("abort", onAbort);
      waiters.push(onWake);
    });

  try {
    const response = await fetch(prepared.url, {
      method: "GET",
      headers: {
        ...prepared.headers,
        accept: "text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
      },
      signal: controller.signal,
    });
    if (!response.ok || response.body === null) {
      throw new Error(`HTTP ${response.status} from ${prepared.url}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    const pump = (async () => {
      try {
        while (!controller.signal.aborted) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          if (buf.length > MAX_BYTES) throw new Error("response exceeded 2MB");
          const pulled = pullSseEvents(buf);
          buf = pulled.rest;
          for (const event of pulled.events) {
            if (event.event === "endpoint" && endpoint === undefined) {
              endpoint = new URL(event.data.trim(), prepared.url).toString();
            }
            const message = tryParseMessage(event.data);
            if (message) messages.push(message);
          }
          wake();
        }
      } catch {
        // cancellation ends the read; the request timeout reports it
      } finally {
        wake();
      }
    })();
    void pump;

    await waitFor(() => endpoint !== undefined);
    const postUrl = endpoint ?? prepared.url;

    const post = async (id: number | undefined, method: string, params: unknown): Promise<JsonRpcMessage | undefined> => {
      const body: Record<string, unknown> = { jsonrpc: "2.0", method, params };
      if (id !== undefined) body["id"] = id;
      const res = await fetch(postUrl, {
        method: "POST",
        headers: {
          ...prepared.headers,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": PROTOCOL_VERSION,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok && res.status !== 202) throw new Error(`HTTP ${res.status} from ${postUrl}`);
      const text = await res.text();
      if (id === undefined) return undefined;
      const inline = text.trim() === "" ? null : findMessage(text, id);
      if (inline && sameId(inline.id, id)) return inline;
      await waitFor(() => messages.some((message) => sameId(message.id, id)));
      return messages.find((message) => sameId(message.id, id));
    };

    const init = await post(1, "initialize", initializeParams(clientVersion));
    if (init === undefined) throw new Error("SSE stream closed before initialize completed");
    if (init.error !== undefined) {
      return { ...base, status: "error", error: `initialize rejected: ${errorText(init.error)}`, warning };
    }
    await post(undefined, "notifications/initialized", {});
    const list = await post(2, "tools/list", {});
    if (list === undefined) throw new Error("SSE stream closed before tools/list completed");
    if (list.error !== undefined) {
      return { ...base, status: "error", error: `tools/list rejected: ${errorText(list.error)}`, warning };
    }
    await reader.cancel().catch(() => undefined);
    return { ...base, status: "ok", tools: extractTools(list.result), warning };
  } catch (err) {
    const aborted = controller.signal.aborted;
    const message = err instanceof Error ? err.message : String(err);
    return {
      ...base,
      status: aborted ? "timeout" : "error",
      error: aborted ? `no response within ${timeoutMs}ms — use --timeout to adjust` : message,
      warning,
    };
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

export function enumerateTools(server: ParsedServer, timeoutMs: number, clientVersion = "0.0.0"): Promise<DeepResult> {
  if (server.transport === "stdio") return enumerateStdio(server, timeoutMs, clientVersion);
  if (server.transport === "sse") return enumerateSse(server, timeoutMs, clientVersion);
  return enumerateHttp(server, timeoutMs, clientVersion);
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
