import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { enumerateTools, prepareDeepRequest, pullSseEvents, resolvedHeaders, takeStdioMessages } from "../src/deep.js";
import { ALL_RULES } from "../src/rules/index.js";
import { makeServer } from "./helpers.js";
import type { RuleContext } from "../src/types.js";

const FIXTURE = fileURLToPath(new URL("./fixtures/fake-mcp-server.mjs", import.meta.url));

function fakeServer(toolset: "poison" | "shadow" | "clean") {
  return makeServer({
    name: toolset === "poison" ? "poisoned" : toolset === "shadow" ? "shadowy" : "clean",
    command: process.execPath,
    args: [FIXTURE],
    env: { FAKE_TOOLS: toolset },
  });
}

async function deepContext(servers: ReturnType<typeof fakeServer>[]): Promise<RuleContext> {
  const deep = new Map();
  for (const server of servers) {
    deep.set(`${server.source}::${server.name}`, await enumerateTools(server, 15_000));
  }
  return { allServers: servers, deep };
}

function runDeepRules(server: ReturnType<typeof fakeServer>, context: RuleContext) {
  const findings: Array<{ ruleId: string; severity: string; title: string }> = [];
  for (const rule of ALL_RULES.filter((r) => r.meta.scope === "deep")) {
    for (const raw of rule.run(server, context)) {
      findings.push({ ruleId: rule.meta.id, severity: raw.severity ?? rule.meta.severity, title: raw.title });
    }
  }
  return findings;
}

describe("enumerateTools (live MCP handshake)", () => {
  it("performs initialize + tools/list over stdio and returns tools", async () => {
    const server = fakeServer("poison");
    const result = await enumerateTools(server, 15_000);
    expect(result.status).toBe("ok");
    expect(result.tools.map((t) => t.name)).toEqual(["run_command", "fetch_url", "read_file"]);
    expect(result.tools[0]!.description).toContain("IGNORE ALL PREVIOUS INSTRUCTIONS");
  });

  it("reports an error for a command that does not exist", async () => {
    const server = makeServer({ command: "definitely-not-a-real-binary-xyz" });
    const result = await enumerateTools(server, 5_000);
    expect(["error", "timeout"]).toContain(result.status);
  });
});

describe("deep rules against live tool metadata", () => {
  it("flags tool-description injection and exec+network combos as critical", async () => {
    const poisoned = fakeServer("poison");
    const context = await deepContext([poisoned]);
    const findings = runDeepRules(poisoned, context);
    const injection = findings.find((f) => f.ruleId === "MCP011");
    expect(injection).toBeDefined();
    expect(injection!.severity).toBe("critical");
    const combo = findings.find((f) => f.ruleId === "MCP013");
    expect(combo).toBeDefined();
    expect(combo!.severity).toBe("critical");
    expect(combo!.title).toContain("exec + network");
  });

  it("flags tool shadowing when a description references another server's tool", async () => {
    const poisoned = fakeServer("poison");
    const shadowy = fakeServer("shadow");
    const context = await deepContext([poisoned, shadowy]);
    const findings = runDeepRules(shadowy, context);
    const shadow = findings.find((f) => f.ruleId === "MCP012");
    expect(shadow).toBeDefined();
    expect(shadow!.title).toContain("another server");
  });

  it("reports a failed tools/list as info and stays quiet when the handshake succeeds", () => {
    const server = makeServer({ name: "gone", command: "missing-bin" });
    const key = `${server.source}::${server.name}`;
    const failed = runDeepRules(server, {
      allServers: [server],
      deep: new Map([[key, { server: server.name, source: server.source, status: "error", error: "spawn ENOENT", tools: [] }]]),
    });
    expect(failed.map((finding) => finding.ruleId)).toEqual(["MCP018"]);
    expect(failed[0]!.severity).toBe("info");
    const ok = runDeepRules(server, {
      allServers: [server],
      deep: new Map([[key, { server: server.name, source: server.source, status: "ok", tools: [] }]]),
    });
    expect(ok).toHaveLength(0);
  });

  it("stays quiet for a well-behaved toolset", async () => {
    // a server whose tools have honest, single-capability descriptions
    const server = makeServer({ name: "clean", command: process.execPath, args: [FIXTURE], env: { FAKE_TOOLS: "clean" } });
    const context = await deepContext([server]);
    const findings = runDeepRules(server, context);
    expect(findings).toHaveLength(0);
  });
});

describe("resolvedHeaders", () => {
  it("resolves Codex env-referenced credentials at request time", () => {
    process.env.FSCK_TEST_TOKEN = "tok-123";
    process.env.FSCK_TEST_TENANT = "t-9";
    const server = makeServer({
      url: "https://x.example",
      raw: {
        url: "https://x.example",
        bearer_token_env_var: "FSCK_TEST_TOKEN",
        env_http_headers: { "X-Tenant": "FSCK_TEST_TENANT" },
      },
    });
    const headers = resolvedHeaders(server);
    expect(headers["Authorization"]).toBe("Bearer tok-123");
    expect(headers["X-Tenant"]).toBe("t-9");
    // resolved values stay out of server.headers — static rules must not
    // mistake an env-var reference for a stored credential
    expect(server.headers).toBeUndefined();
  });

  it("omits headers when the referenced env var is unset", () => {
    const server = makeServer({
      url: "https://x.example",
      headers: { "X-Static": "v" },
      raw: { bearer_token_env_var: "FSCK_DEFINITELY_UNSET_VAR" },
    });
    const headers = resolvedHeaders(server);
    expect(headers).toEqual({ "X-Static": "v" });
  });
});

const FRAMED = fileURLToPath(new URL("./fixtures/framed-mcp-server.mjs", import.meta.url));

function listen(server: ReturnType<typeof createServer>): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as AddressInfo).port);
    });
  });
}

describe("stdio framing", () => {
  it("reassembles a Content-Length frame split across chunks", () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 2, result: { tools: [] } });
    const frame = Buffer.from(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    const head = takeStdioMessages(frame.subarray(0, 12));
    expect(head.messages).toHaveLength(0);
    const rest = takeStdioMessages(Buffer.concat([head.buffer, frame.subarray(12)]));
    expect(rest.messages[0]?.id).toBe(2);
    expect(rest.buffer).toHaveLength(0);
  });

  it("reads a live Content-Length tools/list response", async () => {
    const server = makeServer({ command: process.execPath, args: [FRAMED] });
    const result = await enumerateTools(server, 8_000, "0.3.0");
    expect(result.status).toBe("ok");
    expect(result.tools.map((tool) => tool.name)).toEqual(["ping"]);
  });

  it("reports a process that exits before the handshake instead of waiting out the timeout", async () => {
    const server = makeServer({ command: process.execPath, args: ["-e", "process.exit(0)"] });
    const started = Date.now();
    const result = await enumerateTools(server, 8_000);
    expect(result.status).toBe("error");
    expect(result.error).toMatch(/exited/i);
    expect(Date.now() - started).toBeLessThan(5_000);
  });
});

describe("prepareDeepRequest", () => {
  it("strips credential headers and URL userinfo from non-local HTTP", () => {
    const remote = prepareDeepRequest(
      makeServer({ url: "http://user:s3cret@api.example.com/mcp", headers: { Authorization: "Bearer abc", "X-Tenant": "acme" } }),
    );
    expect(remote.withheld).toBe(true);
    expect(remote.headers["Authorization"]).toBeUndefined();
    expect(remote.headers["X-Tenant"]).toBe("acme");
    expect(remote.url).not.toContain("s3cret");
    const local = prepareDeepRequest(makeServer({ url: "http://127.0.0.1:9/mcp", headers: { Authorization: "Bearer abc" } }));
    expect(local.withheld).toBe(false);
    expect(local.headers["Authorization"]).toBe("Bearer abc");
  });
});

describe("pullSseEvents", () => {
  it("keeps an incomplete event in rest", () => {
    const pulled = pullSseEvents("event: endpoint\ndata: /messages\n\nevent: message\ndata: {");
    expect(pulled.events).toEqual([{ event: "endpoint", data: "/messages" }]);
    expect(pulled.rest).toContain("event: message");
  });
});

describe("remote handshakes", () => {
  it("sends the streamable-HTTP session id before tools/list", async () => {
    const seen: string[] = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        const msg = JSON.parse(body) as { id?: number; method?: string };
        if (msg.method === "tools/list") {
          seen.push(String(req.headers["mcp-session-id"] ?? ""));
          seen.push(String(req.headers["mcp-protocol-version"] ?? ""));
          if (req.headers["mcp-session-id"] !== "sess-1") {
            res.writeHead(400);
            res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { message: "missing session" } }));
            return;
          }
        }
        if (msg.id === undefined) {
          res.writeHead(202);
          res.end();
          return;
        }
        const result = msg.method === "tools/list"
          ? { tools: [{ name: "ping", description: "http pong" }] }
          : { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "http", version: "0" } };
        res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "sess-1" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
      });
    });
    const port = await listen(server);
    try {
      const result = await enumerateTools(makeServer({ name: "remote", url: `http://127.0.0.1:${port}/mcp` }), 8_000, "0.3.0");
      expect(result.status, result.error).toBe("ok");
      expect(result.tools.map((tool) => tool.name)).toEqual(["ping"]);
      expect(seen).toEqual(["sess-1", "2024-11-05"]);
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });

  it("does not call a websocket URL", async () => {
    const result = await enumerateTools(makeServer({ url: "wss://example.com/mcp" }), 1_000);
    expect(result.status).toBe("error");
    expect(result.error).toContain("websocket");
  });

  it("enumerates tools over the classic SSE endpoint event", async () => {
    const clients = new Set<ServerResponse>();
    const server = createServer((req, res) => {
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "text/event-stream", connection: "keep-alive", "cache-control": "no-cache" });
        res.write("event: endpoint\ndata: /messages\n\n");
        clients.add(res);
        req.on("close", () => clients.delete(res));
        return;
      }
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        const msg = JSON.parse(body) as { id?: number; method?: string };
        res.writeHead(202);
        res.end();
        if (msg.id === undefined) return;
        const result = msg.method === "tools/list"
          ? { tools: [{ name: "ping", description: "sse pong" }] }
          : { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "sse", version: "0" } };
        const frame = `event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result })}\n\n`;
        for (const client of clients) client.write(frame);
      });
    });
    const port = await listen(server);
    try {
      const result = await enumerateTools(
        makeServer({ name: "events", transport: "sse", url: `http://127.0.0.1:${port}/sse` }),
        8_000,
        "0.3.0",
      );
      expect(result.status, result.error).toBe("ok");
      expect(result.tools.map((tool) => tool.name)).toEqual(["ping"]);
    } finally {
      for (const client of clients) client.end();
      server.closeAllConnections();
      server.close();
    }
  });
});
