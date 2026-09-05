import { describe, expect, it } from "vitest";
import { parseConfigContents } from "../src/parse.js";

describe("parseConfigContents", () => {
  it("parses the mcpServers shape", () => {
    const text = JSON.stringify({
      mcpServers: {
        fs: { command: "npx", args: ["-y", "server-fs"], env: { K: "v" } },
        remote: { type: "http", url: "https://example.com/mcp", headers: { Authorization: "Bearer x" } },
        sse: { type: "sse", url: "https://example.com/sse" },
      },
    });
    const { servers, error } = parseConfigContents("/p", "test", text);
    expect(error).toBeUndefined();
    expect(servers).toHaveLength(3);
    expect(servers[0]).toMatchObject({ name: "fs", transport: "stdio", command: "npx" });
    expect(servers[1]).toMatchObject({ name: "remote", transport: "http", url: "https://example.com/mcp" });
    expect(servers[2]).toMatchObject({ name: "sse", transport: "sse" });
  });

  it("parses the VS Code servers shape", () => {
    const text = JSON.stringify({
      servers: { fs: { type: "stdio", command: "node", args: ["server.js"] } },
    });
    const { servers } = parseConfigContents("/p", "vscode", text);
    expect(servers).toHaveLength(1);
    expect(servers[0]).toMatchObject({ name: "fs", transport: "stdio", command: "node" });
  });

  it("tolerates comments and trailing commas (JSONC)", () => {
    const text = `{
      // a comment
      "mcpServers": {
        "fs": { "command": "node", "args": ["a.js"], /* inline */ },
      },
    }`;
    const { servers, error } = parseConfigContents("/p", "test", text);
    expect(error).toBeUndefined();
    expect(servers).toHaveLength(1);
  });

  it("reports invalid JSON as an error", () => {
    const { servers, error } = parseConfigContents("/p", "test", "{ not json ]");
    expect(servers).toHaveLength(0);
    expect(error).toContain("not valid JSON");
  });

  it("skips entries it cannot normalize", () => {
    const text = JSON.stringify({ mcpServers: { broken: { args: ["no command"] }, ok: { command: "node" } } });
    const { servers } = parseConfigContents("/p", "test", text);
    expect(servers.map((s) => s.name)).toEqual(["ok"]);
  });
});
