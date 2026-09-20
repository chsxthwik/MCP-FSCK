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

  it("coerces non-string args and env values instead of dropping the server", () => {
    const text = JSON.stringify({
      mcpServers: { srv: { command: "node", args: ["server.js", 3000], env: { DEBUG: true, PORT: 8080 } } },
    });
    const { servers } = parseConfigContents("/p", "test", text);
    expect(servers).toHaveLength(1);
    expect(servers[0]!.args).toEqual(["server.js", "3000"]);
    expect(servers[0]!.env).toEqual({ DEBUG: "true", PORT: "8080" });
  });

  it("parses Zed context_servers entries", () => {
    const text = JSON.stringify({
      context_servers: {
        fs: { command: { path: "npx", args: ["-y", "server-fs"], env: { A: "1" } } },
        remote: { url: "https://mcp.example.com" },
        off: { enabled: false, command: { path: "gone" } },
      },
    });
    const { servers } = parseConfigContents("/p", "zed", text);
    expect(servers).toHaveLength(2);
    expect(servers[0]).toMatchObject({ name: "fs", command: "npx", args: ["-y", "server-fs"] });
    expect(servers[1]).toMatchObject({ name: "remote", transport: "http" });
  });

  it("parses Codex config.toml mcp_servers tables", () => {
    const text = `
# comment
[mcp_servers.docs]
command = "npx"
args = ["-y", "@org/mcp-docs@1.2.3"]
env = { API_KEY = "abc" }

[mcp_servers.remote]
url = "https://mcp.example.com"
http_headers = { Authorization = "Bearer tok" }
`;
    const { servers, error } = parseConfigContents("/x/config.toml", "codex", text);
    expect(error).toBeUndefined();
    expect(servers).toHaveLength(2);
    expect(servers[0]).toMatchObject({ name: "docs", command: "npx", args: ["-y", "@org/mcp-docs@1.2.3"], env: { API_KEY: "abc" } });
    expect(servers[1]).toMatchObject({ name: "remote", transport: "http", headers: { Authorization: "Bearer tok" } });
  });

  it("parses nested [mcp_servers.name.env] tables", () => {
    const text = `
[mcp_servers.srv]
command = "node"
[mcp_servers.srv.env]
TOKEN = "x"
`;
    const { servers } = parseConfigContents("/x/config.toml", "codex", text);
    expect(servers[0]!.env).toEqual({ TOKEN: "x" });
  });

  it("reports invalid TOML as an error", () => {
    const { servers, error } = parseConfigContents("/x/config.toml", "codex", "[unterminated");
    expect(servers).toHaveLength(0);
    expect(error).toContain("TOML");
  });
});
