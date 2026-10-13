import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { candidateConfigFiles, discoverConfigs, loadExplicitConfigs, mcpJsonUnderUserDir, projectSearchDirs } from "../src/discovery.js";
import { scan } from "../src/scan.js";

describe("discovery", () => {
  it("includes profile mcp.json paths under a user dir", () => {
    const dir = mkdtempSync(join(tmpdir(), "fsck-user-"));
    mkdirSync(join(dir, "profiles", "work"), { recursive: true });
    const paths = mcpJsonUnderUserDir(dir);
    expect(paths).toContain(join(dir, "mcp.json"));
    expect(paths).toContain(join(dir, "profiles", "work", "mcp.json"));
  });

  it("honors CLAUDE_CONFIG_DIR without dropping the home file", () => {
    const dir = mkdtempSync(join(tmpdir(), "fsck-claude-"));
    const previous = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const claude = candidateConfigFiles("/tmp").find((candidate) => candidate.client === "claude-code");
      expect(claude?.paths).toContain(join(dir, ".claude.json"));
      expect(claude?.paths.some((path) => path.endsWith(".claude.json"))).toBe(true);
    } finally {
      if (previous === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = previous;
    }
  });

  it("discovers project configs that exist and skips paths that do not", () => {
    const dir = mkdtempSync(join(tmpdir(), "fsck-proj-"));
    mkdirSync(join(dir, ".amazonq"));
    writeFileSync(
      join(dir, ".mcp.json"),
      JSON.stringify({ mcpServers: { local: { command: "node", args: ["srv.js"] } } }),
    );
    writeFileSync(
      join(dir, ".amazonq", "mcp.json"),
      JSON.stringify({ mcpServers: { q: { command: "q-mcp" } } }),
    );
    const { configs } = discoverConfigs(dir);
    expect(configs.some((config) => !config.exists)).toBe(false);
    expect(configs.find((config) => config.path === join(dir, ".mcp.json"))?.servers.map((server) => server.name)).toEqual(["local"]);
    expect(configs.find((config) => config.path === join(dir, ".amazonq", "mcp.json"))?.servers.map((server) => server.name)).toEqual(["q"]);
  });

  it("scans project configs up through the git root and not above it", () => {
    const top = mkdtempSync(join(tmpdir(), "fsck-git-"));
    const root = join(top, "repo");
    const sub = join(root, "packages", "app");
    mkdirSync(join(sub, ".cursor"), { recursive: true });
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { rootish: { command: "root-mcp" } } }));
    writeFileSync(join(top, ".mcp.json"), JSON.stringify({ mcpServers: { outside: { command: "nope" } } }));
    writeFileSync(join(sub, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { local: { command: "local-mcp" } } }));
    expect(projectSearchDirs(sub)).toEqual([sub, join(root, "packages"), root]);
    const { configs } = discoverConfigs(sub);
    expect(configs.find((config) => config.path === join(root, ".mcp.json"))?.servers.map((server) => server.name)).toEqual(["rootish"]);
    expect(configs.find((config) => config.path === join(sub, ".cursor", "mcp.json"))?.servers.map((server) => server.name)).toEqual(["local"]);
    expect(configs.some((config) => config.path === join(top, ".mcp.json"))).toBe(false);
  });

  it("keeps an unreadable path as an existing config so the scan can fail it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "fsck-dir-"));
    const [config] = loadExplicitConfigs([dir]);
    expect(config!.exists).toBe(true);
    expect(config!.error).toBeDefined();
    const result = await scan({ deep: false, timeoutMs: 1_000 }, [config!]);
    expect(result.findings.some((finding) => finding.ruleId === "MCP017")).toBe(true);
    expect(result.findings.find((finding) => finding.ruleId === "MCP017")?.severity).toBe("high");
  });
});
