import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { enumerateTools } from "../src/deep.js";
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

  it("stays quiet for a well-behaved toolset", async () => {
    // a server whose tools have honest, single-capability descriptions
    const server = makeServer({ name: "clean", command: process.execPath, args: [FIXTURE], env: { FAKE_TOOLS: "clean" } });
    const context = await deepContext([server]);
    const findings = runDeepRules(server, context);
    expect(findings).toHaveLength(0);
  });
});
