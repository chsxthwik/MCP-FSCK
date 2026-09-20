import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyBaseline, baselineFrom, loadBaseline } from "../src/baseline.js";
import type { Finding } from "../src/types.js";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "MCP004",
    ruleName: "auto-install-unpinned-package",
    severity: "medium",
    title: "t",
    detail: "d",
    remediation: "r",
    source: "/cfg/mcp.json",
    server: "fs",
    ...overrides,
  };
}

describe("applyBaseline", () => {
  const a = finding({ server: "fs" });
  const b = finding({ ruleId: "MCP002", server: "updater", severity: "critical" });

  it("suppresses only matching findings", () => {
    const { kept, suppressed } = applyBaseline([a, b], [{ rule: "MCP004", server: "fs" }]);
    expect(kept).toEqual([b]);
    expect(suppressed).toEqual([a]);
  });

  it("supports server wildcard", () => {
    const { suppressed } = applyBaseline([a, b], [{ rule: "MCP002", server: "*" }]);
    expect(suppressed).toEqual([b]);
  });

  it("matches source by substring", () => {
    const { suppressed } = applyBaseline([a], [{ source: "mcp.json" }]);
    expect(suppressed).toHaveLength(1);
  });

  it("an entry with no fields matches nothing", () => {
    const { suppressed } = applyBaseline([a, b], [{}]);
    expect(suppressed).toHaveLength(0);
  });
});

describe("baselineFrom", () => {
  it("emits deduped entries covering the findings", () => {
    const baseline = baselineFrom([finding(), finding()]);
    expect(baseline.ignore).toEqual([{ rule: "MCP004", server: "fs", source: "/cfg/mcp.json" }]);
  });
});

describe("loadBaseline", () => {
  it("reads a baseline file", () => {
    const dir = mkdtempSync(join(tmpdir(), "fsck-base-"));
    const path = join(dir, ".mcp-fsck.json");
    writeFileSync(path, JSON.stringify({ ignore: [{ rule: "MCP005", server: "*" }] }));
    expect(loadBaseline(path).ignore).toEqual([{ rule: "MCP005", server: "*" }]);
  });

  it("rejects malformed baselines", () => {
    const dir = mkdtempSync(join(tmpdir(), "fsck-base-"));
    const path = join(dir, ".mcp-fsck.json");
    writeFileSync(path, "{ \"ignore\": \"nope\" }");
    expect(() => loadBaseline(path)).toThrow();
  });
});
