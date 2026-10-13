import { describe, expect, it } from "vitest";
import { renderTerminal } from "../src/report.js";
import type { ScanResult } from "../src/types.js";

function stripAnsi(text: string): string {
  return text.replace(/\u001B\[[0-9;]*[a-zA-Z]/g, "");
}

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scannedAt: "2026-01-01T00:00:00.000Z",
    deepUsed: false,
    configs: [
      {
        path: "/work/mcp.json",
        client: "explicit",
        exists: true,
        servers: [
          { name: "local", transport: "stdio", command: "node", args: ["srv.js"], source: "/work/mcp.json", client: "explicit", raw: {} },
        ],
        skipped: [{ name: "old", reason: "disabled" }],
      },
    ],
    deep: [],
    findings: [],
    suppressed: [],
    warnings: [],
    grades: [
      { source: "/work/mcp.json", grade: "A", score: 0, findings: 0 },
      { source: "/work/mcp.json", server: "local", grade: "A", score: 0, findings: 0, tools: 2 },
    ],
    summary: {
      configsScanned: 1,
      serversFound: 1,
      findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      suppressed: 0,
      grade: "A",
      score: 0,
      disabled: 1,
    },
    ...overrides,
  };
}

describe("renderTerminal", () => {
  it("prints the summary grade, a disabled server, and a deep tool count", () => {
    const text = stripAnsi(renderTerminal({ ...result(), deepUsed: true }, "0.3.0"));
    expect(text).toContain("overall grade A (score 0)");
    expect(text).toContain("1 disabled");
    expect(text).toContain("old");
    expect(text).toContain("disabled, not scanned");
    expect(text).toContain("2 tools");
    expect(text).toContain("grade A");
  });
});
