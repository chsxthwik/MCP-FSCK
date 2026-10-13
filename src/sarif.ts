import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import type { Finding, ScanResult, Severity } from "./types.js";
import { ALL_RULES } from "./rules/index.js";

/** SARIF 2.1.0 writer — uploadable via github/codeql-action/upload-sarif. */

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "warning",
  info: "note",
};

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  partialFingerprints: { "mcp-fsck/v1": string };
  suppressions?: Array<{ kind: string }>;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** 1-based line of the server key, when the config can be read and the name is in it. */
export function findingStartLine(finding: Finding, lines: readonly string[]): number | undefined {
  if (finding.server === undefined) return lines.length > 0 ? 1 : undefined;
  const names = [finding.server];
  const scoped = finding.server.split(" @ ")[0];
  if (scoped !== undefined && scoped !== finding.server) names.push(scoped);
  const patterns = names.flatMap((name) => {
    const escaped = escapeRegExp(name);
    return [
      new RegExp(`["']${escaped}["']\\s*:`),
      new RegExp(`\\[mcp_servers\\.${escaped}(?:\\.|\\])`),
    ];
  });
  for (let i = 0; i < lines.length; i += 1) {
    if (patterns.some((pattern) => pattern.test(lines[i]!))) return i + 1;
  }
  return undefined;
}

function toResult(finding: Finding, suppressed: boolean, lines: readonly string[] | undefined): SarifResult {
  const text =
    `${finding.title}. ${finding.detail}` +
    (finding.evidence !== undefined ? `\nEvidence: ${finding.evidence}` : "") +
    `\nRemediation: ${finding.remediation}`;
  const startLine = lines === undefined ? undefined : findingStartLine(finding, lines);
  const result: SarifResult = {
    ruleId: finding.ruleId,
    level: LEVEL[finding.severity],
    message: { text },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: pathToFileURL(finding.source).href },
          ...(startLine !== undefined ? { region: { startLine } } : {}),
        },
      },
    ],
    partialFingerprints: {
      "mcp-fsck/v1": `${finding.ruleId}:${finding.source}:${finding.server ?? ""}:${finding.title}`,
    },
  };
  if (suppressed) result.suppressions = [{ kind: "external" }];
  return result;
}

function linesOf(path: string, cache: Map<string, string[] | null>): string[] | undefined {
  const cached = cache.get(path);
  if (cached !== undefined) return cached ?? undefined;
  try {
    const lines = readFileSync(path, "utf8").split(/\r?\n/);
    cache.set(path, lines);
    return lines;
  } catch {
    cache.set(path, null);
    return undefined;
  }
}

export function renderSarif(result: ScanResult, version: string): string {
  const suppressed = result.suppressed ?? [];
  const cache = new Map<string, string[] | null>();
  const locate = (finding: Finding): string[] | undefined => linesOf(finding.source, cache);
  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "mcp-fsck",
              version,
              informationUri: "https://github.com/chsxthwik/mcp-fsck",
              rules: ALL_RULES.map((r) => ({
                id: r.meta.id,
                name: r.meta.name,
                shortDescription: { text: r.meta.description },
                help: { text: r.meta.remediation },
                defaultConfiguration: { level: LEVEL[r.meta.severity] },
              })),
            },
          },
          results: [
            ...result.findings.map((f) => toResult(f, false, locate(f))),
            ...suppressed.map((f) => toResult(f, true, locate(f))),
          ],
        },
      ],
    },
    null,
    2,
  );
}
