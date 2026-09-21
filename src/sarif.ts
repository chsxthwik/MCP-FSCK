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
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
  partialFingerprints: { "mcp-fsck/v1": string };
  suppressions?: Array<{ kind: string }>;
}

function toResult(finding: Finding, suppressed: boolean): SarifResult {
  const text =
    `${finding.title}. ${finding.detail}` +
    (finding.evidence !== undefined ? `\nEvidence: ${finding.evidence}` : "") +
    `\nRemediation: ${finding.remediation}`;
  const result: SarifResult = {
    ruleId: finding.ruleId,
    level: LEVEL[finding.severity],
    message: { text },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: `file://${finding.source}` },
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

export function renderSarif(result: ScanResult, version: string): string {
  const suppressed = result.suppressed ?? [];
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
            ...result.findings.map((f) => toResult(f, false)),
            ...suppressed.map((f) => toResult(f, true)),
          ],
        },
      ],
    },
    null,
    2,
  );
}
