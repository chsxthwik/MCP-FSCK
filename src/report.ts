import pc from "picocolors";
import { grade, riskScore } from "./score.js";
import { SEVERITY_ORDER, type ConfigFile, type Finding, type ParsedServer, type ScanResult, type Severity } from "./types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function severityColor(severity: Severity, text: string): string {
  switch (severity) {
    case "critical":
      return pc.bold(pc.bgRed(pc.white(` ${text} `)));
    case "high":
      return pc.bold(pc.red(text));
    case "medium":
      return pc.yellow(text);
    case "low":
      return pc.blue(text);
    case "info":
      return pc.gray(text);
  }
}

function gradeColor(letter: string): string {
  if (letter === "A" || letter === "B") return pc.green(letter);
  if (letter === "C" || letter === "D") return pc.yellow(letter);
  return pc.red(letter);
}

function abbreviateHome(path: string): string {
  const home = process.env.HOME ?? "";
  if (home.length > 1 && path.startsWith(home)) return `~${path.slice(home.length)}`;
  return path;
}

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(current);
  return lines.join(`\n${indent}`);
}

function serverLabel(server: ParsedServer): string {
  if (server.transport === "stdio" && server.command !== undefined) {
    return `${server.name} ${pc.dim(`(${server.command})`)}`;
  }
  return `${server.name} ${pc.dim(`(${server.url ?? "remote"})`)}`;
}

function renderServerFindings(findings: Finding[]): string[] {
  const lines: string[] = [];
  for (const finding of findings) {
    lines.push(`    ${severityColor(finding.severity, SEVERITY_LABEL[finding.severity])} ${pc.dim(`[${finding.ruleId}]`)} ${pc.bold(finding.ruleName)}`);
    lines.push(`        ${finding.title}${finding.deep ? pc.dim("  · live") : ""}`);
    lines.push(`        ${pc.dim(wrap(finding.detail, 92, "          "))}`);
    if (finding.evidence !== undefined) {
      lines.push(`        ${pc.italic(pc.dim(`evidence: ${wrap(finding.evidence, 90, "           ")}`))}`);
    }
    lines.push(`        ${pc.green("→")} ${pc.dim(wrap(finding.remediation, 90, "           "))}`);
  }
  return lines;
}

function renderConfig(config: ConfigFile, findings: Finding[], indent: string): string[] {
  const lines: string[] = [];
  const header = `${config.client} ${pc.dim(abbreviateHome(config.path))}`;
  lines.push(`${indent}${pc.bold(header)}`);
  if (config.error !== undefined) {
    lines.push(`${indent}  ${pc.red("parse error:")} ${config.error}`);
  }
  if (config.servers.length === 0) {
    if (config.exists) lines.push(`${indent}  ${pc.dim("no MCP servers defined")}`);
    return lines;
  }
  for (const server of config.servers) {
    const serverFindings = findings.filter((f) => f.source === config.path && f.server === server.name);
    const score = riskScore(serverFindings);
    const letter = grade(score, serverFindings.some((f) => f.severity === "critical"));
    lines.push(`${indent}  ${serverLabel(server)}  ${pc.dim("grade")} ${gradeColor(letter)} ${pc.dim(`(score ${score}, ${serverFindings.length} finding${serverFindings.length === 1 ? "" : "s"})`)}`);
    if (serverFindings.length === 0) {
      lines.push(`${indent}      ${pc.green("✓")} ${pc.dim("no findings")}`);
    } else {
      lines.push(...renderServerFindings(serverFindings));
    }
  }
  return lines;
}

export function renderTerminal(result: ScanResult, version: string): string {
  const lines: string[] = [];
  const s = result.summary;
  const counts = [
    { n: s.findings.critical, label: "critical" },
    { n: s.findings.high, label: "high" },
    { n: s.findings.medium, label: "medium" },
    { n: s.findings.low, label: "low" },
    { n: s.findings.info, label: "info" },
  ]
    .filter((c) => c.n > 0)
    .map((c) => `${c.n} ${c.label}`)
    .join(", ");

  lines.push("");
  lines.push(`  ${pc.bold("mcp-fsck")} ${pc.dim(`v${version} — integrity check for MCP server configs`)}`);
  lines.push(
    `  scanned ${s.configsScanned} config file${s.configsScanned === 1 ? "" : "s"} · ${s.serversFound} server${s.serversFound === 1 ? "" : "s"} · ${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}${counts.length > 0 ? ` (${counts})` : ""}`,
  );
  if (result.deepUsed) {
    lines.push(`  ${pc.dim("deep mode: live tools/list handshakes were performed (no tools were executed)")}`);
  }
  lines.push("");

  const scannedConfigs = result.configs.filter((c) => c.exists);
  if (scannedConfigs.length === 0) {
    lines.push("  No MCP config files found. Pass paths explicitly: `mcp-fsck scan path/to/config.json`");
    lines.push("");
    return lines.join("\n");
  }

  for (const config of scannedConfigs) {
    lines.push(...renderConfig(config, result.findings, "  "));
    lines.push("");
  }

  const deepProblems = result.deep.filter((d) => d.status !== "ok");
  if (result.deepUsed && deepProblems.length > 0) {
    lines.push(`  ${pc.dim("servers that could not be enumerated in deep mode:")}`);
    for (const d of deepProblems) {
      lines.push(`    ${pc.dim(`· ${d.server}: ${d.status}${d.error !== undefined ? ` — ${d.error}` : ""}`)}`);
    }
    lines.push("");
  }

  lines.push(`  ${pc.dim("scanned at")} ${result.scannedAt}`);
  lines.push("");
  return lines.join("\n");
}

export function renderJson(result: ScanResult, version: string): string {
  return JSON.stringify({ tool: "mcp-fsck", version, ...result }, null, 2);
}

export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export { SEVERITY_LABEL };
