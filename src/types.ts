export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export type Transport = "stdio" | "http" | "sse";

/** A normalized MCP server entry from any client config format. */
export interface ParsedServer {
  name: string;
  transport: Transport;
  /** stdio */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** remote */
  url?: string;
  headers?: Record<string, string>;
  /** config file this entry came from */
  source: string;
  /** which client app owns the config, e.g. "claude-desktop" */
  client: string;
  raw: unknown;
}

export interface ConfigFile {
  path: string;
  client: string;
  exists: boolean;
  servers: ParsedServer[];
  /** parse error, if the file exists but could not be read/parsed */
  error?: string;
}

export interface DeepTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** Result of a live tools/list handshake against one server. */
export interface DeepResult {
  server: string;
  source: string;
  status: "ok" | "error" | "timeout";
  error?: string;
  tools: DeepTool[];
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  title: string;
  detail: string;
  remediation: string;
  /** path of the config file the finding came from */
  source: string;
  /** server name, when the finding is scoped to one */
  server?: string;
  /** redacted evidence */
  evidence?: string;
  /** true when the finding was produced by live tool enumeration */
  deep?: boolean;
}

export interface RuleMeta {
  id: string;
  name: string;
  severity: Severity;
  scope: "static" | "deep";
  description: string;
  remediation: string;
}

export interface ScanOptions {
  deep: boolean;
  /** per-server timeout for deep mode, in milliseconds */
  timeoutMs: number;
}

export interface ScanSummary {
  configsScanned: number;
  serversFound: number;
  findings: Record<Severity, number>;
}

export interface ScanResult {
  scannedAt: string;
  deepUsed: boolean;
  configs: ConfigFile[];
  deep: DeepResult[];
  findings: Finding[];
  summary: ScanSummary;
}

/** A finding before the engine stamps rule id, name and provenance onto it. */
export interface RawFinding {
  title: string;
  detail: string;
  evidence?: string;
  remediation?: string;
  severity?: Severity;
}

export interface RuleContext {
  /** all parsed servers across every discovered config (for cross-file rules) */
  allServers: ParsedServer[];
  /** deep-mode results, when enabled */
  deep: Map<string, DeepResult>;
}

export type RuleFn = (server: ParsedServer, context: RuleContext) => RawFinding[];
