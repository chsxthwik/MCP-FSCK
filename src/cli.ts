import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { baselineFrom, loadBaseline, resolveBaselinePath, writeBaseline, DEFAULT_BASELINE_NAME } from "./baseline.js";
import { DEFAULT_TIMEOUT_MS } from "./deep.js";
import { discoverConfigs, loadExplicitConfigs } from "./discovery.js";
import { renderJson, renderTerminal, severityAtLeast } from "./report.js";
import { ALL_RULES } from "./rules/index.js";
import { mayContainSecret, redactCommandArg, redactKnownSecrets } from "./rules/static.js";
import { renderSarif } from "./sarif.js";
import { scan } from "./scan.js";
import { worstSeverity } from "./score.js";
import { isCredentialHeaderName, looksLikePlaceholder, redactSecret } from "./util.js";
import type { ScanOptions, Severity, ConfigFile, IgnoreEntry } from "./types.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as { version: string };

const FAIL_ON_VALUES = ["critical", "high", "medium", "low", "info", "none"] as const;

/**
 * Deep-copy configs with env/header values that look like credentials
 * redacted, so `--json` output is safe to paste into CI logs or issues.
 */
function redactConfigValue(key: string, value: string, header: boolean): string {
  const credentialHeader = header && isCredentialHeaderName(key) && value.length >= 8 && !looksLikePlaceholder(value);
  if (mayContainSecret(key, value) || credentialHeader) return redactSecret(value);
  return redactKnownSecrets(value);
}

function redactRecord(record: Record<string, string> | undefined, header = false): Record<string, string> | undefined {
  if (record === undefined) return undefined;
  return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, redactConfigValue(key, value, header)]));
}

function sanitizeUrl(value: string): string {
  try {
    const url = new URL(value);
    if (url.username !== "" || url.password !== "") {
      url.username = url.username === "" ? "" : "redacted";
      url.password = url.password === "" ? "" : "redacted";
    }
    return redactKnownSecrets(url.toString());
  } catch {
    return redactKnownSecrets(value);
  }
}

function sanitizeConfigsForJson(configs: ConfigFile[]): ConfigFile[] {
  return configs.map((config) => ({
    ...config,
    servers: config.servers.map((server) => ({
      ...server,
      command: server.command === undefined ? undefined : redactKnownSecrets(server.command),
      args: server.args?.map((arg) => redactCommandArg(arg)),
      env: redactRecord(server.env),
      headers: redactRecord(server.headers, true),
      url: server.url === undefined ? undefined : sanitizeUrl(server.url),
      raw: undefined,
    })),
  }));
}

async function runScan(
  paths: string[],
  opts: { deep?: boolean; timeout?: string; json?: boolean; failOn?: string; sarif?: string; baseline?: string; writeBaseline?: string | boolean },
): Promise<void> {
  const failOn = (opts.failOn ?? "high") as (typeof FAIL_ON_VALUES)[number];
  if (!FAIL_ON_VALUES.includes(failOn)) {
    console.error(`mcp-fsck: invalid --fail-on value "${failOn}" (expected one of ${FAIL_ON_VALUES.join(", ")})`);
    process.exitCode = 2;
    return;
  }
  const timeoutMs = Number.parseInt(opts.timeout ?? String(DEFAULT_TIMEOUT_MS), 10);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    console.error("mcp-fsck: --timeout must be a positive number of milliseconds");
    process.exitCode = 2;
    return;
  }

  let baseline: IgnoreEntry[] = [];
  const baselinePath = resolveBaselinePath(opts.baseline);
  if (baselinePath !== null) {
    try {
      baseline = loadBaseline(baselinePath).ignore;
    } catch (err) {
      console.error(`mcp-fsck: cannot load baseline ${baselinePath}: ${(err as Error).message}`);
      process.exitCode = 2;
      return;
    }
  }

  const configs = paths.length > 0 ? loadExplicitConfigs(paths) : discoverConfigs().configs;
  const missing = configs.filter((config) => !config.exists);
  if (missing.length > 0) {
    for (const config of missing) console.error(`mcp-fsck: config not found: ${config.path}`);
    process.exitCode = 2;
    return;
  }
  const options: ScanOptions = { deep: opts.deep === true, timeoutMs, baseline, clientVersion: pkg.version };
  const result = await scan(options, configs);

  if (opts.writeBaseline !== undefined) {
    const target = typeof opts.writeBaseline === "string" ? opts.writeBaseline : DEFAULT_BASELINE_NAME;
    writeBaseline(target, baselineFrom([...result.findings, ...(result.suppressed ?? [])]));
    console.log(`Wrote baseline ${target}: ${result.findings.length + (result.suppressed?.length ?? 0)} finding(s) recorded.`);
    return;
  }

  if (opts.sarif !== undefined) {
    writeFileSync(opts.sarif, renderSarif(result, pkg.version));
  }

  if (opts.json === true) {
    console.log(renderJson({ ...result, configs: sanitizeConfigsForJson(result.configs) }, pkg.version));
  } else {
    console.log(renderTerminal(result, pkg.version));
  }
  if (opts.sarif !== undefined && opts.json !== true) {
    console.log(`  SARIF written to ${opts.sarif}`);
  }

  if (failOn !== "none") {
    const worst = worstSeverity(result.findings);
    if (worst !== null && severityAtLeast(worst, failOn as Severity)) {
      process.exitCode = 1;
      const count = result.findings.length;
      console.error(`mcp-fsck: ${count} finding(s), worst is ${worst}, fail-on is ${failOn}`);
    }
  }
}

const program = new Command();

program
  .name("mcp-fsck")
  .description("Integrity check for MCP server configs: audits Claude, Cursor, VS Code, Windsurf, Zed, Codex, Gemini and JetBrains/Cline/Roo agent configurations for secrets, injection-prone args, tool poisoning and dangerous capability combinations.")
  .version(pkg.version);

program
  .command("scan", { isDefault: true })
  .description("Scan discovered MCP configs (or the config files passed as arguments).")
  .argument("[paths...]", "explicit config file paths to scan instead of auto-discovery")
  .option("--deep", "enumerate tools from running MCP servers (executes the servers; only audit configs you control)")
  .option("--timeout <ms>", "per-server timeout for deep mode, in milliseconds", String(DEFAULT_TIMEOUT_MS))
  .option("--json", "machine-readable JSON output (secrets redacted)", false)
  .option("--sarif <file>", "also write findings as SARIF 2.1.0 (for codeql-action/upload-sarif)")
  .option("--baseline <file>", `suppression file (default: ${DEFAULT_BASELINE_NAME} in the working directory)`)
  .option("--write-baseline [file]", `record current findings as accepted in a suppression file (default: ${DEFAULT_BASELINE_NAME})`)
  .option("--fail-on <severity>", "exit 1 when findings at or above this severity exist", "high")
  .action(runScan);

program
  .command("list")
  .description("Show which MCP config files were discovered on this machine and the servers they define.")
  .action(() => {
    const { configs } = discoverConfigs();
    const found = configs.filter((c) => c.exists);
    if (found.length === 0) {
      console.log("No MCP config files found.");
      return;
    }
    for (const config of found) {
      console.log(`${config.client}  ${config.path}${config.error !== undefined ? `  (parse error: ${config.error})` : ""}`);
      for (const server of config.servers) {
        const target = server.transport === "stdio" ? `${server.command} ${(server.args ?? []).join(" ")}` : server.url ?? "";
        console.log(`  · ${server.name} (${server.transport}) ${target}`);
      }
      if (config.servers.length === 0) console.log("  · (no servers defined)");
    }
  });

program
  .command("rules")
  .description("List the audit rules and their severities.")
  .action(() => {
    for (const rule of ALL_RULES) {
      console.log(`${rule.meta.id}  ${rule.meta.name.padEnd(34)} ${rule.meta.scope.padEnd(7)} ${rule.meta.severity.padEnd(9)} ${rule.meta.description}`);
    }
  });

program.parseAsync(process.argv).catch((err: Error) => {
  console.error(`mcp-fsck: ${err.message}`);
  process.exitCode = 2;
});
