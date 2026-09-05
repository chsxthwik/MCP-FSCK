import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { discoverConfigs, loadExplicitConfigs } from "./discovery.js";
import { renderJson, renderTerminal, severityAtLeast } from "./report.js";
import { ALL_RULES } from "./rules/index.js";
import { mayContainSecret } from "./rules/static.js";
import { scan } from "./scan.js";
import { worstSeverity } from "./score.js";
import { redactSecret } from "./util.js";
import type { ScanOptions, Severity, ConfigFile } from "./types.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as { version: string };

const FAIL_ON_VALUES = ["critical", "high", "medium", "low", "info", "none"] as const;

/**
 * Deep-copy configs with env/header values that look like credentials
 * redacted, so `--json` output is safe to paste into CI logs or issues.
 */
function sanitizeConfigsForJson(configs: ConfigFile[]): ConfigFile[] {
  return configs.map((config) => ({
    ...config,
    servers: config.servers.map((server) => ({
      ...server,
      env: server.env === undefined
        ? undefined
        : Object.fromEntries(
            Object.entries(server.env).map(([k, v]) => [k, mayContainSecret(k, v) ? redactSecret(v) : v]),
          ),
      headers: server.headers === undefined
        ? undefined
        : Object.fromEntries(
            Object.entries(server.headers).map(([k, v]) => [k, mayContainSecret(k, v) ? redactSecret(v) : v]),
          ),
      raw: undefined,
    })),
  }));
}

async function runScan(paths: string[], opts: { deep?: boolean; timeout?: string; json?: boolean; failOn?: string }): Promise<void> {
  const failOn = (opts.failOn ?? "high") as (typeof FAIL_ON_VALUES)[number];
  if (!FAIL_ON_VALUES.includes(failOn)) {
    console.error(`mcp-fsck: invalid --fail-on value "${failOn}" (expected one of ${FAIL_ON_VALUES.join(", ")})`);
    process.exitCode = 2;
    return;
  }
  const timeoutMs = Number.parseInt(opts.timeout ?? "10000", 10);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    console.error("mcp-fsck: --timeout must be a positive number of milliseconds");
    process.exitCode = 2;
    return;
  }

  const configs = paths.length > 0 ? loadExplicitConfigs(paths) : discoverConfigs().configs;
  const options: ScanOptions = { deep: opts.deep === true, timeoutMs };
  const result = await scan(options, configs);

  if (opts.json === true) {
    console.log(renderJson({ ...result, configs: sanitizeConfigsForJson(result.configs) }, pkg.version));
  } else {
    console.log(renderTerminal(result, pkg.version));
  }

  if (failOn !== "none") {
    const worst = worstSeverity(result.findings);
    if (worst !== null && severityAtLeast(worst, failOn as Severity)) {
      process.exitCode = 1;
    }
  }
}

const program = new Command();

program
  .name("mcp-fsck")
  .description("Integrity check for MCP server configs: audits Claude, Cursor, VS Code and Windsurf agent configurations for secrets, injection-prone args, tool poisoning and dangerous capability combinations.")
  .version(pkg.version);

program
  .command("scan", { isDefault: true })
  .description("Scan discovered MCP configs (or the config files passed as arguments).")
  .argument("[paths...]", "explicit config file paths to scan instead of auto-discovery")
  .option("--deep", "enumerate tools from running MCP servers (executes the servers; only audit configs you control)")
  .option("--timeout <ms>", "per-server timeout for deep mode, in milliseconds", "10000")
  .option("--json", "machine-readable JSON output (secrets redacted)", false)
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
