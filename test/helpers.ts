import type { DeepResult, DeepTool, ParsedServer, RuleContext, Transport } from "../src/types.js";
import { ALL_RULES } from "../src/rules/index.js";

export function makeServer(overrides: {
  name?: string;
  transport?: Transport;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  source?: string;
} = {}): ParsedServer {
  const transport = overrides.transport ?? (overrides.url !== undefined ? "http" : "stdio");
  return {
    name: overrides.name ?? "test-server",
    transport,
    command: overrides.command,
    args: overrides.args,
    env: overrides.env,
    url: overrides.url,
    headers: overrides.headers,
    source: overrides.source ?? "/test/config.json",
    client: "test",
    raw: {},
  };
}

/** Run a single static rule by id against a server. */
export function runStaticRule(ruleId: string, server: ParsedServer, context: RuleContext) {
  const rule = ALL_RULES.find((r) => r.meta.id === ruleId);
  if (rule === undefined) throw new Error(`unknown rule ${ruleId}`);
  return rule.run(server, context);
}

export function deepResultFor(server: ParsedServer, tools: DeepTool[]): [string, DeepResult] {
  return [`${server.source}::${server.name}`, { server: server.name, source: server.source, status: "ok", tools }];
}
