import { classifyTool, shortList, type Capability } from "../classify.js";
import type { DeepTool, ParsedServer, RawFinding, RuleContext } from "../types.js";

/** Phrases that read as instructions to the model rather than documentation for the user. */
const OVERRIDE_PATTERNS: Array<[RegExp, string]> = [
  [/ignore\s+(all\s+|any\s+|your\s+)?(previous|prior|above|earlier)\s+instructions?/i, "instruction override"],
  [/disregard\s+(all\s+|any\s+|your\s+)?(previous|prior|above)?\s*instructions?/i, "instruction override"],
  [/exfiltrat/i, "exfiltration language"],
  [/send\s+(this|the|all|its|their)\s+(data|content|context|file|results?|credentials?)/i, "data-forwarding instruction"],
  [/upload\s+(this|the|all|its)\s+(data|content|context|file)/i, "data-forwarding instruction"],
  [/post\s+(this|the|all|its)\s+(data|content|context)/i, "data-forwarding instruction"],
];

const SUSPICIOUS_PATTERNS: Array<[RegExp, string]> = [
  [/do\s+not\s+(tell|inform|reveal|mention|disclose)/i, "secrecy instruction"],
  [/don'?t\s+(tell|inform|reveal|mention|disclose)/i, "secrecy instruction"],
  [/never\s+(tell|inform|reveal|mention|disclose)\s+(the\s+)?user/i, "secrecy instruction"],
  [/(hidden|secret|covert)\s+(instruction|prompt|directive)/i, "hidden-directive reference"],
  [/(system\s+prompt|developer\s+message)/i, "system-prompt reference"],
  [/before\s+(anything\s+else|responding|any\s+response)/i, "pre-response directive"],
  [/meant\s+for\s+the\s+(model|llm|assistant|agent)/i, "model-only directive"],
  [/\bbase\s?64\b.{0,20}\b(decod|encod)/i, "encoded payload reference"],
];

/** Unicode that renders as nothing (or reorders text) — a classic hiding place for injection text. */
const HIDDEN_UNICODE: Array<[RegExp, string]> = [
  [/[\u200B-\u200F\u2060-\u2064\uFEFF]/, "zero-width characters"],
  [/[\u202A-\u202E\u2066-\u2069]/, "bidirectional control characters"],
  [/[\uE000-\uF8FF]/, "private-use-area characters"],
];

interface ToolContext {
  server: ParsedServer;
  tools: DeepTool[];
}

function deepToolsFor(server: ParsedServer, context: RuleContext): ToolContext | null {
  const result = context.deep.get(`${server.source}::${server.name}`);
  if (result === undefined || result.status !== "ok") return null;
  return { server, tools: result.tools };
}

function toolInjectionRule(server: ParsedServer, context: RuleContext): RawFinding[] {
  const ctx = deepToolsFor(server, context);
  if (ctx === null) return [];
  const findings: RawFinding[] = [];
  for (const tool of ctx.tools) {
    const description = tool.description ?? "";
    if (description.length === 0) continue;
    for (const [pattern, label] of OVERRIDE_PATTERNS) {
      if (pattern.test(description)) {
        findings.push({
          title: `Tool description contains ${label}`,
          detail: `Tool \`${tool.name}\` on \`${server.name}\` carries hidden instructions to the model (${label}). This is the tool-poisoning pattern: the text is invisible in normal use but steers the agent into leaking or overriding behavior.`,
          evidence: `\u201C${description.slice(0, 160)}\u201D`,
          severity: "critical",
          remediation: "Remove or replace this server; if the tool is required, contact the maintainer and re-audit the description.",
        });
        break;
      }
    }
    for (const [pattern, label] of SUSPICIOUS_PATTERNS) {
      if (pattern.test(description)) {
        findings.push({
          title: `Tool description contains ${label}`,
          detail: `Tool \`${tool.name}\` on \`${server.name}\` contains phrasing addressed to the model rather than the user (${label}).`,
          evidence: `\u201C${description.slice(0, 160)}\u201D`,
          severity: "high",
          remediation: "Inspect the full description and decide whether the server is trustworthy.",
        });
        break;
      }
    }
    for (const [pattern, label] of HIDDEN_UNICODE) {
      if (pattern.test(description)) {
        findings.push({
          title: `Tool description hides text with ${label}`,
          detail: `Tool \`${tool.name}\` on \`${server.name}\` embeds ${label} in its description — commonly used to smuggle instructions past human review.`,
          evidence: `description of tool \`${tool.name}\` (${description.length} chars)`,
          severity: "high",
          remediation: "Dump the description with visible codepoints and review what is hidden.",
        });
        break;
      }
    }
  }
  return findings;
}

function collectCapabilities(tools: DeepTool[]): Map<Capability, string[]> {
  const byCap = new Map<Capability, string[]>();
  for (const tool of tools) {
    for (const cap of classifyTool(tool.name, tool.description).capabilities) {
      const list = byCap.get(cap) ?? [];
      list.push(tool.name);
      byCap.set(cap, list);
    }
  }
  return byCap;
}

interface Combo {
  a: Capability;
  b: Capability;
  severity: "critical" | "high" | "medium";
  why: string;
}

const COMBOS: Combo[] = [
  { a: "exec", b: "network", severity: "critical", why: "runs commands and talks to the network — a single injected instruction can execute attacker-supplied code or ship command output to a remote host" },
  { a: "secrets", b: "network", severity: "critical", why: "can read credentials and talk to the network — a single injected instruction is enough to exfiltrate them" },
  { a: "fs-read", b: "network", severity: "high", why: "can read files and send data over the network — file contents can be forwarded out on instruction" },
  { a: "fs-write", b: "exec", severity: "high", why: "can write files and execute commands — writing a file and then executing it is a code-injection path" },
  { a: "fs-write", b: "network", severity: "medium", why: "can write files and download from the network — payloads can be staged onto disk" },
  { a: "exec", b: "secrets", severity: "medium", why: "can execute commands and access credentials — credential theft reduces to command execution" },
];

function capabilityComboRule(server: ParsedServer, context: RuleContext): RawFinding[] {
  const ctx = deepToolsFor(server, context);
  if (ctx === null) return [];
  const byCap = collectCapabilities(ctx.tools);
  const findings: RawFinding[] = [];
  for (const combo of COMBOS) {
    const a = byCap.get(combo.a);
    const b = byCap.get(combo.b);
    if (a === undefined || b === undefined) continue;
    findings.push({
      title: `Dangerous capability combination: ${combo.a} + ${combo.b}`,
      detail: `Server \`${server.name}\` exposes ${combo.a} tools (${shortList(a)}) and ${combo.b} tools (${shortList(b)}). It ${combo.why}. Every tool description on this server is a potential delivery vehicle for that instruction.`,
      evidence: `${combo.a}: ${shortList(a, 3)} · ${combo.b}: ${shortList(b, 3)}`,
      severity: combo.severity,
      remediation: "Split the capabilities across servers with least privilege, or drop the tools you do not actually use.",
    });
  }
  return findings;
}

function toolShadowingRule(server: ParsedServer, context: RuleContext): RawFinding[] {
  const ctx = deepToolsFor(server, context);
  if (ctx === null) return [];
  // index every tool exposed by *other* servers
  const others: Array<{ server: ParsedServer; tool: DeepTool }> = [];
  for (const [key, result] of context.deep) {
    if (key === `${server.source}::${server.name}`) continue;
    if (result.status !== "ok") continue;
    const owner = context.allServers.find((s) => `${s.source}::${s.name}` === key);
    if (owner === undefined) continue;
    for (const tool of result.tools) others.push({ server: owner, tool });
  }
  if (others.length === 0) return [];
  const findings: RawFinding[] = [];
  const seen = new Set<string>();
  for (const tool of ctx.tools) {
    const description = tool.description ?? "";
    if (description.length === 0) continue;
    for (const { server: owner, tool: otherTool } of others) {
      if (owner.name === server.name) continue;
      const pattern = new RegExp(`\\b${otherTool.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
      if (!pattern.test(description)) continue;
      const key = `${tool.name}->${otherTool.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        title: "Tool description references another server's tool",
        detail: `Tool \`${tool.name}\` on \`${server.name}\` mentions \`${otherTool.name}\` (exposed by \`${owner.name}\`) in its description. Cross-server references in descriptions are the setup for tool-shadowing attacks, where a poisoned tool redirects the agent away from the legitimate one.`,
        evidence: `\u201C${description.slice(0, 160)}\u201D`,
        severity: "medium",
        remediation: "Check whether the reference is legitimate (migration notes) or an attempt to steer tool selection.",
      });
      break;
    }
  }
  return findings;
}

export const deepRules: Array<{ meta: import("../types.js").RuleMeta; run: import("../types.js").RuleFn }> = [
  {
    meta: {
      id: "MCP011",
      name: "tool-description-injection",
      severity: "critical",
      scope: "deep",
      description: "Scans live tool descriptions for poisoning: instruction overrides, secrecy directives, exfiltration language and hidden unicode.",
      remediation: "Remove the server or escalate to the maintainer.",
    },
    run: toolInjectionRule,
  },
  {
    meta: {
      id: "MCP012",
      name: "tool-shadowing",
      severity: "medium",
      scope: "deep",
      description: "Detects tool descriptions that reference tools exposed by other servers (shadowing setup).",
      remediation: "Review cross-server references in tool descriptions.",
    },
    run: toolShadowingRule,
  },
  {
    meta: {
      id: "MCP013",
      name: "dangerous-capability-combo",
      severity: "critical",
      scope: "deep",
      description: "Flags servers that combine exec/network/secrets/filesystem capabilities in one toolset, raising the blast radius of any single prompt injection.",
      remediation: "Split capabilities across least-privilege servers.",
    },
    run: capabilityComboRule,
  },
];
