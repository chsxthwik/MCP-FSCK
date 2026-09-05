import { statSync } from "node:fs";
import { homedir } from "node:os";
import { looksLikePlaceholder, redactSecret } from "../util.js";
import type { ParsedServer, RawFinding, RuleContext, Severity } from "../types.js";

/** Pattern, human label, default severity, match against the *value*. */
const KNOWN_SECRET_VALUES: Array<[RegExp, string, Severity]> = [
  [/^AKIA[0-9A-Z]{16}$/, "AWS access key id", "high"],
  [/^sk-ant-/, "Anthropic API key", "high"],
  [/^sk-or-v1-/, "OpenRouter API key", "high"],
  [/^sk-[A-Za-z0-9_-]{20,}$/, "API key (sk-…)", "high"],
  [/^ghp_[A-Za-z0-9]{36}$|^gho_[A-Za-z0-9]{36}$|^github_pat_[A-Za-z0-9_]{22,}$/, "GitHub token", "high"],
  [/^npm_[A-Za-z0-9]{36}$/, "npm publish token", "high"],
  [/^xox[baprs]-/, "Slack token", "high"],
  [/^glpat-[A-Za-z0-9_-]{20,}$/, "GitLab personal access token", "high"],
  [/^AIza[0-9A-Za-z_-]{35}$/, "Google API key", "high"],
  [/^-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY/, "private key material", "critical"],
];

const GENERIC_SECRET_KEY =
  /(secret|token|password|passwd|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth[-_]?token|bearer)/i;

const MAX_SECRET_FINDINGS_PER_SERVER = 5;

/** True when a key/value pair looks like a stored credential (used for JSON redaction). */
export function mayContainSecret(key: string, value: string): boolean {
  if (KNOWN_SECRET_VALUES.some(([pattern]) => pattern.test(value))) return true;
  return GENERIC_SECRET_KEY.test(key) && value.length >= 16 && !looksLikePlaceholder(value);
}

function checkSecretValue(where: string, key: string, value: string): RawFinding | null {
  for (const [pattern, label, severity] of KNOWN_SECRET_VALUES) {
    if (pattern.test(value)) {
      return {
        title: `${label} stored in plaintext`,
        detail: `${where} \`${key}\` holds a value matching the shape of a ${label}. Anyone who can read this config file (backups, dotfile repos, malware) gets the credential.`,
        evidence: `${where}.${key} = ${redactSecret(value)}`,
        severity,
        remediation: "Move the credential to a secret manager or system keychain and reference it indirectly; rotate the exposed value.",
      };
    }
  }
  if (
    GENERIC_SECRET_KEY.test(key) &&
    value.length >= 16 &&
    !looksLikePlaceholder(value)
  ) {
    return {
      title: "Possible credential stored in plaintext",
      detail: `${where} \`${key}\` looks like a sensitive key holding a ${value.length}-character value.`,
      evidence: `${where}.${key} = ${redactSecret(value)}`,
      severity: "medium",
      remediation: "Confirm the value is not a live credential; prefer a keychain or secret manager reference.",
    };
  }
  return null;
}

function secretsRule(server: ParsedServer): RawFinding[] {
  const findings: RawFinding[] = [];
  if (server.env) {
    for (const [key, value] of Object.entries(server.env)) {
      const f = checkSecretValue("env", key, value);
      if (f) {
        findings.push(f);
        if (findings.length >= MAX_SECRET_FINDINGS_PER_SERVER) return findings;
      }
    }
  }
  if (server.headers) {
    for (const [key, value] of Object.entries(server.headers)) {
      const f = checkSecretValue("headers", key, value);
      if (f) {
        findings.push(f);
        if (findings.length >= MAX_SECRET_FINDINGS_PER_SERVER) return findings;
      }
    }
  }
  return findings;
}

const INLINE_INTERPRETERS: Array<[RegExp, string]> = [
  [/(^|\/)(node|python3?|perl|ruby|php|lua|tclsh)($|\s)/, "script interpreter"],
];

function commandLine(server: ParsedServer): string {
  if (server.transport !== "stdio" || server.command === undefined) return "";
  return [server.command, ...(server.args ?? [])].join(" ");
}

function shellMetacharRule(server: ParsedServer): RawFinding[] {
  if (server.transport !== "stdio" || server.command === undefined) return [];
  const args = server.args ?? [];
  const findings: RawFinding[] = [];
  const shellWrapper = /(^|\/)(sh|bash|zsh|dash|ksh|pwsh|powershell|cmd)(\.exe)?$/.test(server.command);

  if (shellWrapper) {
    const joined = args.join(" ");
    if (/[$;&|`><\n]/.test(joined)) {
      findings.push({
        title: "Shell command built with metacharacters",
        detail: `The server runs \`${server.command}\` with arguments containing shell metacharacters. If any part of the string is attacker-influenced (tool arguments, prompt content, file names), this is a command-injection path into your machine.`,
        evidence: `${server.command} ${joined}`.slice(0, 300),
        severity: "critical",
        remediation: "Run the underlying binary directly instead of routing through a shell; if a shell is required, pass the payload as an argument, never as a shell-parsed string.",
      });
      return findings;
    }
  }

  const dangerousArg = args.find((a) => /(\$\(|`|\|\s*(ba)?sh\b|&&\s*(ba)?sh\b|;\s*(ba)?sh\b|curl[^\n|]*\|\s*(ba)?sh\b|wget[^\n|]*\|\s*(ba)?sh\b)/.test(a)) ??
    (/(curl|wget)[^\n|]*\|\s*(ba)?sh\b/.test(server.command) ? server.command : undefined);
  if (dangerousArg !== undefined) {
    findings.push({
      title: "Pipe-to-shell / obfuscated execution pattern",
      detail: "Arguments contain a pipe-to-shell, command substitution or backtick pattern. This is the classic remote-code-execution shape (curl … | sh) and should not appear in an MCP config.",
      evidence: dangerousArg.slice(0, 300),
      severity: "critical",
      remediation: "Remove the pattern and install the referenced tool properly; audit your machine for compromise if you did not add this yourself.",
    });
    return findings;
  }

  const decodeArg = args.find((a) => /\bbase64\b/.test(a) && /(-d|--decode|-D\b)/.test(a));
  if (decodeArg !== undefined) {
    findings.push({
      title: "Base64-decoded execution",
      detail: "Arguments decode base64 at runtime — a common way to hide what a server actually executes.",
      evidence: decodeArg.slice(0, 300),
      severity: "critical",
      remediation: "Decode the payload offline to inspect it, then replace the obfuscation with a plain command.",
    });
  }
  return findings;
}

function inlineCodeRule(server: ParsedServer): RawFinding[] {
  if (server.transport !== "stdio" || server.command === undefined) return [];
  const args = server.args ?? [];
  for (const [pattern] of INLINE_INTERPRETERS) {
    if (pattern.test(server.command)) {
      const inlineFlagIndex = args.findIndex((a) => /^(-e|-c|-r|-E)$/.test(a));
      if (inlineFlagIndex !== -1) {
        return [
          {
            title: "Inline code execution",
            detail: `The server executes inline code via \`${args[inlineFlagIndex]}\` instead of a reviewed script file. Inline snippets bypass code review and are easy to modify unnoticed.`,
            evidence: commandLine(server).slice(0, 300),
            severity: "medium",
            remediation: "Point the interpreter at a versioned script file so changes show up in diffs.",
          },
        ];
      }
    }
  }
  return [];
}

const PACKAGE_RUNNERS: Record<string, "node" | "python"> = {
  npx: "node",
  "pnpm": "node",
  "pnpm.exe": "node",
  bunx: "node",
  uvx: "python",
  "uv": "python",
};

function packageToken(server: ParsedServer): { pkg: string; autoInstall: boolean; runner: "node" | "python"; runnerCommand: string } | null {
  if (server.transport !== "stdio" || server.command === undefined) return null;
  const base = server.command.split(/[/\\]/).pop()!.toLowerCase();
  const args = server.args ?? [];
  if (base === "npm" || base === "pnpm" || base === "uv") {
    // npm exec / pnpm dlx / uv tool run forms
    const hasExec = args.some((a) => ["exec", "dlx", "tool"].includes(a));
    if (!hasExec) return null;
  }
  const runnerKind = PACKAGE_RUNNERS[base];
  if (runnerKind === undefined) return null;
  const autoInstall =
    runnerKind === "python" || args.some((a) => a === "-y" || a === "--yes");
  const pkg = args.find((a) => !a.startsWith("-") && !["exec", "dlx", "tool", "run"].includes(a));
  if (pkg === undefined) return null;
  return { pkg, autoInstall, runner: runnerKind, runnerCommand: base };
}

function isUnpinnedNpm(pkg: string): boolean {
  // strip scope, then require an explicit version after the name
  const withoutScope = pkg.startsWith("@") ? pkg.slice(pkg.indexOf("/") + 1) : pkg;
  return !/^[^@]+@[^@]+$/.test(withoutScope);
}

function autoInstallRule(server: ParsedServer): RawFinding[] {
  const info = packageToken(server);
  if (info === null) return [];
  if (!info.autoInstall) return [];
  if (info.runner === "node" && !isUnpinnedNpm(info.pkg)) return [];
  if (info.runner === "python" && info.pkg.includes("==")) return [];
  return [
    {
      title: "Unpinned package auto-installed at startup",
      detail: `\`${info.runnerCommand} ${info.pkg}\` re-resolves the package on every launch: a compromised or hijacked package version is pulled and executed automatically. This is the "MCP rug pull" pattern.`,
      evidence: `${info.runnerCommand} ${info.pkg}`,
      severity: "medium",
      remediation: "Pin an exact version (e.g. `pkg@1.2.3`) and update deliberately, or install the server locally and run it from a fixed path.",
    },
  ];
}

const KNOWN_PUBLISHER_PREFIXES = [
  "@modelcontextprotocol/",
  "@azure/",
  "@github/",
  "@linear/",
  "@notionhq/",
  "@slack/",
  "@browserbasehq/",
  "@upstash/",
  "@firebase/",
  "@sentry/",
];

function unverifiedPublisherRule(server: ParsedServer): RawFinding[] {
  const info = packageToken(server);
  if (info === null) return [];
  if (KNOWN_PUBLISHER_PREFIXES.some((p) => info.pkg.startsWith(p))) return [];
  if (info.pkg.startsWith(".") || info.pkg.startsWith("/")) return []; // local path, not a registry package
  return [
    {
      title: "Package from an unverified publisher",
      detail: `\`${info.pkg}\` is not from a well-known official publisher. Third-party MCP packages run with your user's permissions and have repeatedly been found typosquatting popular servers.`,
      evidence: info.pkg,
      severity: "info",
      remediation: "Verify the repository and maintainer before trusting this server; prefer official packages.",
    },
  ];
}

function isLocalHost(url: URL): boolean {
  return (
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1" ||
    url.hostname === "[::1]" ||
    url.hostname.endsWith(".local")
  );
}

function insecureTransportRule(server: ParsedServer): RawFinding[] {
  if (server.url === undefined) return [];
  let url: URL;
  try {
    url = new URL(server.url);
  } catch {
    return [
      {
        title: "Unparseable remote URL",
        detail: `The server URL \`${server.url}\` cannot be parsed.`,
        evidence: server.url,
        severity: "low",
        remediation: "Fix the URL in the config.",
      },
    ];
  }
  if (url.protocol === "http:") {
    if (isLocalHost(url)) {
      return [
        {
          title: "Remote server over unencrypted local transport",
          detail: `${url} uses plain HTTP. Traffic is not encrypted on the wire, and any local process can impersonate the server.`,
          evidence: server.url,
          severity: "low",
          remediation: "Prefer HTTPS unless this is a throwaway local server.",
        },
      ];
    }
    return [
      {
        title: "Remote server over plain HTTP",
        detail: `${url} sends every message — including your prompts, files and any tool results — unencrypted across the network. Interception or tampering (tool-list swapping) is trivial on-path.`,
        evidence: server.url,
        severity: "high",
        remediation: "Use an HTTPS endpoint; only accept plain HTTP for isolated local testing.",
      },
    ];
  }
  return [];
}

const CREDENTIAL_HEADER = /(authorization|auth|api[-_]?key|apikey|token|secret|password)/i;

function remoteCredentialsRule(server: ParsedServer): RawFinding[] {
  if (server.headers === undefined) return [];
  const findings: RawFinding[] = [];
  for (const [name, value] of Object.entries(server.headers)) {
    if (!CREDENTIAL_HEADER.test(name) || value.length < 8) continue;
    if (looksLikePlaceholder(value)) continue;
    if (KNOWN_SECRET_VALUES.some(([p]) => p.test(value))) continue; // already flagged by secrets rule
    findings.push({
      title: "Remote credentials stored in config",
      detail: `Header \`${name}\` carries a credential for ${server.url ?? "the remote server"}. The value sits in a plaintext JSON file.`,
      evidence: `${name}: ${redactSecret(value)}`,
      severity: "medium",
      remediation: "Store the token in a secret manager and rotate it if this file was ever shared or committed.",
    });
  }
  return findings;
}

function rootPathArg(server: ParsedServer): string | undefined {
  if (server.transport !== "stdio") return undefined;
  const home = homedir();
  const candidates = (server.args ?? []).filter((a) => !a.startsWith("-"));
  for (const arg of candidates) {
    const normalized = arg.replace(/\\/g, "/").replace(/\/+$/, "") || "/";
    if (normalized === "/") return arg;
    if (normalized === "~" || normalized === "$HOME" || normalized === home) return arg;
    if (/^[a-zA-Z]:$/.test(normalized) || /^[a-zA-Z]:\/$/.test(normalized)) return arg;
  }
  return undefined;
}

function broadFilesystemScopeRule(server: ParsedServer): RawFinding[] {
  const looksFilesystem =
    /fs|file[-_]?system|filesystem/i.test(server.name) ||
    (server.command !== undefined && /file[-_]?system/i.test(server.command)) ||
    (server.args ?? []).some((a) => /file[-_]?system/i.test(a));
  if (!looksFilesystem) return [];
  const root = rootPathArg(server);
  if (root === undefined) return [];
  return [
    {
      title: "Filesystem server granted root-level scope",
      detail: `The filesystem server is allowed to operate on \`${root}\` — the entire disk or home directory, not a project folder. Combined with any prompt injection, the agent can read or rewrite every file your user can.`,
      evidence: `${server.name}: allowed root ${root}`,
      severity: "high",
      remediation: "Restrict the server to specific project directories (pass explicit paths instead of `/` or `~`).",
    },
  ];
}

function worldWritableConfigRule(server: ParsedServer): RawFinding[] {
  if (process.platform === "win32") return [];
  let mode: number;
  try {
    mode = statSync(server.source).mode;
  } catch {
    return [];
  }
  // eslint-disable-next-line no-bitwise -- POSIX mode bits
  if ((mode & 0o002) === 0) return [];
  return [
    {
      title: "Config file is world-writable",
      detail: `${server.source} is writable by other users on this machine. Anything running under another local account can add or replace MCP servers and silently re-tool your AI agent.`,
      evidence: `${server.source} (mode ${(mode & 0o777).toString(8)})`,
      severity: "high",
      remediation: "`chmod o-w <file>` — config files should be owned and writable only by you.",
    },
  ];
}

/** Mask tokens that look like known secrets before echoing a command line. */
function safeCommandLine(server: ParsedServer): string {
  const line = commandLine(server);
  let out = line;
  for (const [pattern] of KNOWN_SECRET_VALUES) {
    out = out.replace(new RegExp(pattern.source, "g"), (m) => redactSecret(m));
  }
  return out.slice(0, 300);
}

function configDriftRule(server: ParsedServer, context: RuleContext): RawFinding[] {
  const twins = context.allServers.filter(
    (s) => s.name === server.name && s.source !== server.source,
  );
  const findings: RawFinding[] = [];
  const seen = new Set<string>();
  for (const twin of twins) {
    const key = twin.source;
    if (seen.has(key)) continue;
    const differs =
      (server.url ?? `${server.command ?? ""} ${(server.args ?? []).join(" ")}`.trim()) !==
      (twin.url ?? `${twin.command ?? ""} ${(twin.args ?? []).join(" ")}`.trim());
    if (!differs) continue;
    seen.add(key);
    findings.push({
      title: "Same server name defined differently in another client",
      detail: `\`${server.name}\` is also defined in ${twin.source} (${twin.client}) with a different ${
        twin.command !== undefined ? "command" : "URL"
      }. Clients will run different code under the same name — a quiet way for a tampered copy to go unnoticed.`,
      evidence: `here: ${safeCommandLine(server) || (server.url ?? "?")} | there: ${safeCommandLine(twin) || (twin.url ?? "?")}`,
      severity: "low",
      remediation: "Keep one canonical definition per server, or make the divergence explicit with distinct names.",
    });
  }
  return findings;
}

export const staticRules: Array<{ meta: import("../types.js").RuleMeta; run: import("../types.js").RuleFn }> = [
  {
    meta: {
      id: "MCP001",
      name: "secrets-in-config",
      severity: "high",
      scope: "static",
      description: "Detects API keys, tokens and private key material stored in plaintext in MCP configs.",
      remediation: "Move credentials into a secret manager; rotate anything found.",
    },
    run: secretsRule,
  },
  {
    meta: {
      id: "MCP002",
      name: "shell-metachar-execution",
      severity: "critical",
      scope: "static",
      description: "Detects shell wrappers, pipes-to-shell, command substitution and runtime base64 decoding.",
      remediation: "Run binaries directly; treat pipe-to-shell configs as compromised until proven otherwise.",
    },
    run: shellMetacharRule,
  },
  {
    meta: {
      id: "MCP003",
      name: "inline-code-execution",
      severity: "medium",
      scope: "static",
      description: "Detects interpreters invoked with inline code flags (-e / -c) instead of reviewed files.",
      remediation: "Reference versioned script files so changes are visible in diffs.",
    },
    run: inlineCodeRule,
  },
  {
    meta: {
      id: "MCP004",
      name: "auto-install-unpinned-package",
      severity: "medium",
      scope: "static",
      description: "Detects npx/uvx -y style launches that re-resolve an unpinned package on every startup (MCP rug pulls).",
      remediation: "Pin exact versions or install locally from a fixed path.",
    },
    run: autoInstallRule,
  },
  {
    meta: {
      id: "MCP005",
      name: "unverified-publisher",
      severity: "info",
      scope: "static",
      description: "Flags packages that are not from a known official MCP publisher.",
      remediation: "Verify the maintainer and repository before trusting the server.",
    },
    run: unverifiedPublisherRule,
  },
  {
    meta: {
      id: "MCP006",
      name: "insecure-transport",
      severity: "high",
      scope: "static",
      description: "Detects remote MCP servers served over plain HTTP.",
      remediation: "Use HTTPS endpoints.",
    },
    run: insecureTransportRule,
  },
  {
    meta: {
      id: "MCP007",
      name: "remote-credentials-in-config",
      severity: "medium",
      scope: "static",
      description: "Detects Authorization/API-key headers carrying credentials in plaintext configs.",
      remediation: "Reference tokens from a secret manager and rotate exposed values.",
    },
    run: remoteCredentialsRule,
  },
  {
    meta: {
      id: "MCP008",
      name: "broad-filesystem-scope",
      severity: "high",
      scope: "static",
      description: "Detects filesystem servers allowed to operate on / or the entire home directory.",
      remediation: "Pass explicit project directories instead of root paths.",
    },
    run: broadFilesystemScopeRule,
  },
  {
    meta: {
      id: "MCP009",
      name: "world-writable-config",
      severity: "high",
      scope: "static",
      description: "Detects MCP config files writable by other users (POSIX).",
      remediation: "Restrict write access to your own account.",
    },
    run: worldWritableConfigRule,
  },
  {
    meta: {
      id: "MCP010",
      name: "config-drift",
      severity: "low",
      scope: "static",
      description: "Detects the same server name defined with different commands/URLs across client configs.",
      remediation: "Keep one canonical definition per server name.",
    },
    run: configDriftRule,
  },
];
