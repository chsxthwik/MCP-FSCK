import { statSync } from "node:fs";
import { homedir } from "node:os";
import { looksLikePlaceholder, redactSecret } from "../util.js";
import type { ParsedServer, RawFinding, RuleContext, Severity } from "../types.js";

/** Pattern, human label, default severity, match against the *value*. */
const KNOWN_SECRET_VALUES: Array<[RegExp, string, Severity]> = [
  [/^AKIA[0-9A-Z]{16}$/, "AWS access key id", "high"],
  [/^sk-ant-/, "Anthropic API key", "high"],
  [/^sk-or-v1-/, "OpenRouter API key", "high"],
  [/^[sr]k_(live|test)_[A-Za-z0-9]{16,}$/, "Stripe secret key", "high"],
  [/^sk-[A-Za-z0-9_-]{20,}$/, "API key (sk-…)", "high"],
  [/^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}$|^github_pat_[A-Za-z0-9_]{22,}$/, "GitHub token", "high"],
  [/^npm_[A-Za-z0-9]{36}$/, "npm publish token", "high"],
  [/^xox[baprs]-|^xapp-[A-Za-z0-9-]+$/, "Slack token", "high"],
  [/^glpat-[A-Za-z0-9_-]{20,}$/, "GitLab personal access token", "high"],
  [/^AIza[0-9A-Za-z_-]{35}$/, "Google API key", "high"],
  [/^lin_api_[A-Za-z0-9]{20,}$/, "Linear API key", "high"],
  [/^sbp_[a-f0-9]{32,}$/, "Supabase service key", "high"],
  [/^dop_v1_[a-f0-9]{64}$/, "DigitalOcean token", "high"],
  [/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$/, "JWT", "medium"],
  [/^-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/, "private key material", "critical"],
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
  const push = (f: RawFinding | null): boolean => {
    if (f !== null) findings.push(f);
    return findings.length >= MAX_SECRET_FINDINGS_PER_SERVER;
  };
  if (server.env) {
    for (const [key, value] of Object.entries(server.env)) {
      if (push(checkSecretValue("env", key, value))) return findings;
    }
  }
  if (server.headers) {
    for (const [key, value] of Object.entries(server.headers)) {
      if (push(checkSecretValue("headers", key, value))) return findings;
    }
  }
  // Credentials passed as CLI args or embedded in the URL are just as exposed
  // as env vars — they sit in the same plaintext file.
  for (const arg of server.args ?? []) {
    for (const [pattern, label, severity] of KNOWN_SECRET_VALUES) {
      if (pattern.test(arg)) {
        if (push({
          title: `${label} passed as a command argument`,
          detail: `An argument holds a value matching the shape of a ${label}. Command-line credentials leak into the plaintext config and may surface in process listings while the server runs.`,
          evidence: redactSecret(arg),
          severity,
          remediation: "Pass the credential via a secret-manager-backed env reference instead of a literal argument; rotate the exposed value.",
        })) return findings;
      }
    }
  }
  if (server.url !== undefined) {
    try {
      const url = new URL(server.url);
      const userinfo = url.username !== "" || url.password !== "";
      if (userinfo) {
        push({
          title: "Credentials embedded in server URL",
          detail: "The server URL carries a username/password. URL userinfo ends up in plaintext configs, logs and error messages.",
          evidence: `${url.protocol}//${url.username !== "" ? redactSecret(url.username) : ""}:****@${url.host}${url.pathname}`,
          severity: "high",
          remediation: "Move the credential to an Authorization header sourced from a secret manager; drop userinfo from the URL.",
        });
      }
    } catch {
      // unparseable URLs are MCP006's problem
    }
  }
  return findings;
}

const INLINE_INTERPRETERS: Array<[RegExp, string]> = [
  [/(^|[\\/])(node|python3?|perl|ruby|php|lua|tclsh)(\.exe)?($|\s)/i, "script interpreter"],
];

function commandLine(server: ParsedServer): string {
  if (server.transport !== "stdio" || server.command === undefined) return "";
  return [server.command, ...(server.args ?? [])].join(" ");
}

const SHELL_WRAPPER = /(^|[\\/])(sh|bash|zsh|dash|ksh|pwsh|powershell|cmd)(\.exe)?$/i;
const SHELL_CODE_FLAGS = new Set(["-c", "--call", "/c", "-command", "-encodedcommand", "-ec", "-e"]);

/** The argument a shell actually interprets as code (after -c / /c / -Command). */
function shellCodeArg(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i += 1) {
    if (SHELL_CODE_FLAGS.has(args[i]!.toLowerCase())) return args[i + 1];
  }
  return undefined;
}

function shellMetacharRule(server: ParsedServer): RawFinding[] {
  if (server.transport !== "stdio" || server.command === undefined) return [];
  const args = server.args ?? [];
  const findings: RawFinding[] = [];
  const base = server.command.split(/[/\\]/).pop()!.toLowerCase();
  const shellWrapper = SHELL_WRAPPER.test(server.command);

  // `base64 -d …` invoked as the command itself decodes a hidden payload.
  const hasDecodeFlag = args.some((a) => /^--?d(ecode)?$/i.test(a) || a === "-D");
  const decodesViaCommand =
    ((base === "base64" || base === "b64decode") && hasDecodeFlag) ||
    (base === "openssl" && hasDecodeFlag && args.some((a) => /^(enc|base64)$/i.test(a)));
  if (decodesViaCommand) {
    findings.push({
      title: "Base64-decoded execution",
      detail: `The server invokes \`${base}\` with a decode flag at startup — a common way to hide what actually runs.`,
      evidence: commandLine(server).slice(0, 300),
      severity: "critical",
      remediation: "Decode the payload offline to inspect it, then replace the obfuscation with a plain command.",
    });
    return findings;
  }

  // `npx -c "…"` / `npm exec -- -c "…"` run the argument through a shell too.
  const runnerShell = ["npx", "npx.exe", "npm", "npm.exe", "bunx", "bunx.exe"].includes(base);
  const wrapperCode = shellWrapper || runnerShell;

  if (wrapperCode) {
    const code = shellCodeArg(args) ?? (args.length > 0 && shellWrapper ? args.join(" ") : undefined);
    const joined = args.join(" ");
    if (code !== undefined && /[$;&|`><\n]|\|\s*(ba)?sh\b|&&|;|\bcurl\b[^\n|]*\||\bwget\b[^\n|]*\||\bbase64\b/.test(code)) {
      findings.push({
        title: "Shell command built with metacharacters",
        detail: `The server runs \`${server.command}\` with arguments containing shell syntax. If any part of the string is attacker-influenced (tool arguments, prompt content, file names), this is a command-injection path into your machine.`,
        evidence: `${server.command} ${joined}`.slice(0, 300),
        severity: "critical",
        remediation: "Run the underlying binary directly instead of routing through a shell; if a shell is required, pass the payload as an argument, never as a shell-parsed string.",
      });
      return findings;
    }
    if (code !== undefined) {
      findings.push({
        title: "Server routed through a shell wrapper",
        detail: `The server is launched via \`${server.command}\` — its command string is shell-parsed at every startup. Even without obvious metacharacters, this hides the real program from review and makes later tampering invisible in diffs of the binary it runs.`,
        evidence: `${server.command} ${joined}`.slice(0, 300),
        severity: "medium",
        remediation: "Launch the real binary directly with explicit args; reserve shells for configs you have reviewed line by line.",
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
  "npx.exe": "node",
  npm: "node",
  "npm.exe": "node",
  pnpm: "node",
  "pnpm.exe": "node",
  bunx: "node",
  "bunx.exe": "node",
  uvx: "python",
  "uvx.exe": "python",
  uv: "python",
  "uv.exe": "python",
};

/** Subcommand words that precede the package spec. */
const RUNNER_SUBCOMMANDS = new Set(["exec", "x", "dlx", "tool", "run", "add"]);

/** Flags whose next argument is a value, not the package spec. */
const RUNNER_VALUE_FLAGS = new Set([
  "--registry", "--cache", "--userconfig", "--prefix", "--cwd", "--workspace", "-w",
  "--node-arg", "--from", "--with", "--index-url", "--extra-index-url", "--python",
  "--config", "--tag", "--arch", "--platform", "-c", "--call",
]);

/** Extract the package spec and whether the runner silently fetches it. */
function packageToken(server: ParsedServer): { pkg: string; autoInstall: boolean; runner: "node" | "python"; runnerCommand: string } | null {
  if (server.transport !== "stdio" || server.command === undefined) return null;
  const base = server.command.split(/[/\\]/).pop()!.toLowerCase();
  const runnerKind = PACKAGE_RUNNERS[base];
  if (runnerKind === undefined) return null;
  const args = server.args ?? [];

  // npm/pnpm/uv need an exec-style subcommand to act as a package runner.
  if (base === "npm" || base === "npm.exe" || base === "pnpm" || base === "pnpm.exe" || base === "uv" || base === "uv.exe") {
    if (!args.some((a) => RUNNER_SUBCOMMANDS.has(a))) return null;
  }

  // Which invocations fetch without asking? uvx/uv tool run and pnpm dlx/npm
  // exec resolve from the registry by default; bunx installs silently; npx
  // needs -y/--yes to skip its (already fragile) confirmation prompt.
  const autoInstall =
    runnerKind === "python" ||
    base.startsWith("bunx") ||
    args.some((a) => a === "-y" || a === "--yes" || a === "dlx") ||
    ((base === "npm" || base === "npm.exe") && args.some((a) => a === "exec" || a === "x"));

  let pkg: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a.startsWith("--")) {
      if (!a.includes("=") && RUNNER_VALUE_FLAGS.has(a)) i += 1; // skip its value
      continue;
    }
    if (a.startsWith("-") && a !== "-") {
      // bundled short flags: -y is flag-only; -p takes a package spec (do not
      // skip it — it IS a package), -c's value is a command string (skip).
      if (a === "-c" || a === "--call") i += 1;
      continue;
    }
    if (RUNNER_SUBCOMMANDS.has(a)) continue;
    pkg = a;
    break;
  }
  if (pkg === undefined) return null;
  return { pkg, autoInstall, runner: runnerKind, runnerCommand: base };
}

function isUnpinnedNpm(pkg: string): boolean {
  // Local refs (file:, link:, workspace:, portal:, patch:) never hit the
  // registry — nothing re-resolves at startup.
  if (/^(file|link|workspace|portal|patch):/i.test(pkg)) return false;
  // strip scope, then require the ref after the name to be immutable:
  // an exact semver, a git sha, or a local path. `pkg@latest`, `pkg@^1`,
  // `pkg@*`, `pkg@beta` all re-resolve on every launch — that is unpinned.
  const withoutScope = pkg.startsWith("@") ? pkg.slice(pkg.indexOf("/") + 1) : pkg;
  const at = withoutScope.lastIndexOf("@");
  if (at <= 0) return true;
  const ref = withoutScope.slice(at + 1);
  if (/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(ref)) return false;
  if (/^(file|link|workspace):/.test(ref)) return false;
  if (/^[0-9a-f]{7,40}$/i.test(ref)) return false;
  return true;
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
  if (/^(file|link|workspace|portal|patch):/i.test(info.pkg)) return []; // local ref, not a registry package
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
    url.hostname === "0.0.0.0" ||
    url.hostname === "::1" ||
    url.hostname === "[::1]" ||
    url.hostname === "[::]" ||
    url.hostname.endsWith(".local") ||
    url.hostname.endsWith(".localhost")
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
    if (
      normalized === "~" ||
      normalized === "." ||
      normalized === "$HOME" ||
      normalized === "${HOME}" ||
      /^%USERPROFILE%$/i.test(normalized) ||
      normalized === home
    ) {
      return arg;
    }
    if (/^[a-zA-Z]:$/.test(normalized) || /^[a-zA-Z]:\/$/.test(normalized)) return arg;
  }
  return undefined;
}

// `fs` must be a token — a bare substring match flags names like "diffs" or "refs".
const FILESYSTEM_HINT = /(^|[^a-z0-9])(fs|filesystem|files|file[-_]?system)([^a-z0-9]|$)/i;

function broadFilesystemScopeRule(server: ParsedServer): RawFinding[] {
  const looksFilesystem =
    FILESYSTEM_HINT.test(server.name) ||
    (server.command !== undefined && FILESYSTEM_HINT.test(server.command)) ||
    (server.args ?? []).some((a) => FILESYSTEM_HINT.test(a));
  if (!looksFilesystem) return [];
  const root = rootPathArg(server);
  if (root === undefined) return [];
  return [
    {
      title: "Filesystem server granted root-level scope",
      detail: `The filesystem server is allowed to operate on \`${root}\` — the entire disk, home directory or the host app's working directory, not a project folder. Combined with any prompt injection, the agent can read or rewrite every file your user can.`,
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
