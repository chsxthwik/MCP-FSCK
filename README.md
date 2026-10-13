# mcp-fsck

Integrity check for MCP server configs.

[![CI](https://github.com/chsxthwik/MCP-FSCK/actions/workflows/ci.yml/badge.svg)](https://github.com/chsxthwik/MCP-FSCK/actions/workflows/ci.yml)
[MIT](LICENSE)

An MCP server is a program an AI coding agent is allowed to start. It can read files, run commands, and hold API keys. The config that lists those servers is easy to get wrong, and a bad entry runs with your permissions.

mcp-fsck grades each server from A to F, explains what it found, and tells you what to change. A clean scan exits 0. A finding at or above the chosen severity (high, by default) exits 1, so the same command can gate CI. You point it at the files you already have. It does not need a service.

It is for people who run Claude, Cursor, VS Code, Windsurf, Zed, Codex, Gemini CLI, JetBrains Junie, Cline, Roo, Kilo, or Amazon Q, and for anyone reviewing those configs in a pull request.

## Install

mcp-fsck requires Node.js 18 or newer (`engines` in `package.json`). It is not published on the npm registry. Install it from a checkout of this repository. The commands below were run here with Node.js v22.14.0 and npm 10.9.9:

```bash
npm install
npm run build
node dist/cli.js --version
```

`node dist/cli.js --version` printed `0.3.0`. The `mcp-fsck` bin in `package.json` points at `dist/cli.js`, so every command in this README uses that built file.

## Common scans

Static scans only read config files. With no paths, mcp-fsck looks in the [client locations](#configs-it-reads) for the current user, and in project configs from the working directory up to the git root. On a home directory with none of those files, that looks like this:

```bash
mkdir -p /tmp/mcp-fsck-empty-home
HOME=/tmp/mcp-fsck-empty-home node dist/cli.js
```

```text
  mcp-fsck v0.3.0 — integrity check for MCP server configs
  scanned 0 config files · 0 servers · 0 findings

  No MCP config files found. Pass paths explicitly: `mcp-fsck scan path/to/config.json`
```

Pass files when you want a specific config. These two are in the repo.

```bash
node dist/cli.js scan examples/clean.mcp.json
node dist/cli.js scan examples/risky.mcp.json
```

The clean example is one pinned filesystem server. The scan exited 0.

![Clean scan of examples/clean.mcp.json: overall grade A and exit 0](docs/images/clean-scan.png)

`examples/risky.mcp.json` is the failing case: a shell pipe, a filesystem rooted at `/`, plain HTTP, a wildcard auto-approve list, and an unpinned lookalike package. The scan exited 1, and stderr was:

```text
mcp-fsck: 8 finding(s), worst is critical, fail-on is high
```

![Failing scan of examples/risky.mcp.json: overall grade F and exit 1](docs/images/failing-scan.png)

Other commands that were run from this checkout:

```bash
node dist/cli.js list examples/clean.mcp.json
node dist/cli.js rules
node dist/cli.js --help
node dist/cli.js scan --help
```

`list` prints each config that exists and the servers in it, with secrets removed from the command line and the URL. `rules` prints the rule table below. `scan` is the default command, so `node dist/cli.js scan FILE` and `node dist/cli.js FILE` are the same scan.

| Flag | What it does |
|---|---|
| `--deep` | Start each server and ask for `tools/list`. See [Deep mode](#deep-mode). |
| `--timeout <ms>` | Per-server deep handshake timeout. Default `10000`. |
| `--json` | Print the report as JSON. Credential-shaped values are redacted. |
| `--sarif <file>` | Also write [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html). |
| `--baseline <file>` | Suppression file. If you omit it, `.mcp-fsck.json` in the working directory is used when that file exists. |
| `--write-baseline [file]` | Record the current findings as accepted. Default file `.mcp-fsck.json`. |
| `--fail-on <severity>` | Exit 1 when a finding is at or above this severity. Default `high`. `none` turns the gate off. |

Accepted `--fail-on` values: `critical`, `high`, `medium`, `low`, `info`, `none`.

## How to read a report

The first summary line is the overall grade. It uses the same scoring as each server, applied to every finding that is still in the report (baseline suppressions are already removed). Servers inside a file are listed worst score first.

A finding has a severity, a rule id, a title, a short explanation, redacted evidence, and a remediation. Severities, from most serious to least: `critical`, `high`, `medium`, `low`, `info`.

The score is the sum of the weights below, capped at 100. Any critical finding is an F on its own.

| Severity | Weight |
|---|---|
| critical | 40 |
| high | 25 |
| medium | 10 |
| low | 3 |
| info | 0 |

| Grade | Score | What it means here |
|---|---|---|
| A | 0–4 | Nothing meaningful, or only info findings. `examples/clean.mcp.json` scored 0. |
| B | 5–14 | A medium finding, or a couple of low ones. |
| C | 15–29 | One high finding is 25, so grade C. `insecure-remote` and `preapproved` in the risky example both scored 25. |
| D | 30–49 | A high finding plus something else. `fs-root` scored 35 (MCP008 high + MCP004 medium). |
| F | 50–100, or any critical | Act on this server. `updater` is one critical MCP002: the weighted score is 40, and the critical finding makes it an F. |

Info findings do not move the score. They also stay under the default high gate, so a report that is only MCP005 or MCP018 still exits 0.

Some rules use a severity other than the default printed by `rules`:

- MCP001 is **critical** for private-key material, **high** for known token shapes, and **medium** for a generic secret-looking value. The bad-config scan showed both high and medium.
- MCP002 is **critical** when the shell string has metacharacters, a pipe, or runtime decoding, and **medium** for a shell wrapper without that syntax.
- MCP006 is **high** for remote `http://` or `ws://`, and **low** for those schemes on localhost.
- MCP016 is **high** when the auto-approve list contains `*`. The risky example's `preapproved` server was high for that reason. A named list stays medium.
- MCP017 is **high**. A file that exists and cannot be read or parsed fails the default gate.
- MCP018 is **info**. A deep handshake that does not return a tool list does not fail the default gate.

Entries with `enabled: false` or `disabled: true` are skipped, so a disabled server is not graded and is not started in deep mode.

## Exit codes

The broken file, the directory, and the bad baseline used in the table were created with these commands. The early-exit config is created in [Deep mode](#deep-mode).

```bash
printf '{ not json\n' > /tmp/mcp-fsck-broken.json
mkdir -p /tmp/mcp-fsck-not-a-file
printf '[]\n' > /tmp/mcp-fsck-bad-baseline.json
```

| Exit | Meaning | Command that produced it |
|---|---|---|
| 0 | No finding reached the gate. | `node dist/cli.js scan examples/clean.mcp.json` |
| 0 | Gate disabled. | `node dist/cli.js scan examples/risky.mcp.json --fail-on none` |
| 0 | Only info, or a severity below the gate. | `node dist/cli.js scan /tmp/mcp-fsck-early.json --deep --timeout 3000` (MCP018 info and MCP003 medium; default gate is high; overall grade B) |
| 0 | Baseline written. The gate is not applied on this invocation. | `node dist/cli.js scan examples/risky.mcp.json --write-baseline /tmp/mcp-fsck-baseline-gate.json` |
| 1 | A kept finding is at or above `--fail-on`. | `node dist/cli.js scan examples/risky.mcp.json` |
| 1 | The file exists but could not be parsed (MCP017, high). | `node dist/cli.js scan /tmp/mcp-fsck-broken.json` |
| 1 | The path exists and is not a regular file (MCP017, high). | `node dist/cli.js scan /tmp/mcp-fsck-not-a-file` |
| 2 | A path you named is missing. | `node dist/cli.js scan /tmp/mcp-fsck-does-not-exist.json` |
| 2 | `list` was given a missing path. | `node dist/cli.js list /tmp/mcp-fsck-does-not-exist.json` |
| 2 | `--fail-on` is not one of the six values. | `node dist/cli.js scan examples/clean.mcp.json --fail-on bogus` |
| 2 | `--timeout` is not a positive number of milliseconds. | `node dist/cli.js scan examples/clean.mcp.json --timeout 0` |
| 2 | The baseline cannot be read as an object with an `ignore` array. | `node dist/cli.js scan examples/clean.mcp.json --baseline /tmp/mcp-fsck-bad-baseline.json` |

Exit 2 prints the reason on stderr and does not print a grade. Exit 1 prints the report, then a line like `mcp-fsck: 1 finding(s), worst is high, fail-on is high`.

## Rules

`node dist/cli.js rules` printed this table. The severity column is the rule default; the exceptions are in [How to read a report](#how-to-read-a-report).

### Static rules

These run on the config text. No server process is started.

| Rule | Default | What `rules` says it detects |
|---|---|---|
| MCP001 secrets-in-config | high | API keys, tokens, and private key material in plaintext configs, including URL query strings and command arguments |
| MCP002 shell-metachar-execution | critical | Shell wrappers, pipes-to-shell, command substitution, and runtime base64 decoding |
| MCP003 inline-code-execution | medium | Interpreters invoked with `-e` / `-c` instead of a reviewed file |
| MCP004 auto-install-unpinned-package | medium | `npx` / `uvx -y` style launches that re-resolve an unpinned package on every startup (the MCP rug pull). An exact version such as `@modelcontextprotocol/server-filesystem@2025.8.21` in the clean example is not flagged |
| MCP005 unverified-publisher | info | Packages that are not from a known official MCP publisher |
| MCP006 insecure-transport | high | Remote MCP servers served over plain HTTP or `ws://` |
| MCP007 remote-credentials-in-config | medium | Authorization or API-key headers carrying credentials |
| MCP008 broad-filesystem-scope | high | Filesystem servers allowed to operate on `/`, `~`, `.`, or the whole home directory |
| MCP009 world-writable-config | high | MCP config files writable by other users (POSIX) |
| MCP010 config-drift | low | The same server name defined with different commands or URLs across configs |
| MCP014 typosquat-lookalike-package | medium | A package reusing an official server's name, a one-character misspelling, or a non-ASCII lookalike |
| MCP015 suspicious-server-name | medium | Invisible or non-ASCII characters in a server name |
| MCP016 tools-auto-approved | medium | `alwaysAllow` / `autoApprove` lists that skip consent prompts |
| MCP017 config-parse-error | high | A config file that exists but could not be read or parsed, so its servers were not audited |

### Deep rules

These run only with `--deep`, and only when a `tools/list` result came back. MCP018 is the exception: it reports that the list never arrived.

| Rule | Default | What `rules` says it detects |
|---|---|---|
| MCP011 tool-description-injection | critical | Instruction overrides, secrecy directives, exfiltration language, and hidden unicode in live tool descriptions |
| MCP012 tool-shadowing | medium | A tool description that names a tool exposed by another server |
| MCP013 dangerous-capability-combo | critical | One server combining exec, network, secrets, and filesystem capabilities. Pairs such as exec+network are critical; fs-read+network is high |
| MCP018 deep-handshake-failed | info | `tools/list` timed out or failed, so the poisoning rules had nothing to inspect |

## Redaction

Evidence in the terminal report, `list` output, and `--json` output keeps a short prefix and drops the rest of a credential. The fixture `test/fixtures/bad-config.json` holds example tokens. This scan exited 1:

```bash
node dist/cli.js scan test/fixtures/bad-config.json
```

![Redacted scan of test/fixtures/bad-config.json: token evidence is shortened and the scan exits 1](docs/images/redaction.png)

The same file's JSON report (`--json --fail-on none`, exit 0) redacts env values and the Authorization header the same way: `AKIA…(redacted, 20 chars)`, `ghp_…(redacted, 40 chars)`, `Bear…(redacted, 38 chars)`. The raw token strings were not in that JSON.

`list` does the same for the line it prints. A scratch config with a password in an `http://` URL and a token argument was listed with:

```bash
node dist/cli.js list /tmp/mcp-fsck-redact.json
```

```text
explicit  /tmp/mcp-fsck-redact.json
  · remote (http) http://redacted:redacted@files.example/mcp?token=redacted
  · cli (stdio) npx -y some-server --token ghp_…(redacted, 36 chars)
```

Placeholder values such as `${TOKEN}`, `{{secret}}`, and `changeme` are left alone and are not treated as stored credentials.

## Deep mode

`--deep` speaks enough of MCP to call [`initialize`](https://modelcontextprotocol.io/specification/2024-11-05) and [`tools/list`](https://modelcontextprotocol.io/specification/2024-11-05/server/tools). The handshake stops there. Tool calls are not sent.

The client sends protocol version `2024-11-05`. Stdio servers may answer with newline-delimited JSON, which is the [stdio transport](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports), or with older `Content-Length` frames. Remote `http` and `streamable-http` URLs get a streamable-HTTP POST handshake: `Accept: application/json, text/event-stream`, the `MCP-Protocol-Version` header, and the `Mcp-Session-Id` from the initialize response replayed on the next request, as described in the [2025-06-18 transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports). `type: sse` uses the [2024-11-05 HTTP+SSE](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports) flow and waits for the `endpoint` event. `ws://` and `wss://` URLs are not fetched. Credential headers and URL userinfo are withheld from a non-local plain HTTP server; the report says so, and the static rules still flag the config.

The server process gets a small environment: `PATH`, `HOME`, `LANG`, `TMPDIR`, `SYSTEMROOT`, `COMSPEC`, `USERPROFILE`, and `APPDATA` when they are set, plus the env from the config. Its working directory is the config's `cwd`, or the system temp directory when `cwd` is omitted. The process group is killed at the timeout, including children it spawned.

Deep mode does start the configured command. An `npx -y` entry can download a package. Use it on configs you trust, the way you would run an install on purpose. Static mode is the default.

This run pointed a scratch config at `test/fixtures/fake-mcp-server.mjs` with `FAKE_TOOLS=poison`, then handshook it. The command is absolute because deep mode's default working directory is the temp dir. Exit code was 1 (two critical findings).

```bash
node --input-type=module -e '
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
const server = resolve("test/fixtures/fake-mcp-server.mjs");
writeFileSync("/tmp/mcp-fsck-deep.json", JSON.stringify({
  mcpServers: {
    poisoned: {
      command: process.execPath,
      args: [server],
      env: { FAKE_TOOLS: "poison" }
    }
  }
}, null, 2));
'
node dist/cli.js scan /tmp/mcp-fsck-deep.json --deep --timeout 5000
```

![Deep scan of a poisoned tool list: MCP011 and MCP013, overall grade F, exit 1](docs/images/deep-scan.png)

A handshake that exits before `tools/list` is MCP018, not a green check. This one also tripped MCP003 because the command was `node -e`, so the grade was B and the exit was 0 under the default high gate:

```bash
node -e 'const fs=require("fs"); fs.writeFileSync("/tmp/mcp-fsck-early.json", JSON.stringify({mcpServers:{gone:{command:process.execPath,args:["-e","process.exit(0)"]}}},null,2))'
node dist/cli.js scan /tmp/mcp-fsck-early.json --deep --timeout 3000
```

## Baselines

A `.mcp-fsck.json` file records findings you have already reviewed. Later scans hide matching findings and count them as suppressed, so `--fail-on` only fires on new ones. The summary names the baseline file.

```bash
node dist/cli.js scan examples/risky.mcp.json --write-baseline /tmp/mcp-fsck-baseline.json --fail-on none
node dist/cli.js scan examples/risky.mcp.json --baseline /tmp/mcp-fsck-baseline.json
```

`--write-baseline` printed the full grade-F report, then `Wrote baseline /tmp/mcp-fsck-baseline.json: 8 finding(s) recorded.`, and exited 0. The follow-up scan exited 0 with `overall grade A` and `8 suppressed by /tmp/mcp-fsck-baseline.json`.

The file it wrote starts like this:

```json
{
  "ignore": [
    { "rule": "MCP002", "server": "updater", "source": "examples/risky.mcp.json" },
    { "rule": "MCP008", "server": "fs-root", "source": "examples/risky.mcp.json" }
  ]
}
```

An entry matches when every field it sets matches. `rule` is an exact rule id. `server` is a server name, or `"*"` for any server. `source` is a substring of the config path. An entry with no fields matches nothing. You can widen a generated file by hand:

```json
{ "ignore": [{ "rule": "MCP005", "server": "*" }] }
```

## CI and SARIF

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `npm ci`, `npm run typecheck`, `npm run build`, and `npm test` on Node.js 18, 20, and 22.

[`.github/workflows/mcp-fsck.yml`](.github/workflows/mcp-fsck.yml) builds the CLI and runs the two scans below. The clean example must pass the high gate. The risky example is written as SARIF with the gate off so the upload still happens, then [github/codeql-action/upload-sarif@v3](https://github.com/github/codeql-action) sends it to [GitHub code scanning](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file). The same two scans were run locally; the SARIF file was written under `/tmp` so it stayed out of the tree:

```bash
node dist/cli.js scan examples/clean.mcp.json --fail-on high
node dist/cli.js scan examples/risky.mcp.json --fail-on none --sarif /tmp/mcp-fsck-results.sarif
```

The clean scan exited 0. The SARIF scan exited 0 and printed `SARIF written to /tmp/mcp-fsck-results.sarif`. That file is SARIF `2.1.0` with `$schema` `https://json.schemastore.org/sarif-2.1.0.json`, 18 rule descriptors, and 8 results. Critical and high findings are SARIF `error`, medium and low are `warning`, and info is `note`. GitHub's supported subset is documented in [SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

For a pull request that should fail on new high findings and still upload the report, run the scan twice or accept a failing step before the upload, the way `mcp-fsck.yml` uses `if: always()` on the upload.

## Configs it reads

Discovery reports files that exist. A scan started in a subdirectory of a git repo still sees project MCP configs up to the repo root, and does not continue past that root. Checked from `packages/app` in a scratch repo whose root held `.cursor/mcp.json`: the report listed that file as `cursor-project` and graded the server A.

| Client | Paths this tool reads | Config docs |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` in the per-OS app directory (`~/Library/Application Support/Claude` on macOS, `%APPDATA%\Claude` on Windows, `~/.config/Claude` elsewhere) | [Local MCP servers on Claude Desktop](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop), and [custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) which name `claude_desktop_config.json` as the local-server file |
| Claude Code | `~/.claude.json` (top-level `mcpServers` and `projects.<path>.mcpServers`), `$CLAUDE_CONFIG_DIR/.claude.json` when that variable is set, and project `.mcp.json` | [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp), [MCP quickstart](https://code.claude.com/docs/en/mcp-quickstart) |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json`, plus the Cursor user `mcp.json` and profile copies under the editor user dir | [Cursor MCP](https://cursor.com/docs/mcp) |
| VS Code, VSCodium, Insiders, Code - OSS | `User/mcp.json`, each profile's `mcp.json`, and project `.vscode/mcp.json` | [Add and manage MCP servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers), [MCP configuration reference](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | [Cascade MCP](https://docs.windsurf.com/windsurf/cascade/mcp). That page currently documents `~/.config/devin/mcp_config.json` for Devin Desktop; pass that path explicitly if you use it |
| Cline, Roo Code, Kilo Code | The editor `globalStorage` settings files: `cline_mcp_settings.json` for `saoudrizwan.claude-dev` and `cline.cline`, `mcp_settings.json` for `rooveterinaryinc.roo-cline` and `kilocode.Kilo-Code` | [Cline](https://docs.cline.bot/mcp/configuring-mcp-servers), [Roo Code](https://docs.roocode.com/features/mcp/using-mcp-in-roo), [Kilo Code](https://kilo.ai/docs/automate/mcp/using-in-kilo-code). Current Kilo docs store servers under `mcp` in `kilo.jsonc`; pass that file explicitly |
| Zed | `settings.json` (`context_servers`), including a nested `command.path` / `command.args` object, and project `.zed/settings.json` | [Zed MCP](https://zed.dev/docs/ai/mcp) |
| Gemini CLI | `~/.gemini/settings.json` and project `.gemini/settings.json` | [Gemini CLI MCP servers](https://github.com/google-gemini/gemini-cli/blob/HEAD/docs/tools/mcp-server.md) |
| Codex CLI | `~/.codex/config.toml` and project `.codex/config.toml`, `[mcp_servers.<name>]` tables | [Codex config reference](https://developers.openai.com/codex/config-reference) |
| JetBrains Junie | `~/.junie/mcp/mcp.json` | [Junie MCP configuration](https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html). Junie also documents a project `.junie/mcp/mcp.json`; pass that path explicitly |
| Amazon Q Developer | `~/.aws/amazonq/mcp.json` and project `.amazonq/mcp.json` | [MCP configuration for Q Developer in the IDE](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/mcp-ide.html). That page describes `mcp.json` as the legacy location and `default.json` as the current GUI file |

JSON configs may include comments and trailing commas, which is how VS Code writes `mcp.json`. Args and env values that are numbers or booleans are accepted. Codex files are TOML. A file that exists and cannot be parsed becomes MCP017. It is not an empty successful scan.

Shapes the parser accepts:

- `{ "mcpServers": { } }` for Claude, Cursor, Windsurf, Gemini, Junie, Cline, and Roo
- `{ "servers": { } }` for VS Code `mcp.json`
- `{ "context_servers": { } }` for Zed
- `[mcp_servers.name]` tables for Codex

## Limits

mcp-fsck is a linter for config files and, if you opt in, for tool metadata. It cannot see what a compiled binary will do later. Static checks can miss a clever obfuscation, and they can flag an odd setup that you have already decided is fine. MCP005 is info for that reason. Findings are there so you can make the call.

Other scanners exist and make different tradeoffs. [Snyk Agent Scan](https://github.com/snyk/mcp-scan) discovers agent components and starts stdio servers to read their tool descriptions. [mcp-audit](https://github.com/onekn8/mcp-audit) is a local Rust static scanner. mcp-fsck's static mode stays on the config files, and deep mode is the opt-in handshake above.

## Development

```bash
npm test
npm run typecheck
```

`npm test` builds `dist/` and then runs the unit tests and the real command. This checkout: 7 files, 127 tests, all passed. `npm run typecheck` (`tsc --noEmit`) exited 0.

The deep tests drive `test/fixtures/fake-mcp-server.mjs` and `test/fixtures/framed-mcp-server.mjs` through a real JSON-RPC handshake.

New rules and client formats are welcome. Open an issue with a redacted config snippet.

## References

- [MCP specification, 2024-11-05](https://modelcontextprotocol.io/specification/2024-11-05) — the protocol version the deep client sends
- [Tools, including `tools/list`](https://modelcontextprotocol.io/specification/2024-11-05/server/tools)
- [Transports, 2024-11-05](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports) — newline-delimited stdio, and HTTP+SSE with the `endpoint` event
- [Transports, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) — streamable HTTP, `Mcp-Session-Id`, `MCP-Protocol-Version`
- [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- [Uploading a SARIF file to GitHub](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- Client config docs are linked in the [table above](#configs-it-reads)

## License

[MIT](LICENSE)
