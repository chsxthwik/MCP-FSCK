import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { parseTolerantJson } from "./util.js";
import type { Finding, IgnoreEntry } from "./types.js";

/**
 * Baseline suppressions: a `.mcp-fsck.json` file listing findings the user has
 * already reviewed and accepted. Entries match on any combination of
 * `rule` (exact rule id), `server` (name or "*") and `source` (substring of
 * the config file path, a `~/` path, or a path relative to the working
 * directory). An entry with no fields matches nothing.
 */
export interface Baseline {
  ignore: IgnoreEntry[];
}

export const DEFAULT_BASELINE_NAME = ".mcp-fsck.json";

export function loadBaseline(path: string): Baseline {
  const text = readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = parseTolerantJson(text);
  } catch (err) {
    throw new Error(`not valid JSON: ${(err as Error).message}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("baseline must be an object with an \"ignore\" array");
  }
  const ignore = (parsed as Record<string, unknown>)["ignore"];
  if (ignore === undefined) return { ignore: [] };
  if (!Array.isArray(ignore)) {
    throw new Error("\"ignore\" must be an array");
  }
  const entries: IgnoreEntry[] = [];
  for (const item of ignore) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("each ignore entry must be an object");
    }
    const e = item as Record<string, unknown>;
    for (const key of ["rule", "server", "source"]) {
      if (e[key] !== undefined && typeof e[key] !== "string") {
        throw new Error(`ignore entry field "${key}" must be a string`);
      }
    }
    entries.push({
      rule: e["rule"] as string | undefined,
      server: e["server"] as string | undefined,
      source: e["source"] as string | undefined,
    });
  }
  return { ignore: entries };
}

/** Resolve the baseline path: explicit flag, else `.mcp-fsck.json` in cwd. */
export function resolveBaselinePath(explicit?: string): string | null {
  if (explicit !== undefined) return resolve(explicit);
  const def = resolve(DEFAULT_BASELINE_NAME);
  return existsSync(def) ? def : null;
}

function withinDir(path: string, dir: string): boolean {
  const base = resolve(dir);
  const abs = resolve(path);
  return abs === base || abs.startsWith(base + sep);
}

/**
 * Path stored in a baseline. Files inside `cwd` are relative to it, so a
 * committed baseline still matches on another checkout. Other files under
 * the home directory use a `~/` prefix. Everything else stays absolute.
 * Absolute entries from older baselines still match.
 */
export function portableSource(source: string, cwd = process.cwd()): string {
  const abs = resolve(source);
  const base = resolve(cwd);
  if (withinDir(abs, base) && abs !== base) {
    return relative(base, abs).replace(/\\/g, "/");
  }
  const home = resolve(homedir());
  if (home.length > 1 && withinDir(abs, home)) {
    return `~${abs.slice(home.length)}`.replace(/\\/g, "/");
  }
  return abs;
}

function expandSource(source: string, cwd: string): string {
  if (source === "~") return resolve(homedir());
  if (source.startsWith("~/") || source.startsWith("~\\")) return resolve(homedir(), source.slice(2));
  if (isAbsolute(source)) return resolve(source);
  return resolve(cwd, source);
}

function sourceMatches(entrySource: string, findingSource: string, cwd: string): boolean {
  // Substring match is the original contract (hand-written "mcp.json" entries).
  if (findingSource.includes(entrySource)) return true;
  return resolve(findingSource) === expandSource(entrySource, cwd);
}

function matchIgnore(entry: IgnoreEntry, finding: Finding, cwd: string): boolean {
  let fields = 0;
  if (entry.rule !== undefined) {
    if (entry.rule !== finding.ruleId) return false;
    fields += 1;
  }
  if (entry.server !== undefined) {
    if (entry.server !== "*" && entry.server !== finding.server) return false;
    fields += 1;
  }
  if (entry.source !== undefined) {
    if (!sourceMatches(entry.source, finding.source, cwd)) return false;
    fields += 1;
  }
  return fields > 0;
}

/** Split findings into kept vs baseline-suppressed, preserving order. */
export function applyBaseline(
  findings: Finding[],
  ignore: IgnoreEntry[],
  cwd = process.cwd(),
): { kept: Finding[]; suppressed: Finding[] } {
  if (ignore.length === 0) return { kept: findings, suppressed: [] };
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const finding of findings) {
    if (ignore.some((entry) => matchIgnore(entry, finding, cwd))) {
      suppressed.push(finding);
    } else {
      kept.push(finding);
    }
  }
  return { kept, suppressed };
}

/** Build a baseline covering exactly the current findings (deduped). */
export function baselineFrom(findings: Finding[], cwd = process.cwd()): Baseline {
  const seen = new Set<string>();
  const ignore: IgnoreEntry[] = [];
  for (const f of findings) {
    const entry: IgnoreEntry = {
      rule: f.ruleId,
      ...(f.server !== undefined ? { server: f.server } : {}),
      source: portableSource(f.source, cwd),
    };
    const key = JSON.stringify(entry);
    if (seen.has(key)) continue;
    seen.add(key);
    ignore.push(entry);
  }
  return { ignore };
}

export function writeBaseline(path: string, baseline: Baseline): void {
  writeFileSync(path, `${JSON.stringify(baseline, null, 2)}\n`);
}
