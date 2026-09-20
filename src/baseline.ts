import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseTolerantJson } from "./util.js";
import type { Finding, IgnoreEntry } from "./types.js";

/**
 * Baseline suppressions: a `.mcp-fsck.json` file listing findings the user has
 * already reviewed and accepted. Entries match on any combination of
 * `rule` (exact rule id), `server` (name or "*") and `source` (substring of
 * the config file path). An entry with no fields matches nothing.
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

function matchIgnore(entry: IgnoreEntry, finding: Finding): boolean {
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
    if (!finding.source.includes(entry.source)) return false;
    fields += 1;
  }
  return fields > 0;
}

/** Split findings into kept vs baseline-suppressed, preserving order. */
export function applyBaseline(findings: Finding[], ignore: IgnoreEntry[]): { kept: Finding[]; suppressed: Finding[] } {
  if (ignore.length === 0) return { kept: findings, suppressed: [] };
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const finding of findings) {
    if (ignore.some((entry) => matchIgnore(entry, finding))) {
      suppressed.push(finding);
    } else {
      kept.push(finding);
    }
  }
  return { kept, suppressed };
}

/** Build a baseline covering exactly the current findings (deduped). */
export function baselineFrom(findings: Finding[]): Baseline {
  const seen = new Set<string>();
  const ignore: IgnoreEntry[] = [];
  for (const f of findings) {
    const entry: IgnoreEntry = {
      rule: f.ruleId,
      ...(f.server !== undefined ? { server: f.server } : {}),
      source: f.source,
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
