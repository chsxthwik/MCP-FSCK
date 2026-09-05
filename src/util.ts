import { homedir } from "node:os";

/**
 * Parse JSON that may contain comments and trailing commas (VS Code's mcp.json
 * is JSONC). Strings are respected so "//" inside a value is never stripped.
 */
export function stripJsonComments(text: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < text.length) {
    const ch = text[i]!;
    if (inString) {
      out += ch;
      if (ch === "\\") {
        // keep escape sequences verbatim
        if (i + 1 < text.length) {
          out += text[i + 1]!;
          i += 2;
          continue;
        }
      } else if (ch === '"') {
        inString = false;
      }
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

export function stripTrailingCommas(text: string): string {
  // remove a comma directly followed by } or ] (outside strings — input is
  // already comment-free and strings contain no bare } risk is acceptable;
  // we still track strings to avoid mangling string content like "a,}")
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (inString) {
      out += ch;
      if (ch === "\\") {
        if (i + 1 < text.length) {
          out += text[i + 1]!;
          i += 1;
        }
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j += 1;
      if (j < text.length && (text[j] === "}" || text[j] === "]")) continue;
    }
    out += ch;
  }
  return out;
}

export function parseTolerantJson(text: string): unknown {
  const cleaned = stripTrailingCommas(stripJsonComments(text));
  return JSON.parse(cleaned);
}

/** True when a value looks like a placeholder rather than a real secret. */
export function looksLikePlaceholder(value: string): boolean {
  return (
    /^\$\{.+\}$/.test(value) ||
    /^\{\{.+\}\}$/.test(value) ||
    /^<[a-z0-9_-]+>$/i.test(value) ||
    /^(changeme|change-me|your[-_].*|xxx+|\*+|example|placeholder|dummy|redacted|none|n\/?a|true|false|1|0)$/i.test(
      value,
    )
  );
}

/** Redact the middle of a sensitive value, keeping a short prefix. */
export function redactSecret(value: string): string {
  if (value.length <= 8) return "…";
  return `${value.slice(0, 4)}…(redacted, ${value.length} chars)`;
}

export function home(): string {
  return homedir();
}
