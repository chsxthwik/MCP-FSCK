/**
 * Minimal TOML subset parser — just enough for Codex CLI's config.toml:
 *
 *   [mcp_servers.name]
 *   command = "npx"
 *   args = ["-y", "pkg"]
 *   env = { KEY = "value" }
 *   [mcp_servers.name.env]
 *   OTHER = "value"
 *
 * Supports: [dotted.tables], "basic" and 'literal' strings, arrays, inline
 * tables, integers/floats/booleans, and # comments outside strings.
 * Anything it cannot parse throws, so callers can report a parse error
 * instead of silently misreading the file.
 */

type TomlTable = Record<string, unknown>;

function unescapeBasic(body: string): string {
  return body.replace(/\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)/g, (m, esc: string) => {
    switch (esc) {
      case "n": return "\n";
      case "t": return "\t";
      case "r": return "\r";
      case '"': return '"';
      case "\\": return "\\";
      case "b": return "\b";
      case "f": return "\f";
      default:
        if (esc.startsWith("u") || esc.startsWith("U")) {
          return String.fromCodePoint(Number.parseInt(esc.slice(1), 16));
        }
        return m;
    }
  });
}

class TomlParser {
  private i = 0;
  constructor(private text: string) {}

  private peek(): string | undefined {
    return this.text[this.i];
  }

  private skipWs(withinLine = false): void {
    while (this.i < this.text.length) {
      const c = this.text[this.i]!;
      if (c === " " || c === "\t" || (!withinLine && (c === "\n" || c === "\r"))) {
        this.i += 1;
        continue;
      }
      if (c === "#") {
        while (this.i < this.text.length && this.text[this.i] !== "\n") this.i += 1;
        continue;
      }
      break;
    }
  }

  private parseKeyPart(): string {
    this.skipWs(true);
    const c = this.peek();
    if (c === '"' || c === "'") return this.parseString() as string;
    const m = /^[A-Za-z0-9_-]+/.exec(this.text.slice(this.i));
    if (m === null) throw new Error(`expected key at offset ${this.i}`);
    this.i += m[0].length;
    return m[0];
  }

  private parseString(): string {
    const quote = this.peek()!;
    if (this.text.startsWith(quote.repeat(3), this.i)) {
      // multiline strings: keep contents verbatim
      const q = quote.repeat(3);
      const end = this.text.indexOf(q, this.i + 3);
      if (end === -1) throw new Error("unterminated multiline string");
      let body = this.text.slice(this.i + 3, end);
      this.i = end + 3;
      if (body.startsWith("\n")) body = body.slice(1);
      return quote === '"' ? unescapeBasic(body) : body;
    }
    this.i += 1;
    const start = this.i;
    if (quote === "'") {
      const end = this.text.indexOf("'", this.i);
      if (end === -1) throw new Error("unterminated literal string");
      this.i = end + 1;
      return this.text.slice(start, end);
    }
    let out = "";
    while (this.i < this.text.length) {
      const c = this.text[this.i]!;
      if (c === '"') {
        this.i += 1;
        return out;
      }
      if (c === "\n") throw new Error("unterminated string");
      if (c === "\\") {
        const esc = /^\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)/.exec(this.text.slice(this.i));
        if (esc === null) throw new Error("bad escape");
        out += unescapeBasic(esc[0]);
        this.i += esc[0].length;
        continue;
      }
      out += c;
      this.i += 1;
    }
    throw new Error("unterminated string");
  }

  private parseArray(): unknown[] {
    this.i += 1; // [
    const out: unknown[] = [];
    for (;;) {
      this.skipWs();
      if (this.peek() === "]") {
        this.i += 1;
        return out;
      }
      out.push(this.parseValue());
      this.skipWs();
      if (this.peek() === ",") {
        this.i += 1;
        continue;
      }
      if (this.peek() === "]") {
        this.i += 1;
        return out;
      }
      throw new Error(`expected ',' or ']' at offset ${this.i}`);
    }
  }

  private parseInlineTable(): TomlTable {
    this.i += 1; // {
    const out: TomlTable = {};
    for (;;) {
      this.skipWs(true);
      if (this.peek() === "}") {
        this.i += 1;
        return out;
      }
      const key = this.parseKeyPart();
      this.skipWs(true);
      if (this.peek() !== "=") throw new Error(`expected '=' at offset ${this.i}`);
      this.i += 1;
      out[key] = this.parseValue();
      this.skipWs(true);
      if (this.peek() === ",") {
        this.i += 1;
        continue;
      }
      if (this.peek() === "}") {
        this.i += 1;
        return out;
      }
      throw new Error(`expected ',' or '}' at offset ${this.i}`);
    }
  }

  private parseValue(): unknown {
    this.skipWs(true);
    const c = this.peek();
    if (c === '"' || c === "'") return this.parseString();
    if (c === "[") return this.parseArray();
    if (c === "{") return this.parseInlineTable();
    const rest = this.text.slice(this.i);
    const m = /^(true|false|[-+]?\d[\d_]*(\.\d+)?([eE][-+]?\d+)?|[-+]?\.\d+)/.exec(rest);
    if (m === null) throw new Error(`cannot parse value at offset ${this.i}`);
    this.i += m[0].length;
    const raw = m[0].replace(/_/g, "");
    if (raw === "true") return true;
    if (raw === "false") return false;
    return Number(raw);
  }

  parse(): TomlTable {
    const root: TomlTable = {};
    let current = root;
    while (true) {
      this.skipWs();
      if (this.i >= this.text.length) return root;
      const c = this.peek()!;
      if (c === "[") {
        // [table] or [[array-of-tables]] — for mcp_servers both reduce to a map
        const double = this.text[this.i + 1] === "[";
        this.i += double ? 2 : 1;
        const parts: string[] = [];
        for (;;) {
          parts.push(this.parseKeyPart());
          this.skipWs(true);
          if (this.peek() === ".") {
            this.i += 1;
            continue;
          }
          break;
        }
        const closer = double ? "]]" : "]";
        if (!this.text.startsWith(closer, this.i)) {
          throw new Error(`expected '${closer}' at offset ${this.i}`);
        }
        this.i += closer.length;
        current = root;
        for (const p of parts) {
          const next = current[p];
          if (next === undefined || typeof next !== "object" || next === null) {
            current[p] = {};
          }
          current = current[p] as TomlTable;
        }
        continue;
      }
      const key = this.parseKeyPart();
      this.skipWs(true);
      if (this.peek() !== "=") throw new Error(`expected '=' at offset ${this.i}`);
      this.i += 1;
      current[key] = this.parseValue();
      // consume rest-of-line (must be comment or blank)
      this.skipWs(true);
      if (this.peek() !== undefined && this.peek() !== "\n" && this.peek() !== "\r") {
        throw new Error(`unexpected content after value at offset ${this.i}`);
      }
    }
  }
}

/** Parse a TOML document, restricted to the constructs MCP configs use. */
export function parseTomlSubset(text: string): TomlTable {
  return new TomlParser(text).parse();
}
