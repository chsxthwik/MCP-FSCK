// MCP stdio server that answers with Content-Length frames.
// The client under test speaks newline-delimited JSON; this fixture replies
// in the legacy LSP-style framing so both readers stay covered.
let buf = Buffer.alloc(0);

function send(message) {
  const body = Buffer.from(JSON.stringify(message));
  process.stdout.write(`Content-Length: ${body.length}\r\n\r\n`);
  process.stdout.write(body);
}

process.stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  let nl = buf.indexOf(0x0a);
  while (nl !== -1) {
    const line = buf.subarray(0, nl).toString("utf8").trim();
    buf = buf.subarray(nl + 1);
    nl = buf.indexOf(0x0a);
    if (!line.startsWith("{")) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.method === "initialize") {
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "framed-mcp-server", version: "0.0.1" },
        },
      });
    } else if (msg.method === "tools/list") {
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: [{ name: "ping", description: "framed pong" }] },
      });
    } else if (msg.id !== undefined) {
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } });
    }
  }
});

setInterval(() => {}, 1 << 30);
