// /api/leaky returns a stack trace when the JSON body is malformed (dev error
// handler left on); /api/safe returns a clean generic error (the decoy).
import { createServer } from "node:http";

const STACK = [
  "SyntaxError: Unexpected end of JSON input",
  "    at JSON.parse (<anonymous>)",
  "    at parse (/app/node_modules/body-parser/lib/types/json.js:89:19)",
  "    at /app/server.js:42:10",
  "    at Layer.handle (/app/node_modules/express/lib/router/layer.js:95:5)",
].join("\n");

const read = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });

export default () => createServer(async (req, res) => {
  const body = await read(req);
  let ok = true; try { JSON.parse(body || "{}"); } catch { ok = false; }
  const send = (s, b, t = "text/plain") => { res.writeHead(s, { "content-type": t }); res.end(b); };
  if (req.url === "/api/leaky") return ok ? send(400, '{"error":"missing field"}', "application/json") : send(500, STACK);
  if (req.url === "/api/safe") return ok ? send(400, '{"error":"missing field"}', "application/json") : send(500, '{"error":"Internal Server Error"}', "application/json");
  send(404, "no");
});
