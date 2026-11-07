// An Ollama server reachable without auth next to the app, and a vector DB that
// correctly asks for a key.
import { createServer } from "node:http";

export default () => createServer((req, res) => {
  const j = (s, b) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
  if (req.url === "/api/tags") return j(200, { models: [{ name: "llama3.1:8b" }, { name: "nomic-embed-text" }] });
  if (req.url?.startsWith("/api/v2/")) return j(401, { error: "unauthorized" });
  if (req.url === "/") { res.writeHead(200, { "content-type": "text/html" }); return res.end("<h1>app</h1>"); }
  j(404, {});
});
