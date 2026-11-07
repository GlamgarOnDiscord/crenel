// A host that serves its .env by mistake, and answers other unknown paths with
// a friendly 200 "not found" page (a soft 404 that must not count).
import { createServer } from "node:http";

export default () => createServer((req, res) => {
  if (req.url === "/.env") { res.writeHead(200, { "content-type": "text/plain" }); return res.end("STRIPE_SECRET_KEY=sk_live_redacted\nDATABASE_URL=postgres://app@db/app\n"); }
  if (req.url?.startsWith("/api/")) { res.writeHead(404); return res.end("{}"); }
  res.writeHead(200, { "content-type": "text/html" });
  res.end(`<html><h1>Page ${req.url} not found</h1></html>`);
});
