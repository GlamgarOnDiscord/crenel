// A shared cache keyed on path + query. The app writes X-Forwarded-Host into
// its script URLs. /pricing answers with Vary: X-Forwarded-Host, which this
// cache honours; / does not.
import { createServer } from "node:http";

export default () => {
  const cache = new Map();
  return createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const vary = u.pathname === "/pricing";
    const key = u.pathname + u.search + (vary ? `|${req.headers["x-forwarded-host"] ?? ""}` : "");
    const hit = cache.get(key);
    if (hit) { res.writeHead(200, { "content-type": "text/html", "x-cache": "HIT", age: "3" }); return res.end(hit); }
    const host = req.headers["x-forwarded-host"] ?? "app.acme.test";
    const body = `<!doctype html><title>Acme</title><script src="https://${host}/_static/app.js"></script>`;
    cache.set(key, body);
    res.writeHead(200, { "content-type": "text/html", "x-cache": "MISS", ...(vary ? { vary: "X-Forwarded-Host" } : {}) });
    res.end(body);
  });
};
