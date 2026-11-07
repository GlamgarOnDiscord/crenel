// A CDN that caches anything ending in .css, in front of an app that ignores
// unknown path suffixes.
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

const cache = new Map();
const projects = { proj_b_1: { id: "proj_b_1", tenant: "t_b", name: "Bravo payroll" } };
const app = serve([
  { pattern: /^\/api\/projects\/([^/;.]+)/, handle(req, res, id) {
    const u = userOf(req); if (!u) return json(res, 401, { error: "auth" });
    const p = projects[id]; return p && p.tenant === u.tenant ? json(res, 200, p) : json(res, 404, { error: "not found" });
  } },
]);
export default () => {
  const listeners = app.listeners("request");
  app.removeAllListeners("request");
  app.on("request", (req, res) => {
    const key = req.url ?? "";
    if (/\.css(\?|$)/.test(key) && cache.has(key)) { res.writeHead(200, { "content-type": "application/json", "x-cache": "HIT" }); return res.end(cache.get(key)); }
    if (/\.css(\?|$)/.test(key)) {
      const end = res.end.bind(res);
      res.end = (body, ...rest) => { if (res.statusCode === 200 && body) cache.set(key, String(body)); return end(body, ...rest); };
    }
    for (const l of listeners) l.call(app, req, res);
  });
  return app;
};
