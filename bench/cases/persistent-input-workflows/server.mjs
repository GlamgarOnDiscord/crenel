// Stateful but isolated workflows. The fixture deliberately pairs each flaw
// with the same API shape implemented safely, so reflection and status alone
// cannot earn credit.
import { json, serve } from "../../lib/tenant-app.mjs";

const body = (req) => new Promise((resolve) => {
  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", () => { try { resolve(JSON.parse(raw || "{}")); } catch { resolve({}); } });
});
const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

export default () => {
  const unsafeUsers = [];
  const safeUsers = [];
  const comments = { unsafe: "", safe: "", json: "" };
  return serve([
  // BUG: request fields are copied into the new user row.
  { method: "POST", pattern: /^\/signup\/unsafe$/, async handle(req, res) {
    const value = await body(req);
    unsafeUsers.push({ username: value.username, role: value.role ?? "member" });
    return json(res, 201, { created: true });
  } },
  // Correct: role is assigned server-side, regardless of the request body.
  { method: "POST", pattern: /^\/signup\/safe$/, async handle(req, res) {
    const value = await body(req);
    safeUsers.push({ username: value.username, role: "member" });
    return json(res, 201, { created: true });
  } },
  { pattern: /^\/internal\/users\/unsafe$/, handle(_req, res) { return json(res, 200, { users: unsafeUsers }); } },
  { pattern: /^\/internal\/users\/safe$/, handle(_req, res) { return json(res, 200, { users: safeUsers }); } },

  { method: "POST", pattern: /^\/comments\/(unsafe|safe|json)$/, async handle(req, res, kind) {
    const value = await body(req);
    comments[kind] = typeof value.text === "string" ? value.text : "";
    return json(res, 201, { created: true });
  } },
  // BUG: stored input is interpolated into the HTML response unchanged.
  { pattern: /^\/feed\/unsafe$/, handle(_req, res) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<article>${comments.unsafe}</article>`);
  } },
  // Correct output encoding for the HTML context.
  { pattern: /^\/feed\/safe$/, handle(_req, res) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<article>${escapeHtml(comments.safe)}</article>`);
  } },
  // Raw markup can safely be returned as JSON data; it is not rendered here.
  { pattern: /^\/feed\/json$/, handle(_req, res) { return json(res, 200, { text: comments.json }); } },
  ]);
};
