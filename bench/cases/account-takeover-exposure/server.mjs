// The takeover proof requires a rejected bogus-id control, a failed pre-change
// login, a successful post-change login and a successful restoration. Beside it,
// the response leak is paired with hashes and schema-shaped decoys.
import { createServer } from "node:http";

const ORIGINAL = "victim-original-Aa1!";
const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0tYiJ9.signature123456";
const read = (req) => new Promise((resolve) => {
  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", () => { try { resolve(JSON.parse(raw || "{}")); } catch { resolve({}); } });
});
const send = (res, status, value) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(value));
};

export default () => {
  const passwords = { "victim-b": ORIGINAL, "victim-safe": ORIGINAL };
  return createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", "http://local").pathname;
    const change = /^\/accounts\/(unsafe|safe)\/([^/]+)\/password$/.exec(path);
    if (change && req.method === "PUT") {
      const [, mode, id] = change;
      if (!(id in passwords)) return send(res, 404, { error: "account not found" });
      if (!req.headers.authorization) return send(res, 401, { error: "auth required" });
      if (mode === "safe" && req.headers.authorization !== "Bearer tok-b") return send(res, 403, { error: "owner required" });
      const value = await read(req);
      if (typeof value.password !== "string") return send(res, 400, { error: "password required" });
      passwords[id] = value.password;
      return send(res, 200, { changed: true });
    }
    if (path === "/login" && req.method === "POST") {
      const value = await read(req);
      if (typeof value.username === "string" && value.password === passwords[value.username]) return send(res, 200, { auth_token: TOKEN });
      return send(res, 401, { error: "invalid credentials" });
    }
    if (path === "/debug/raw-users") return send(res, 200, { users: [
      { username: "alice", password: "spring-river-17" },
      { username: "bob", password: "copper-cloud-82" }
    ] });
    if (path === "/debug/password-policy") return send(res, 200, { passwordPolicy: {
      acceptedAlgorithms: ["argon2id", "bcrypt"], minimumLength: 14, plaintextStorage: false
    } });
    if (path === "/debug/form-schema") return send(res, 200, { form: { password: "" }, labels: ["username", "password"] });
    return send(res, 404, { error: "not found" });
  });
};
