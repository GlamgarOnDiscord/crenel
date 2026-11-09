// An extension filter blocks *.bak (403), but the file layer truncates at a null
// byte: a `.bak%00.md` suffix passes the filter (sees .md) and reads the .bak.
// A properly-secured area (/secure) resolves the real path and blocks the bypass
// too — the decoy the tool must not flag.
import { createServer } from "node:http";

const FILES = {
  "/ftp/secret.bak": "db_password=SuperSecret123\napi_key=sk_live_51abcDEF\n",
  "/secure/private.bak": "ssn=000-00-0000\n",
};
const page = (s, b) => (res) => { res.writeHead(s, { "content-type": "text/plain" }); res.end(b); };
const nb = /^(.*?)%(?:25)?00\.(?:md|png|ico|jpg|txt|json)$/i; // null-byte before an allowed ext

export default () => createServer((req, res) => {
  const raw = (req.url ?? "/").split("?")[0];
  const m = raw.match(nb);
  if (m) {
    const real = (() => { try { return decodeURIComponent(m[1]); } catch { return m[1]; } })();
    // /secure resolves the real path first and still blocks .bak (no bypass).
    if (real.startsWith("/secure/") && /\.bak$/i.test(real)) return page(403, "Forbidden")(res);
    return FILES[real] ? page(200, FILES[real])(res) : page(404, "Not found")(res);
  }
  if (/\.(bak|old|sql|env|zip)$/i.test(raw)) return page(403, "Forbidden")(res); // extension filter
  return page(404, "Not found")(res);
});
