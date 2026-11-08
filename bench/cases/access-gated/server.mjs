// A staging host behind Cloudflare Access, answered the way Access answers an
// anonymous request (the shape a real staging host returned on 2026-11-08):
// 302 to <team>.cloudflareaccess.com/cdn-cgi/access/login/<host>, a
// WWW-Authenticate: Cloudflare-Access header, a CF_AppSession cookie without
// SameSite, no security headers. None of it is the app: a tool that grades this
// page grades Cloudflare's login redirect, not the code behind it.
import { createServer } from "node:http";

export default () => createServer((req, res) => {
  const host = String(req.headers.host ?? "").replace(/:\d+$/, "");
  res.writeHead(302, {
    "content-type": "text/html; charset=UTF-8",
    location: `https://bench-team.cloudflareaccess.com/cdn-cgi/access/login/${host}?kid=ae09&redirect_url=${encodeURIComponent(req.url ?? "/")}`,
    "www-authenticate": `Cloudflare-Access resource_metadata="https://${host}/.well-known/cloudflare-access-protected-resource${req.url ?? "/"}"`,
    "set-cookie": "CF_AppSession=f9c6e42fa2386160; Path=/; Secure; HttpOnly",
    "cache-control": "private, max-age=0, no-store, no-cache, must-revalidate",
    "access-control-allow-credentials": "true",
    server: "cloudflare",
  });
  res.end("<html>\n<head><title>302 Found</title></head>\n<body>\n<center><h1>302 Found</h1></center>\n<hr><center>cloudflare</center>\n</body>\n</html>\n");
});
