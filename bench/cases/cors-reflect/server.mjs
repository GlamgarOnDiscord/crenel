// An API that echoes any Origin and allows credentials: any site a signed-in
// user visits can read their data.
import { createServer } from "node:http";

export default () => createServer((req, res) => {
  const headers = { "content-type": "application/json" };
  if (req.headers.origin) Object.assign(headers, { "access-control-allow-origin": req.headers.origin, "access-control-allow-credentials": "true" });
  res.writeHead(req.url === "/" ? 200 : 404, headers);
  res.end("{}");
});
