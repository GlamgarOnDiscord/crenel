import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Scope } from "../core/scope.js";
import { dockerStatus } from "./docker.js";
import { judge, probes, selfTest } from "./selftest.js";

test("self-test verdicts: a failure to connect passes a 'fail' probe, a proxy 403 passes a 'refused' probe", () => {
  const [direct, , , proxied] = probes();
  assert.equal(judge(direct!, "wget: bad address 'example.com'").pass, true);
  assert.equal(judge(direct!, "  HTTP/1.1 200 OK  <html>").pass, false, "a direct 200 means the confinement leaks");
  assert.equal(judge(proxied!, "  HTTP/1.1 403 Forbidden wget: server returned error: HTTP/1.1 403 Forbidden").pass, true);
  assert.equal(judge(proxied!, "wget: download timed out").pass, false, "a timeout is not a refusal: the proxy must answer");
});

// Real containers. Skipped (not failed) when Docker or the image is missing,
// so the suite still passes on a machine without the optional toolbox.
test("escape test: from the toolbox container, example.com, a raw IP and 169.254.169.254 are unreachable; the proxy refuses them and lets the declared target through", async (t) => {
  const st = await dockerStatus();
  if (!st.available || !st.imagePresent) { t.skip(`toolbox unavailable: ${st.reason}`); return; }
  const server = createServer((_q, s) => { s.writeHead(200, { "content-type": "text/plain" }); s.end("own target"); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  try {
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true });
    const r = await selfTest(scope, `http://127.0.0.1:${port}/`);
    for (const x of r.results) assert.ok(x.pass, `${x.name}: ${x.got}`);
    assert.ok(r.pass);
    const refused = r.events.filter((e) => e.refused).map((e) => e.target);
    assert.ok(refused.some((u) => u.includes("example.com")), "the proxy journalled the refusal of example.com");
    assert.ok(refused.some((u) => u.includes("169.254.169.254")), "the proxy journalled the refusal of the metadata address");
    assert.ok(r.events.some((e) => e.status === 200 && e.target.includes(`:${port}/`)), "the declared target went through, pinned");
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});
