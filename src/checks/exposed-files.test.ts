import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { exposedFiles } from "./exposed-files.js";
import { Scope } from "../core/scope.js";

async function serve(handler: (url: string) => [number, string]) {
  const srv = createServer((req, res) => { const [s, b] = handler(req.url ?? "/"); res.writeHead(s); res.end(b); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}/` };
}
const run = (base: string) => exposedFiles.run({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl: base, options: {}, log: () => {} });

test("a served .env and .git/HEAD are proven, by their content", async () => {
  const { srv, base } = await serve((u) => u === "/.env" ? [200, "# prod\nDATABASE_URL=postgres://u:p@db/app\n"] : u === "/.git/HEAD" ? [200, "ref: refs/heads/main\n"] : [404, "no"]);
  try {
    const found = await run(base);
    assert.deepEqual(found.map((f) => f.id).sort(), ["exposed-files:/.env", "exposed-files:/.git/HEAD"]);
    assert.equal(found.find((f) => f.id.endsWith("/.env"))!.severity, "critical");
  } finally { srv.close(); }
});

test("a single-page app answering every path with index.html is not a finding", async () => {
  const { srv, base } = await serve(() => [200, "<!doctype html><div id=root></div>\nAPP_NAME=x"]);
  try { assert.equal((await run(base)).length, 0); } finally { srv.close(); }
});

test("a 200 without the file's signature is ignored", async () => {
  const { srv, base } = await serve((u) => u === "/.env" ? [200, "<html>Not here</html>"] : [404, ""]);
  try { assert.equal((await run(base)).length, 0); } finally { srv.close(); }
});
