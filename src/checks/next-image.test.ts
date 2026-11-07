import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { nextImage, DEFAULT_CONTROL_URL } from "./next-image.js";
import { Scope } from "../core/scope.js";
import type { CheckContext } from "../core/types.js";

async function serve(h: (req: IncomingMessage, res: ServerResponse) => void) {
  const srv = createServer(h);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` };
}
const ctx = (stagingUrl: string, options: Record<string, unknown> = {}): CheckContext =>
  ({ scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), projectDir: ".", stagingUrl, options, log: () => {} });

// A Next.js image optimizer: allowed(host) decides remotePatterns. It never fetches anything here.
const optimizer = (allowed: (host: string) => boolean, seen: string[] = [], widths = [16, 32, 48, 64, 96, 128, 256, 384, 640]) =>
  (req: IncomingMessage, res: ServerResponse) => {
    const u = new URL(req.url!, "http://x");
    if (u.pathname !== "/_next/image") { res.writeHead(200, { "content-type": "text/html" }); return res.end("<!doctype html><div id=root>"); }
    const url = u.searchParams.get("url");
    const bad = (m: string) => { res.writeHead(400, { "content-type": "text/plain" }); res.end(m); };
    if (!url) return bad('"url" parameter is required');
    if (!widths.includes(Number(u.searchParams.get("w")))) return bad(`"w" parameter (width) of ${u.searchParams.get("w")} is not allowed`);
    seen.push(url);
    if (!allowed(new URL(url).hostname)) return bad('"url" parameter is not allowed');
    bad("The requested resource isn't a valid image.");
  };

test("next-image: remotePatterns '**' makes the optimizer fetch the control URL: proven", async () => {
  const seen: string[] = [];
  const { srv, base } = await serve(optimizer(() => true, seen));
  try {
    const f = await nextImage.run(ctx(base));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.state, "proven");
    assert.equal(f[0]!.severity, "high");
    assert.deepEqual(seen, [DEFAULT_CONTROL_URL]);
    assert.match(f[0]!.proof!.replay, /_next\/image\?url=https%3A%2F%2Fexample\.com%2F&w=64&q=75/);
  } finally { srv.close(); }
});

test("next-image: a restricted remotePatterns answers 'not allowed': nothing", async () => {
  const { srv, base } = await serve(optimizer((h) => h === "images.acme.test"));
  try { assert.equal((await nextImage.run(ctx(base))).length, 0); } finally { srv.close(); }
});

test("next-image: a width outside imageSizes is retried with a device size; controlUrl is configurable", async () => {
  const seen: string[] = [];
  const { srv, base } = await serve(optimizer(() => true, seen, [640, 750]));
  try {
    const f = await nextImage.run(ctx(base, { "next-image": { controlUrl: "https://www.iana.org/favicon.ico" } }));
    assert.equal(f.length, 1);
    assert.match(f[0]!.location, /w=640/);
    assert.deepEqual(seen, ["https://www.iana.org/favicon.ico"]);
  } finally { srv.close(); }
});

test("next-image: a soft-200 page that echoes the words is not the optimizer (negative control)", async () => {
  const { srv, base } = await serve((_q, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end("<p>The requested resource isn't a valid image.</p>"); });
  try { assert.equal((await nextImage.run(ctx(base))).length, 0); } finally { srv.close(); }
});

test("next-image: a real image coming back counts; a non-http controlUrl is refused", async () => {
  const { srv, base } = await serve((req, res) => {
    if (!req.url!.includes("url=")) { res.writeHead(400); return res.end('"url" parameter is required'); }
    res.writeHead(200, { "content-type": "image/webp" }); res.end("RIFF");
  });
  try {
    assert.equal((await nextImage.run(ctx(base))).length, 1);
    assert.equal((await nextImage.run(ctx(base, { "next-image": { controlUrl: "file:///etc/passwd" } }))).length, 0);
  } finally { srv.close(); }
});
