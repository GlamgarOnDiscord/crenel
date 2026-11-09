import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { commandInjection } from "./command-injection.js";
import { Scope } from "../core/scope.js";

// A sink that runs its input in a shell (echoes the result). The check must prove
// it via the computed nonce+49; a sink that reflects input without evaluating it
// (or ignores it) must stay unproven.
function sink(evaluate: boolean) {
  return createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      let arg = ""; try { arg = (JSON.parse(b || "{}").query ?? "").match(/arg:\s*"([^"]*)"/)?.[1] ?? ""; } catch { /* */ }
      let out = arg;
      if (evaluate) {
        // emulate a shell: evaluate `echo <x>$((7*7))` breakouts
        const m = arg.match(/echo\s+(\S*?)\$\(\(7\*7\)\)/);
        if (m) out = m[1] + "49";
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { systemDebug: out } }));
    });
  });
}

async function run(evaluate: boolean, active = true) {
  const srv = sink(evaluate);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    return await commandInjection.run({
      scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, allowActiveTesting: active }),
      projectDir: ".", stagingUrl: base, log: () => {},
      options: { "command-injection": { enabled: true, endpoints: [{ url: "/graphql", method: "POST", gql: '{ systemDebug(arg: "__INJECT__") }' }] } },
    });
  } finally { srv.close(); }
}

test("command-injection: a shell that evaluates the payload is proven", async () => {
  const f = await run(true);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.state, "proven");
  assert.match(f[0]!.title, /command|Template/i);
});

test("command-injection: a sink that only reflects input (no eval) stays unproven", async () => {
  const f = await run(false);
  assert.equal(f.filter((x) => x.state === "proven").length, 0);
});

test("command-injection: without active mode the check refuses to probe", async () => {
  await assert.rejects(() => run(true, false));
});
