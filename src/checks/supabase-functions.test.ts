import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { supabaseFunctions, verifyJwtOff } from "./supabase-functions.js";

test("verifyJwtOff reads [functions.x] sections", () => {
  assert.deepEqual([...verifyJwtOff(`[api]\nverify_jwt = false\n[functions.stripe-webhook]\nverify_jwt = false\n[functions.report]\nverify_jwt = true\n`)], ["stripe-webhook"]);
});

test("supabase-functions: service role without a caller check is a lead; getUser, a signature or a secret header is fine", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crenel-sbf-"));
  const fn = (name: string, code: string) => { mkdirSync(join(dir, "supabase", "functions", name), { recursive: true }); writeFileSync(join(dir, "supabase", "functions", name, "index.ts"), code); };
  try {
    mkdirSync(join(dir, "supabase"), { recursive: true });
    writeFileSync(join(dir, "supabase", "config.toml"), `[functions.export-users]\nverify_jwt = false\n`);
    fn("export-users", `const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nDeno.serve(async () => Response.json(await admin.from("profiles").select("*")));`);
    fn("grant-credits", `const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nDeno.serve(async (req) => { const { userId } = await req.json(); await admin.from("credits").insert({ userId, n: 100 }); return new Response("ok") });`);
    fn("me", `const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nDeno.serve(async (req) => { const { data: { user } } = await admin.auth.getUser(req.headers.get("Authorization")!.replace("Bearer ", "")); return Response.json(user) });`);
    fn("stripe-webhook", `const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nconst event = await stripe.webhooks.constructEventAsync(body, sig, secret);`);
    fn("cron", `const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nif (req.headers.get("authorization") !== \`Bearer \${Deno.env.get("CRON_SECRET")}\`) return new Response("no", { status: 401 });`);
    fn("hello", `Deno.serve(() => new Response("hi"))`);
    mkdirSync(join(dir, "supabase", "functions", "_shared"), { recursive: true });
    writeFileSync(join(dir, "supabase", "functions", "_shared", "admin.ts"), `export const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);`);
    const f = await supabaseFunctions.run({ scope: undefined as never, projectDir: dir, options: {}, log: () => {} });
    assert.deepEqual(f.map((x) => x.id).sort(), ["supabase-functions:export-users", "supabase-functions:grant-credits"]);
    const exp = f.find((x) => x.id.endsWith("export-users"))!;
    assert.match(exp.title, /verify_jwt = false/);
    assert.equal(exp.location, "supabase/functions/export-users/index.ts");
    assert.match(f.find((x) => x.id.endsWith("grant-credits"))!.description, /anon key .* is one/);
    assert.ok(f.every((x) => x.state === "unproven"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
