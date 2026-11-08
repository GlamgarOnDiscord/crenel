// WSL backend, tested on Linux: unit tests with an injected wsl.exe, then end
// to end with a fake wsl.exe (fixtures/fake-wsl.mjs) that emulates WSLENV,
// -u root, UTF-16 output, and tools that talk to Crenel's proxy.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigSchema } from "../core/config.js";
import { Scope } from "../core/scope.js";
import { REGISTRY } from "../core/registry.js";
import { AgentRun } from "../agent/run.js";
import { StateStore } from "../agent/state.js";
import { exposedSecrets } from "../checks/exposed-secrets.js";
import type { ExecResult } from "./exec.js";
import { decodeWslBytes, installPlan, networkingOf, proxyEndpoint, templatesState, toolEnv, wslStatus, wslToolArgv, type WslExec } from "./wsl.js";
import { runTool, ToolboxOptions } from "./run.js";
import { toolsCommand } from "./cli.js";
import { filterHash, NUCLEI_TEMPLATES_SHA256, NUCLEI_TEMPLATES_VERSION } from "./paths.js";

const ok = (stdout = "", code = 0): ExecResult => ({ code, stdout, stderr: "", timedOut: false });

/** A scripted wsl.exe: answers by the program after --exec. */
function scripted(o: { distros?: string; info?: string; which?: string; code?: number }): { exec: WslExec; calls: string[][] } {
  const calls: string[][] = [];
  const exec: WslExec = async (args) => {
    calls.push(args);
    if (args[0] === "-l") return o.code !== undefined ? { code: o.code, stdout: "", stderr: "spawn wsl.exe ENOENT", timedOut: false } : ok(o.distros ?? "");
    const prog = args[args.indexOf("--exec") + 1];
    if (prog === "sh") return ok(o.info ?? "");
    if (prog === "which") return ok(o.which ?? "", 1);
    return ok();
  };
  return { exec, calls };
}

/** What realWsl returns for UTF-16LE output with a BOM (older wsl.exe builds). */
const utf16 = (s: string) => decodeWslBytes(Buffer.from("\uFEFF" + s, "utf16le"));
const INFO = "uid=1000\nuser=kali\nhome=/home/kali\nnet=mirrored\nkernel=5.15.167.4-microsoft-standard-WSL2\ngw=172.22.32.1\n";

test("wsl status: UTF-16 distro list, default non-root user, tools found by which, templates not installed", async () => {
  const { exec, calls } = scripted({ distros: utf16("Ubuntu\r\nkali-linux\r\n"), info: INFO, which: "/usr/bin/nuclei\n/usr/bin/trufflehog\n" });
  const st = await wslStatus("kali-linux", { exec });
  assert.equal(st.available, true, st.reason);
  assert.deepEqual(st.distros, ["Ubuntu", "kali-linux"]);
  assert.equal(st.uid, 1000);
  assert.deepEqual(st.endpoint, { listen: "127.0.0.1", dial: "127.0.0.1" }, "mirrored networking: the shared loopback");
  assert.equal(st.tools.nuclei, "/usr/bin/nuclei");
  assert.equal(st.tools.katana, null);
  assert.equal(st.templates.ready, false);
  assert.ok(calls.every((c) => !c.includes("-u")), "status never runs anything as root");
  assert.deepEqual(calls[2]!.slice(-4), ["which", "nuclei", "katana", "trufflehog"]);
});

test("wsl status: no WSL, a missing distro, and a root default user are each reported, never run", async () => {
  assert.match((await wslStatus("kali-linux", { exec: scripted({ code: 127 }).exec })).reason!, /WSL is not installed/);
  const missing = await wslStatus("kali-linux", { exec: scripted({ distros: "Ubuntu\n" }).exec });
  assert.equal(missing.available, false);
  assert.match(missing.reason!, /kali-linux is not installed .*wsl --install -d kali-linux/);
  const root = await wslStatus("kali-linux", { exec: scripted({ distros: "kali-linux\n", info: INFO.replace("uid=1000", "uid=0") }).exec });
  assert.equal(root.available, false);
  assert.match(root.reason!, /default user of kali-linux is root: tools never run as root/);
  assert.match((await wslStatus("kali linux; rm -rf /", { exec: scripted({}).exec })).reason!, /invalid distro name/);
});

test("wsl networking: mirrored and WSL 1 use the loopback, NAT the private gateway only, anything else needs proxyHost", () => {
  assert.equal(networkingOf("", "4.4.0-19041-Microsoft"), "wsl1");
  assert.equal(networkingOf("", "5.15.167.4-microsoft-standard-WSL2"), "nat");
  assert.equal(networkingOf("mirrored", ""), "mirrored");
  assert.deepEqual(proxyEndpoint("nat", "172.22.32.1"), { listen: "172.22.32.1", dial: "172.22.32.1" });
  assert.match((proxyEndpoint("nat", "8.8.8.8") as { error: string }).error, /not a private address/);
  assert.match((proxyEndpoint("nat", undefined) as { error: string }).error, /proxyHost/);
  assert.match((proxyEndpoint("unknown", "10.0.0.1") as { error: string }).error, /proxyHost/);
  assert.deepEqual(proxyEndpoint("nat", "172.22.32.1", "10.1.2.3"), { listen: "10.1.2.3", dial: "10.1.2.3" });
  assert.ok("error" in proxyEndpoint("nat", undefined, "localhost; x"));
});

test("wsl templates: only a set filtered by this filter version and the pinned release is trusted", () => {
  const good = JSON.stringify({ filter: filterHash(), version: NUCLEI_TEMPLATES_VERSION, kept: 3814 });
  assert.equal(templatesState(good, "/home/kali").ready, true);
  assert.equal(templatesState(undefined, "/home/kali").ready, false);
  assert.equal(templatesState(JSON.stringify({ filter: "0000", version: NUCLEI_TEMPLATES_VERSION }), "/home/kali").ready, false);
  assert.equal(templatesState("{not json", "/home/kali").ready, false);
});

test("wsl tool argv: default user (no -u), home directory, coreutils timeout, allowlisted programs only", () => {
  const a = wslToolArgv("kali-linux", 1_200_000, ["katana", "-u", "http://x/"]);
  assert.deepEqual(a.slice(0, 9), ["-d", "kali-linux", "--cd", "~", "--exec", "timeout", "-k", "10", "1200s"]);
  assert.ok(!a.includes("-u") || a.indexOf("-u") > a.indexOf("katana"), "never -u root for a tool");
  for (const bad of [["sqlmap", "-u", "x"], ["sh", "-c", "curl x"], ["bash"], []]) assert.throws(() => wslToolArgv("kali-linux", 1000, bad), /allowlisted/);
  const env = toolEnv("http://crenel:t@127.0.0.1:1");
  assert.deepEqual(env.WSLENV!.split(":").sort(), Object.keys(env).filter((k) => k !== "WSLENV").sort(), "WSLENV carries exactly the proxy and template variables");
  assert.equal(env.NO_PROXY, "");
  assert.equal(env.DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD, "true");
});

test("wsl install plan: root only for apt-get and the template permissions, never sudo or a password", () => {
  const plan = installPlan("/home/kali");
  const root = plan.filter((s) => s.as === "root").map((s) => s.argv.find((a) => !["env", "DEBIAN_FRONTEND=noninteractive"].includes(a)));
  assert.deepEqual(root, ["apt-get", "apt-get", "rm", "chown", "chmod"]);
  const all = JSON.stringify(plan);
  assert.ok(!/sudo|passwd|password|chpasswd/.test(all));
  assert.ok(all.includes(NUCLEI_TEMPLATES_SHA256), "the templates are checked against the pinned sha256");
  assert.ok(plan.find((s) => s.as === "root" && s.argv[0] === "rm")!.argv[2] === "/home/kali/.crenel/nuclei-templates");
  assert.throws(() => installPlan("/"), /unexpected home/);
  assert.throws(() => installPlan("/home/x y"), /unexpected home/);
});

test("pins: the WSL templates are the same release and sha256 as toolbox/Dockerfile", () => {
  const df = readFileSync(resolve(fileURLToPath(import.meta.url), "../../../toolbox/Dockerfile"), "utf8");
  assert.ok(df.includes(`TEMPLATES_VERSION=${NUCLEI_TEMPLATES_VERSION}`));
  assert.ok(df.includes(NUCLEI_TEMPLATES_SHA256));
});

/* ---------------- end to end with a fake wsl.exe ---------------- */

interface Fake { dir: string; root: string; log: string; cfgPath: string; calls: () => { argv: string[]; crossed: string[]; user?: string; tool?: string; [k: string]: unknown }[]; close: () => void }

function fakeWsl(over: Record<string, unknown> = {}): Fake {
  const dir = mkdtempSync(join(tmpdir(), "crenel-wsl-"));
  const root = join(dir, "distro");
  mkdirSync(join(root, "home", "kali"), { recursive: true });
  const log = join(dir, "calls.jsonl");
  const cfgPath = join(dir, "fake.json");
  writeFileSync(cfgPath, JSON.stringify({
    distros: ["Ubuntu", "kali-linux"], utf16: true, uid: 1000, user: "kali", home: "/home/kali", net: "mirrored",
    kernel: "5.15.167.4-microsoft-standard-WSL2", tools: { nuclei: "/usr/bin/nuclei", katana: "/usr/bin/katana", trufflehog: "/usr/bin/trufflehog" },
    root, log, ...over,
  }));
  const bin = join(dir, "wsl.exe");
  const script = fileURLToPath(new URL("./fixtures/fake-wsl.mjs", import.meta.url));
  writeFileSync(bin, `#!/bin/sh\nexec "${process.execPath}" "${script}" "$@"\n`);
  chmodSync(bin, 0o755);
  const prev = { wsl: process.env.CRENEL_WSL, fake: process.env.FAKE_WSL };
  process.env.CRENEL_WSL = bin;
  process.env.FAKE_WSL = cfgPath;
  return {
    dir, root, log, cfgPath,
    calls: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []),
    close: () => {
      if (prev.wsl === undefined) delete process.env.CRENEL_WSL; else process.env.CRENEL_WSL = prev.wsl;
      if (prev.fake === undefined) delete process.env.FAKE_WSL; else process.env.FAKE_WSL = prev.fake;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function target(): Promise<{ srv: Server; url: string; hits: string[] }> {
  const hits: string[] = [];
  const srv = createServer((q, s) => { hits.push(`${q.method} ${q.url}`); s.writeHead(q.url?.startsWith("/api/") ? 401 : 200, { "content-type": "text/html" }); s.end("<html>own staging</html>"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}/`, hits };
}

const skipOnWindows = process.platform === "win32" ? "the fake wsl.exe is a POSIX shell script" : false;
const cfg = (dir: string, url: string, extra: Record<string, unknown> = {}) => ConfigSchema.parse({
  project: "t", projectDir: dir,
  scope: { allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: url, ...((extra.scope as object) ?? {}) },
  options: { toolbox: { backend: "wsl", ...((extra.toolbox as object) ?? {}) } },
});

test("e2e: crenel tools install --wsl asks first; 'no' runs nothing, 'yes' installs as root and filters the templates read-only", { skip: skipOnWindows }, async () => {
  const f = fakeWsl();
  try {
    const config = cfg(f.dir, "http://127.0.0.1:1/");
    const io = { config, configPath: join(f.dir, "crenel.config.yaml"), json: false, wsl: true, out: () => {}, err: () => {}, hostPath: (_d: string, p: string) => join(f.root, p) };
    let text = "";
    assert.equal(await toolsCommand({ ...io, sub: "install", ask: async () => "no", out: (s) => { text += s; } }), 1);
    assert.match(text, /as root .*apt-get install -y --no-install-recommends nuclei katana trufflehog/);
    assert.match(text, /needs no password: Crenel never asks for one/);
    assert.ok(!f.calls().some((c) => c.user === "root"), "nothing ran as root after a 'no'");

    assert.equal(await toolsCommand({ ...io, sub: "install", ask: async () => "yes" }), 0);
    const rootCalls = f.calls().filter((c) => c.user === "root").map((c) => c.argv.slice(c.argv.indexOf("--exec") + 1)[0]);
    assert.deepEqual(rootCalls, ["apt-get", "env", "rm", "chown", "chmod"]);
    const fetch = f.calls().find((c) => c.fetched)!;
    assert.equal(fetch.asRoot, false, "the download runs as the default user");
    assert.equal(fetch.sha, NUCLEI_TEMPLATES_SHA256);
    const tdir = join(f.root, "home/kali/.crenel/nuclei-templates");
    assert.equal(readdirSync(join(tdir, "http", "exposures")).length, 60);
    assert.equal(existsSync(join(tdir, "http", "cves")) ? readdirSync(join(tdir, "http", "cves")).length : 0, 0, "templates off the allowlist are deleted");
    assert.equal(JSON.parse(readFileSync(join(tdir, ".crenel-filtered"), "utf8")).kept, 60);

    let status = "";
    assert.equal(await toolsCommand({ ...io, sub: "status", out: (s) => { status += s; } }), 0);
    assert.match(status, /backend  wsl .*distro kali-linux/);
    assert.match(status, /user {5}kali \(uid 1000\), tools run as this user/);
    assert.match(status, /tool {5}katana {5}present/);
    assert.match(status, /templates filtered set v10\.5\.1 \(60 kept, read-only\)/);
    assert.match(status, /not forced through it/);
  } finally { f.close(); }
});

test("e2e: nuclei from WSL goes through the scoped proxy (WSLENV and -proxy), off-scope results dropped, a header lead proven", { skip: skipOnWindows }, async () => {
  const f = fakeWsl({ templatesMarker: JSON.stringify({ filter: filterHash(), version: NUCLEI_TEMPLATES_VERSION, kept: 60 }) });
  const t = await target();
  try {
    const events: { refused?: string; target: string; status?: number }[] = [];
    const scope = new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true, stagingUrl: t.url });
    const off = await runTool({ tool: "nuclei", config: cfg(f.dir, t.url), projectDir: f.dir, scope, checks: REGISTRY });
    assert.equal(off.ran, false);
    assert.match(off.reason!, /allowActiveTesting/);

    const config = cfg(f.dir, t.url, { scope: { allowActiveTesting: true } });
    const r = await runTool({ tool: "nuclei", config, projectDir: f.dir, scope, checks: REGISTRY, onEvent: (e) => events.push(e) });
    assert.equal(r.ran, true, r.reason);
    assert.equal(r.backend, "wsl");
    assert.equal(r.network, "wsl+proxy");
    const call = f.calls().find((c) => c.tool === "nuclei")!;
    assert.equal(call.proxy, true);
    assert.equal(call.envProxy, true, "HTTP_PROXY crossed into the distro through WSLENV");
    assert.equal(call.templates, "/home/kali/.crenel/nuclei-templates/http", "only the filtered set");
    assert.equal(call.status, 200);
    assert.equal(call.stray, 403, "the proxy refused the undeclared host");
    assert.ok(events.some((e) => e.refused && e.target.includes("example.com")));
    assert.deepEqual(t.hits, ["GET /", "GET /"], "one request from nuclei, one re-read by the validator");
    assert.equal(r.findings.length, 1, "the off-scope result is dropped");
    assert.equal(r.findings[0]!.state, "proven", "header-reread confirmed the missing X-Frame-Options");
    const tool = f.calls().find((c) => c.tool === "nuclei")!;
    assert.ok(!JSON.stringify(f.calls().filter((c) => c !== tool).map((c) => c.argv)).includes("-u root"));
  } finally { t.srv.close(); f.close(); }
});

test("e2e: nuclei refuses to run from WSL without the filtered templates", { skip: skipOnWindows }, async () => {
  const f = fakeWsl();
  try {
    const config = cfg(f.dir, "http://127.0.0.1:1/", { scope: { allowActiveTesting: true } });
    const r = await runTool({ tool: "nuclei", config, projectDir: f.dir, scope: new Scope({ allowedHosts: ["127.0.0.1"], allowPrivate: true }), checks: REGISTRY });
    assert.equal(r.ran, false);
    assert.match(r.reason!, /crenel tools install --wsl/);
    assert.ok(!f.calls().some((c) => c.tool === "nuclei"));
  } finally { f.close(); }
});

test("e2e: trufflehog from WSL reads the project, a stray request hits a proxy that refuses everything, the lead is replayed", { skip: skipOnWindows }, async () => {
  const f = fakeWsl();
  try {
    writeFileSync(join(f.dir, "app.js"), `const k = "ghp_${"Q7rS9tU1vW3xY5zA2bC4dE6fG8hJ0kL2mN4p"}";\n`);
    const events: { refused?: string }[] = [];
    const r = await runTool({ tool: "trufflehog", config: cfg(f.dir, "http://127.0.0.1:1/"), projectDir: f.dir, scope: new Scope({ allowedHosts: ["127.0.0.1"] }), checks: REGISTRY, onEvent: (e) => events.push(e) });
    assert.equal(r.ran, true, r.reason);
    const call = f.calls().find((c) => c.tool === "trufflehog")!;
    assert.equal(call.stray, 403);
    assert.ok(events.length === 1 && events[0]!.refused, "journalled as refused");
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0]!.location, "app.js:1", "paths made relative to the project as WSL saw it");
    assert.equal(r.findings[0]!.state, "proven");
  } finally { f.close(); }
});

test("e2e: the agent treats WSL tools like Docker tools: katana and nuclei ask in ask mode, a deny sends nothing", { skip: skipOnWindows }, async () => {
  const f = fakeWsl({ templatesMarker: JSON.stringify({ filter: filterHash(), version: NUCLEI_TEMPLATES_VERSION, kept: 60 }) });
  const t = await target();
  try {
    writeFileSync(join(f.dir, "app.js"), "ok\n");
    const config = cfg(f.dir, t.url, { scope: { allowActiveTesting: true } });
    const store = new StateStore(join(f.dir, ".crenel"));
    const run = new AgentRun({ config, configPath: join(f.dir, "crenel.config.yaml"), store, grants: new Set(), llm: null, checks: [exposedSecrets] }, { prompt: "/tools", mode: "ask" });
    const asked: string[] = [];
    const done = run.start();
    for (let i = 0; i < 1500 && run.status !== "done" && run.status !== "error"; i++) {
      for (const e of run.journal.since(0)) {
        const ev = (e.data as { ev?: { kind: string; id: string; tool: string } }).ev;
        if (e.type === "ui" && ev?.kind === "permission" && !asked.includes(ev.id)) { asked.push(ev.id); asked.push(ev.tool); run.decide(ev.id, "deny"); }
      }
      await new Promise((r) => setTimeout(r, 10));
    }
    await done;
    assert.ok(asked.includes("tools.katana") && asked.includes("tools.nuclei"), `asked: ${asked.join(", ")}`);
    assert.ok(f.calls().some((c) => c.tool === "trufflehog"), "the offline tool ran");
    assert.ok(!f.calls().some((c) => c.tool === "katana" || c.tool === "nuclei"), "denied tools never started");
    assert.deepEqual(t.hits, []);
  } finally { t.srv.close(); f.close(); }
});

test("e2e: selftest on WSL: the proxy refuses example.com and the metadata address, lets the target through, reports direct egress as open", { skip: skipOnWindows }, async () => {
  const f = fakeWsl({ directOpen: true });
  const t = await target();
  try {
    let text = "";
    const code = await toolsCommand({ sub: "selftest", config: cfg(f.dir, t.url), configPath: join(f.dir, "crenel.config.yaml"), json: false, out: (s) => { text += s; }, err: (s) => { text += s; } });
    assert.equal(code, 0, text);
    assert.match(text, /PASS +proxy, undeclared host .*HTTP 403/);
    assert.match(text, /PASS +proxy, cloud metadata .*HTTP 403/);
    assert.match(text, /PASS +proxy, declared target .*HTTP 200/);
    assert.match(text, /OPEN +direct, undeclared host/);
    assert.match(text, /expected under WSL/);
  } finally { t.srv.close(); f.close(); }
});

test("options.toolbox: docker by default, wsl only when asked, distro validated", () => {
  assert.equal(ToolboxOptions.parse({}).backend, "docker");
  assert.equal(ToolboxOptions.parse({}).wsl.distro, "kali-linux");
  assert.equal(ToolboxOptions.parse({ backend: "wsl", wsl: { distro: "Ubuntu-24.04" } }).wsl.distro, "Ubuntu-24.04");
  assert.equal(ToolboxOptions.safeParse({ backend: "wsl", wsl: { distro: "kali; rm" } }).success, false);
  assert.equal(ToolboxOptions.safeParse({ backend: "podman" }).success, false);
});
