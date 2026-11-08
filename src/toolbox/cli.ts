// `crenel tools ...`: the optional toolbox from the command line.
//
//   crenel tools status                 active backend (docker or wsl), what is present, options.toolbox
//   crenel tools build                  build the image from toolbox/ (Docker backend)
//   crenel tools install --wsl [--yes]  apt-get install the allowlisted tools in the WSL distro (asks first)
//   crenel tools selftest               escape test of the confinement (real containers, or the WSL distro)
//   crenel tools nuclei|katana|trufflehog [--json]
//
// Every egress event of the proxy (sent or refused) is appended to the audit
// JSONL (.crenel/audit.jsonl next to the config, or --audit <file>).

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { Config } from "../core/config.js";
import { Scope } from "../core/scope.js";
import { REGISTRY } from "../core/registry.js";
import type { ProxyEvent } from "../core/egress-proxy.js";
import { buildImage, cleanupLeftovers, dockerStatus } from "./docker.js";
import { runTool, toolboxOptions, TOOL_NAMES, type ToolName, type ToolboxOptions } from "./run.js";
import { backendFor, type BackendStatus } from "./backend.js";
import { installWsl, WSL_BINARIES, type InstallStep, type WslExec } from "./wsl.js";
import { wslSelfTest } from "./wsl-selftest.js";
import { selfTest } from "./selftest.js";
import { toolboxDir } from "./paths.js";

export interface ToolsCliInput {
  sub: string;
  config: Config;
  configPath: string;
  json: boolean;
  audit?: string;
  /** install: --wsl (the only install there is), --yes (skip the question). */
  wsl?: boolean;
  yes?: boolean;
  /** install: asks the question on a terminal; tests inject an answer. */
  ask?: (question: string) => Promise<string>;
  /** Replaces wsl.exe (tests). */
  wslExec?: WslExec;
  /** Replaces the \\wsl.localhost path mapping of the install's filter step (tests). */
  hostPath?: (distro: string, linuxPath: string) => string;
  out: (s: string) => void;
  err: (s: string) => void;
}

function statusLines(st: BackendStatus, o: ToolboxOptions): string[] {
  const agent = `agent    ${o.enabled ? "tools included in full scans" : "off in agent runs (options.toolbox.enabled: false)"}`;
  if (st.backend === "docker" && st.docker) {
    const d = st.docker;
    return [
      `backend  docker (options.toolbox.backend)`,
      `docker   ${d.available ? `yes (${d.version})` : "no"}`,
      `image    ${d.image} ${d.imagePresent ? "(built)" : "(not built)"}`,
      `relay    ${d.relay === "unix" ? "Unix socket, no container has a route out" : "TCP via host.docker.internal (Docker Desktop)"}`,
      agent,
      ...(st.reason ? [`note     ${st.reason}`] : []),
    ];
  }
  const w = st.wsl!;
  const net = w.endpoint ? `${w.networking}: proxy on ${w.endpoint.listen}, tools dial ${w.endpoint.dial}` : (w.networking ?? "unknown");
  return [
    `backend  wsl (options.toolbox.backend), distro ${w.distro}`,
    `wsl      ${w.wsl ? "yes" : "no"}${w.wsl ? `, distro ${w.distroPresent ? "installed" : "NOT installed"} (installed: ${w.distros.join(", ") || "none"})` : ""}`,
    ...(w.uid !== undefined ? [`user     ${w.user ?? "?"} (uid ${w.uid})${w.uid === 0 ? ": root, refused" : ", tools run as this user"}`] : []),
    ...(w.distroPresent ? [`network  ${net}`] : []),
    ...TOOL_NAMES.map((t) => `tool     ${t.padEnd(10)} ${w.tools[t] ? `present (${w.tools[t]})` : `missing (${WSL_BINARIES[t]})`}${st.tools[t].ready || !w.tools[t] ? "" : `, ${st.tools[t].reason}`}`),
    `templates ${w.templates.ready ? `filtered set v${w.templates.version} (${w.templates.kept} kept, read-only)` : (w.templates.reason ?? "not installed")}`,
    "confine  weaker than Docker: tools are pointed at the proxy, not forced through it (docs/TOOLBOX.md)",
    agent,
    ...(st.reason ? [`note     ${st.reason}`] : []),
  ];
}

async function askTerminal(question: string): Promise<string> {
  if (!process.stdin.isTTY) return "";
  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try { return await rl.question(question); } finally { rl.close(); }
}

export { toolboxDir } from "./paths.js";

function auditWriter(path: string): (e: Record<string, unknown>) => void {
  mkdirSync(dirname(path), { recursive: true });
  return (e) => appendFileSync(path, JSON.stringify(e) + "\n");
}

export async function toolsCommand(i: ToolsCliInput): Promise<number> {
  const configDir = dirname(resolve(i.configPath));
  const auditPath = i.audit ?? join(configDir, ".crenel", "audit.jsonl");
  const sub = i.sub;
  let writer: ((e: Record<string, unknown>) => void) | undefined;
  const write = (e: Record<string, unknown>) => (writer ??= auditWriter(auditPath))(e);

  if (sub === "status") {
    const o = toolboxOptions(i.config);
    const st = await backendFor(o, { wslExec: i.wslExec }).status();
    if (i.json) { i.out(JSON.stringify({ ...st, enabledInAgentRuns: o.enabled, options: o }, null, 2) + "\n"); return st.ready ? 0 : 1; }
    i.out([...statusLines(st, o), ""].join("\n"));
    return st.ready ? 0 : 1;
  }

  if (sub === "build") {
    const o = toolboxOptions(i.config);
    if (o.backend === "wsl") { i.err("crenel tools build is for the Docker backend; with the WSL backend run `crenel tools install --wsl`\n"); return 2; }
    const dir = toolboxDir();
    i.out(`Building ${o.image} from ${dir} (pinned inputs, a few minutes)...\n`);
    const r = await buildImage(dir, o.image);
    if (r.code !== 0) { i.err(r.stderr.slice(-2000) + "\n"); return 1; }
    i.out(`Built ${o.image}.\n`);
    return 0;
  }

  if (sub === "install") {
    if (!i.wsl) { i.err("crenel tools install --wsl installs the tools in a WSL distribution; for the Docker image run `crenel tools build`\n"); return 2; }
    const o = toolboxOptions(i.config);
    const distro = o.wsl.distro;
    const ask = i.ask ?? askTerminal;
    const confirm = async (plan: InstallStep[]) => {
      i.out(`crenel tools install --wsl will run, in the WSL distribution ${distro}:\n\n`);
      for (const s of plan) i.out(`  ${s.as === "root" ? "as root " : s.as === "user" ? "as user " : "Crenel  "} ${s.argv.map((a) => (a.length > 60 ? a.slice(0, 57) + "..." : a)).join(" ")}\n           ${s.why}\n`);
      i.out("\nRoot steps use `wsl -u root`, which needs no password: Crenel never asks for one.\nThe tools themselves always run as the distro's default (non-root) user.\n\n");
      if (i.yes) return true;
      const a = (await ask("Type yes to run these steps: ")).trim().toLowerCase();
      if (a === "") i.err("No answer (not a terminal?): pass --yes to confirm.\n");
      return a === "yes";
    };
    const r = await installWsl(distro, { exec: i.wslExec, confirm, out: i.out, hostPath: i.hostPath });
    write({ at: new Date().toISOString(), kind: "toolbox.install", backend: "wsl", distro, ok: r.ok, reason: r.reason, steps: r.ran.map((s) => ({ as: s.as, argv: s.argv.slice(0, 3) })), kept: r.kept });
    if (!r.ok) { i.err(`${r.reason}\n`); return 1; }
    i.out(`\nInstalled. ${r.kept} nuclei templates kept, ${r.removed} removed by the filter. Next: crenel tools status, then crenel tools selftest.\n`);
    if (o.backend !== "wsl") i.out("The active backend is still docker: set options.toolbox.backend: wsl to use these tools.\n");
    return 0;
  }

  if (sub === "cleanup") {
    await cleanupLeftovers();
    i.out("Removed leftover toolbox containers and networks.\n");
    return 0;
  }

  const scope = new Scope({
    allowedHosts: i.config.scope.allowedHosts, allowActiveTesting: i.config.scope.allowActiveTesting,
    allowPrivate: i.config.scope.allowPrivate, stagingUrl: i.config.scope.stagingUrl,
  });
  const onEvent = (e: ProxyEvent) => write({ ...e });

  if (sub === "selftest" && toolboxOptions(i.config).backend === "wsl") {
    const o = toolboxOptions(i.config);
    const st = await backendFor(o, { wslExec: i.wslExec }).status();
    if (!st.ready || !st.wsl?.endpoint) { i.err(`toolbox off: ${st.reason}\n`); return 2; }
    const r = await wslSelfTest({ scope, distro: o.wsl.distro, endpoint: st.wsl.endpoint, target: i.config.scope.stagingUrl, exec: i.wslExec });
    for (const e of r.events) write({ ...e });
    write({ at: new Date().toISOString(), kind: "toolbox.selftest", backend: "wsl", pass: r.pass, proxyHolds: r.proxyHolds, directOpen: r.directOpen, targetReachable: r.targetReachable, results: r.results.map((x) => ({ name: x.name, code: x.code, pass: x.pass, direct: x.direct })) });
    if (i.json) { i.out(JSON.stringify({ backend: "wsl", pass: r.pass, proxyHolds: r.proxyHolds, directOpen: r.directOpen, targetReachable: r.targetReachable, results: r.results }, null, 2) + "\n"); return r.pass ? 0 : 1; }
    for (const x of r.results) {
      const verdict = x.via === "direct" ? (x.direct === "open" ? "OPEN" : "shut") : x.pass ? "PASS" : "FAIL";
      i.out(`${verdict.padEnd(5)} ${x.name.padEnd(32)} ${x.url}  (HTTP ${x.code || "none"})\n`);
    }
    i.out(`\n${r.proxyHolds ? "The proxy refuses undeclared hosts and the metadata address" : "PROXY CHECK FAILED: do not use the WSL backend on this machine"}.\n`);
    if (r.directOpen) i.out("Direct requests from the distro reach the network without the proxy: expected under WSL. Tools are pointed at the proxy, not confined (docs/TOOLBOX.md).\n");
    if (r.targetReachable === false) i.out("The declared target did not answer through the proxy: is it running, and can WSL reach the proxy address? (Windows firewall in NAT mode)\n");
    if (r.results.every((x) => x.code === 0)) i.out(`No probe answered at all: is curl installed in the distro? (crenel tools install --wsl)${r.stderr ? `\n${r.stderr.slice(-400)}` : ""}\n`);
    i.out(`Proxy events in ${auditPath}.\n`);
    return r.pass ? 0 : 1;
  }

  if (sub === "selftest") {
    const st = await dockerStatus(toolboxOptions(i.config).image);
    if (!st.available || !st.imagePresent) { i.err(`toolbox off: ${st.reason}\n`); return 2; }
    const r = await selfTest(scope, i.config.scope.stagingUrl);
    for (const e of r.events) write({ ...e });
    write({ at: new Date().toISOString(), kind: "toolbox.selftest", pass: r.pass, confined: r.confined, targetReachable: r.targetReachable, results: r.results.map((x) => ({ name: x.name, pass: x.pass })) });
    if (i.json) { i.out(JSON.stringify({ pass: r.pass, confined: r.confined, targetReachable: r.targetReachable, results: r.results }, null, 2) + "\n"); return r.pass ? 0 : 1; }
    for (const x of r.results) i.out(`${x.pass ? "PASS" : "FAIL"}  ${x.name.padEnd(32)} ${x.url}\n      ${x.got}\n`);
    const esc = r.results.filter((x) => x.expect !== "ok");
    i.out(`\n${r.confined ? "Confinement holds" : "CONFINEMENT FAILED: do not use the toolbox on this machine"} (${esc.filter((x) => x.pass).length}/${esc.length} escape probes blocked).\n`);
    if (r.targetReachable === false) i.out("The declared target did not answer through the proxy: is it running? (not a confinement problem)\n");
    i.out(`Proxy events in ${auditPath}.\n`);
    return r.pass ? 0 : 1;
  }

  if (!(TOOL_NAMES as readonly string[]).includes(sub)) {
    i.err(`crenel tools: unknown subcommand "${sub}" (status, build, install, selftest, cleanup, ${TOOL_NAMES.join(", ")})\n`);
    return 2;
  }
  const projectDir = isAbsolute(i.config.projectDir) ? i.config.projectDir : resolve(configDir, i.config.projectDir);
  const t0 = Date.now();
  const r = await runTool({ tool: sub as ToolName, config: i.config, projectDir, scope, checks: REGISTRY, onEvent, wslExec: i.wslExec });
  write({
    at: new Date().toISOString(), kind: "toolbox.run", tool: r.tool, backend: r.backend, ran: r.ran, reason: r.reason, exit: r.exit, timedOut: r.timedOut,
    network: r.network, proxy: r.proxy, ms: Date.now() - t0, project: i.config.project,
    findings: r.findings.map((f) => ({ id: f.id, severity: f.severity, state: f.state })),
  });
  if (i.json) {
    const { raw, ...rest } = r;
    i.out(JSON.stringify({ ...rest, raw: raw ? { trust: raw.trust, source: raw.source, bytes: raw.bytes, sha256: raw.sha256 } : undefined }, null, 2) + "\n");
    return r.ran ? 0 : 2;
  }
  if (!r.ran) { i.err(`${r.reason}\n`); return 2; }
  const proven = r.findings.filter((f) => f.state === "proven");
  i.out(`${r.tool} (${r.backend}): exit ${r.exit}${r.timedOut ? " (timed out)" : ""}, network ${r.network}` +
    (r.proxy ? `, ${r.proxy.requests} request(s) through the proxy, ${r.proxy.refused} refused` : "") + `, ${Math.round((Date.now() - t0) / 1000)} s\n`);
  i.out(`${r.findings.length} lead(s), ${proven.length} proven by a Crenel validator.\n\n`);
  for (const f of r.findings) {
    i.out(`  [${f.state === "proven" ? "PROVEN" : "lead"}] ${f.severity.padEnd(8)} ${f.title}\n           ${f.location}\n`);
    if (f.state === "proven" && f.proof) i.out(`           proof: ${f.proof.method}: ${f.proof.replay}\n`);
  }
  if (r.tool === "katana") {
    i.out(`\n${r.routes.length} route(s) discovered on declared hosts.\n`);
    if (r.suggestions.length) {
      i.out("Suggested for options.authz-matrix.resources (add B's ids in accounts.b.owns, the validator decides):\n");
      for (const s of r.suggestions) i.out(`  - { name: ${s.name}, path: ${s.path}, methods: [GET] }   # e.g. ${s.examples[0]}\n`);
    }
  }
  if (r.stderrTail && r.exit !== 0) i.err(`\n${r.tool} stderr (tail):\n${r.stderrTail}\n`);
  i.out(`\nEvery proxied request and refusal is in ${auditPath}.\n`);
  return 0;
}
