// `crenel tools ...`: the optional toolbox from the command line.
//
//   crenel tools status                 Docker, image, relay mode, options.toolbox
//   crenel tools build                  build the image from toolbox/
//   crenel tools selftest               escape test of the confinement (real containers)
//   crenel tools nuclei|katana|trufflehog [--json]
//
// Every egress event of the proxy (sent or refused) is appended to the audit
// JSONL (.crenel/audit.jsonl next to the config, or --audit <file>).

import { appendFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Config } from "../core/config.js";
import { Scope } from "../core/scope.js";
import { REGISTRY } from "../core/registry.js";
import type { ProxyEvent } from "../core/egress-proxy.js";
import { buildImage, cleanupLeftovers, dockerStatus, relayMode } from "./docker.js";
import { runTool, toolboxOptions, TOOL_NAMES, type ToolName } from "./run.js";
import { selfTest } from "./selftest.js";

export interface ToolsCliInput {
  sub: string;
  config: Config;
  configPath: string;
  json: boolean;
  audit?: string;
  out: (s: string) => void;
  err: (s: string) => void;
}

/** The toolbox/ directory shipped next to dist/ (or src/ in development). */
export function toolboxDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const c of [resolve(here, "../toolbox"), resolve(here, "../../toolbox")]) if (existsSync(join(c, "Dockerfile"))) return c;
  return resolve(here, "../toolbox");
}

function auditWriter(path: string): (e: Record<string, unknown>) => void {
  mkdirSync(dirname(path), { recursive: true });
  return (e) => appendFileSync(path, JSON.stringify(e) + "\n");
}

export async function toolsCommand(i: ToolsCliInput): Promise<number> {
  const configDir = dirname(resolve(i.configPath));
  const auditPath = i.audit ?? join(configDir, ".crenel", "audit.jsonl");
  const sub = i.sub;

  if (sub === "status") {
    const o = toolboxOptions(i.config);
    const st = await dockerStatus(o.image);
    const info = { ...st, relay: relayMode(), enabledInAgentRuns: o.enabled, options: o };
    if (i.json) { i.out(JSON.stringify(info, null, 2) + "\n"); return 0; }
    i.out([
      `docker   ${st.available ? `yes (${st.version})` : "no"}`,
      `image    ${st.image} ${st.imagePresent ? "(built)" : "(not built)"}`,
      `relay    ${info.relay === "unix" ? "Unix socket, no container has a route out" : "TCP via host.docker.internal (Docker Desktop)"}`,
      `agent    ${o.enabled ? "tools included in full scans" : "off in agent runs (options.toolbox.enabled: false)"}`,
      ...(st.reason ? [`note     ${st.reason}`] : []),
      "",
    ].join("\n"));
    return st.available && st.imagePresent ? 0 : 1;
  }

  if (sub === "build") {
    const o = toolboxOptions(i.config);
    const dir = toolboxDir();
    i.out(`Building ${o.image} from ${dir} (pinned inputs, a few minutes)...\n`);
    const r = await buildImage(dir, o.image);
    if (r.code !== 0) { i.err(r.stderr.slice(-2000) + "\n"); return 1; }
    i.out(`Built ${o.image}.\n`);
    return 0;
  }

  if (sub === "cleanup") {
    await cleanupLeftovers();
    i.out("Removed leftover toolbox containers and networks.\n");
    return 0;
  }

  const write = auditWriter(auditPath);
  const scope = new Scope({
    allowedHosts: i.config.scope.allowedHosts, allowActiveTesting: i.config.scope.allowActiveTesting,
    allowPrivate: i.config.scope.allowPrivate, stagingUrl: i.config.scope.stagingUrl,
  });
  const onEvent = (e: ProxyEvent) => write({ ...e });

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
    i.err(`crenel tools: unknown subcommand "${sub}" (status, build, selftest, cleanup, ${TOOL_NAMES.join(", ")})\n`);
    return 2;
  }
  const projectDir = isAbsolute(i.config.projectDir) ? i.config.projectDir : resolve(configDir, i.config.projectDir);
  const t0 = Date.now();
  const r = await runTool({ tool: sub as ToolName, config: i.config, projectDir, scope, checks: REGISTRY, onEvent });
  write({
    at: new Date().toISOString(), kind: "toolbox.run", tool: r.tool, ran: r.ran, reason: r.reason, exit: r.exit, timedOut: r.timedOut,
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
  i.out(`${r.tool}: exit ${r.exit}${r.timedOut ? " (timed out)" : ""}, network ${r.network}` +
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
