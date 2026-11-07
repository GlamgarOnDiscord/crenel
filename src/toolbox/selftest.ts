// Escape test of the confinement, run for real in the toolbox container.
//
// The container gets the same network as a tool (internal network + relay +
// proxy) and busybox wget tries to get out, with and without the proxy:
//
//   direct  http://example.com/            must fail (no DNS, no route)
//   direct  http://192.0.2.1/              must fail (TEST-NET-1 literal: proves there is no route, not just no DNS)
//   direct  http://169.254.169.254/        must fail (cloud metadata)
//   proxy   http://example.com/            must be refused by the proxy (403, host not declared)
//   proxy   http://169.254.169.254/        must be refused by the proxy (403)
//   proxy   <target>                       must go through (only when a declared target is given)
//
// 192.0.2.0/24 is reserved for documentation (RFC 5737): nobody answers there,
// so even a failed confinement would not reach a third party with it.

import { runConfined, type ConfinedResult } from "./docker.js";
import type { ProxyEvent } from "../core/egress-proxy.js";
import type { Scope } from "../core/scope.js";

export interface Probe { name: string; via: "direct" | "proxy"; url: string; expect: "fail" | "refused" | "ok" }
export interface ProbeResult extends Probe { pass: boolean; got: string }

export function probes(target?: string): Probe[] {
  return [
    { name: "direct, undeclared host", via: "direct", url: "http://example.com/", expect: "fail" },
    { name: "direct, IP literal (no route)", via: "direct", url: "http://192.0.2.1/", expect: "fail" },
    { name: "direct, cloud metadata", via: "direct", url: "http://169.254.169.254/latest/meta-data/", expect: "fail" },
    { name: "proxy, undeclared host", via: "proxy", url: "http://example.com/", expect: "refused" },
    { name: "proxy, cloud metadata", via: "proxy", url: "http://169.254.169.254/latest/meta-data/", expect: "refused" },
    ...(target ? [{ name: "proxy, declared target", via: "proxy" as const, url: target, expect: "ok" as const }] : []),
  ];
}

// One shell line per probe; the output is "<index> <exit code> <first line of stderr/stdout>".
function script(ps: Probe[]): string {
  const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
  return ps.map((p, i) => {
    const env = p.via === "direct" ? "env -u http_proxy -u HTTP_PROXY -u https_proxy -u HTTPS_PROXY" : "env";
    return `out=$(${env} busybox wget -q -T 5 -O - -S ${q(p.url)} 2>&1 | head -c 400 | tr '\\n' ' '); echo "${i} $? $out"`;
  }).join("\n");
}

export function judge(p: Probe, line: string): ProbeResult {
  // A direct probe passes only if no HTTP answer came back at all: any status
  // line, even an error, means a packet left the container without the proxy.
  const failed = /can't connect|bad address|unreachable|timed out|Connection refused|error getting response|No route/i.test(line);
  const sawHttp = /HTTP\/1\.[01] \d{3}/.test(line);
  const refused = /HTTP\/1\.[01] 40[357]/.test(line);
  const ok = /HTTP\/1\.[01] [23]\d\d/.test(line);
  const pass = p.expect === "fail" ? failed && !sawHttp : p.expect === "refused" ? refused && !ok : ok;
  return { ...p, pass, got: line.slice(0, 200) };
}

export interface SelfTestResult {
  /** Every escape probe failed as it should: no way out but the proxy, and the proxy refuses. */
  confined: boolean;
  /** The declared target answered through the proxy (null when no target was given). */
  targetReachable: boolean | null;
  pass: boolean;
  results: ProbeResult[];
  run: ConfinedResult;
  events: ProxyEvent[];
}

/** Run the escape test. `scope` is the run's scope; `target` an optional declared URL that must work. */
export async function selfTest(scope: Scope, target?: string): Promise<SelfTestResult> {
  const ps = probes(target);
  const events: ProxyEvent[] = [];
  const run = await runConfined({
    tool: "selftest", scope, entrypoint: "/bin/sh", argv: ["-c", script(ps)],
    onEvent: (e) => events.push(e), limits: { timeoutMs: 120_000, memory: "128m", pids: 64 },
  });
  const lines = new Map<number, string>();
  for (const l of run.stdout.split("\n")) {
    const m = l.match(/^(\d+) (\d+) (.*)$/);
    if (m) lines.set(Number(m[1]), m[3]!);
  }
  const results = ps.map((p, i) => judge(p, lines.get(i) ?? "(no output)"));
  const confined = run.code === 0 && results.filter((r) => r.expect !== "ok").every((r) => r.pass);
  const t = results.find((r) => r.expect === "ok");
  const targetReachable = t ? t.pass : null;
  return { confined, targetReachable, pass: confined && targetReachable !== false, results, run, events };
}
