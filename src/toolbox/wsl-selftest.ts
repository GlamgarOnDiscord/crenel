// `crenel tools selftest` on the WSL backend.
//
// Same probes as the Docker escape test, with curl from the distro. The
// difference is the expected result of the direct probes: WSL gives the tools
// the host's network, so a direct request usually WORKS. That is reported as
// such ("open"), not hidden: it is the guarantee the WSL backend does not have.
// What must hold: the proxy refuses undeclared hosts and the metadata address,
// and lets the declared target through.

import { startEgressProxy, type EgressProxy, type ProxyEvent } from "../core/egress-proxy.js";
import type { Scope } from "../core/scope.js";
import { probes, type Probe } from "./selftest.js";
import { decode, realWsl, toolEnv, type WslExec } from "./wsl.js";

export interface WslProbeResult extends Probe {
  /** HTTP status curl saw, 0 when nothing answered. */
  code: number;
  /** For a proxy probe: as expected. For a direct probe: always true (informative). */
  pass: boolean;
  /** Direct probes: "open" when an answer came back without the proxy. */
  direct?: "open" | "closed";
}

export interface WslSelfTestResult {
  /** The proxy refused what it must refuse. */
  proxyHolds: boolean;
  /** Every direct probe got an answer: no confinement on this machine (expected under WSL). */
  directOpen: boolean;
  targetReachable: boolean | null;
  pass: boolean;
  results: WslProbeResult[];
  events: ProxyEvent[];
  stderr: string;
}

const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

/** One line per probe: "<index> <http code>". No double quotes (Windows command-line quoting). */
export function wslProbeScript(ps: Probe[]): string {
  return ps.map((p, i) => {
    const via = p.via === "direct" ? "--noproxy '*'" : "";
    return `c=$(curl -s -o /dev/null -m 5 -w %{http_code} ${via} ${q(p.url)} 2>/dev/null); echo ${i} $c`;
  }).join("; ");
}

export function judgeWsl(p: Probe, code: number): WslProbeResult {
  if (p.via === "direct") return { ...p, code, pass: true, direct: code > 0 ? "open" : "closed" };
  const pass = p.expect === "refused" ? [403, 405, 407].includes(code) : code >= 200 && code < 400;
  return { ...p, code, pass };
}

export async function wslSelfTest(o: { scope: Scope; distro: string; endpoint: { listen: string; dial: string }; target?: string; exec?: WslExec }): Promise<WslSelfTestResult> {
  const exec = o.exec ?? realWsl;
  const ps = probes(o.target);
  const events: ProxyEvent[] = [];
  let proxy: EgressProxy | undefined;
  try {
    proxy = await startEgressProxy({ scope: o.scope, host: o.endpoint.listen, tool: "selftest", onEvent: (e) => events.push(e), maxRequests: 50 });
    const url = `http://crenel:${proxy.token}@${o.endpoint.dial}:${proxy.port}`;
    const r = await exec(["-d", o.distro, "--cd", "~", "--exec", "sh", "-c", wslProbeScript(ps)], { timeoutMs: 120_000, env: { ...process.env, ...toolEnv(url) } });
    const codes = new Map<number, number>();
    for (const l of decode(r.stdout).split("\n")) {
      const m = l.trim().match(/^(\d+)\s*(\d*)$/);
      if (m) codes.set(Number(m[1]), Number(m[2] || 0));
    }
    const results = ps.map((p, i) => judgeWsl(p, codes.get(i) ?? 0));
    const proxied = results.filter((x) => x.via === "proxy" && x.expect === "refused");
    const proxyHolds = codes.size === ps.length && proxied.every((x) => x.pass);
    const t = results.find((x) => x.expect === "ok");
    const targetReachable = t ? t.pass : null;
    const direct = results.filter((x) => x.via === "direct");
    return { proxyHolds, directOpen: direct.length > 0 && direct.some((x) => x.direct === "open"), targetReachable, pass: proxyHolds && targetReachable !== false, results, events, stderr: decode(r.stderr) };
  } finally {
    await proxy?.close();
  }
}
