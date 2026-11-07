// Authorization gate in front of every tool call (P0 #3 of the research backlog).
//
// Two stages, and the order matters:
//
//   1. Deterministic, blocking, not negotiable: the tool must be known and
//      non-mutating, every planned request must use a safe method (GET, HEAD,
//      OPTIONS), an http(s) URL on a declared host, no private IP literal unless
//      the config allows it, no path that looks like a side effect (logout,
//      delete...), and an active probe needs allowActiveTesting in the config.
//      The run mode cannot loosen any of this: "bypass" removes the questions,
//      not the perimeter.
//   2. Optional judge (a model, or any function): it sees the user's request
//      and the proposed call, and can only HARDEN the verdict, deny or ask,
//      never allow what stage 1 refused. A judge that throws counts as "ask".
//
// The verdict is "allow" (run it), "ask" (pause and ask the user: Allow once /
// Always for this host / Deny) or "deny" (never sent). Hosts the user allowed
// "always" are remembered in `grants` (persisted in .crenel/grants.json).

import { isPrivateIp } from "../core/net.js";
import type { Scope } from "../core/scope.js";

export type Mode = "ask" | "readonly" | "bypass";

export interface ToolSpec {
  name: string;
  /** Sends requests over the network (through the scoped client). */
  network: boolean;
  /** Sends crafted requests (cross-tenant replays, BaaS reads): needs allowActiveTesting. */
  active: boolean;
  /** Changes state somewhere. Crenel ships no such tool; the gate refuses it anyway. */
  mutating: boolean;
}

export const TOOLS: Record<string, ToolSpec> = {
  "scan.secrets": { name: "scan.secrets", network: false, active: false, mutating: false },
  "scan.repo": { name: "scan.repo", network: false, active: false, mutating: false },
  "scan.deps": { name: "scan.deps", network: false, active: false, mutating: false },
  "scan.baas": { name: "scan.baas", network: true, active: true, mutating: false },
  "scan.web": { name: "scan.web", network: true, active: false, mutating: false },
  "authz.matrix": { name: "authz.matrix", network: true, active: true, mutating: false },
  "validate.claims": { name: "validate.claims", network: true, active: false, mutating: false },
  "tests.generate": { name: "tests.generate", network: false, active: false, mutating: false },
  "llm.advise": { name: "llm.advise", network: false, active: false, mutating: false },
};

export interface PlannedRequest {
  method: string;
  url: string;
}

export interface ToolCall {
  tool: string;
  requests?: PlannedRequest[];
}

export interface GateContext {
  scope: Scope;
  mode: Mode;
  /** Hosts the user allowed "always" (kept across restarts in .crenel/grants.json). */
  grants: ReadonlySet<string>;
  /** The user's own words for this run; a judge needs them (ScopeJudge). */
  userRequest: string;
}

export type Verdict = "allow" | "ask" | "deny";

export interface GateDecision {
  verdict: Verdict;
  reasons: string[];
  /** Which stage set the final verdict. */
  stage: "deterministic" | "judge";
  /** Hosts this call would reach. */
  hosts: string[];
  /** True when allowed with nobody asked (bypass mode or a standing grant): logged to the audit. */
  unattended: boolean;
}

export const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
// GET routes that commonly have side effects: never probed, even read-only.
const RISKY_PATH = /\/(logout|log-out|signout|sign-out|delete|destroy|remove|reset|unsubscribe|revoke|deactivate|cancel|purge|drop)(\/|$|\?)/i;

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Stage 1. Pure and synchronous, so it is easy to test exhaustively. */
export function gateDeterministic(call: ToolCall, ctx: GateContext): GateDecision {
  const deny = (reasons: string[], hosts: string[] = []): GateDecision => ({ verdict: "deny", reasons, stage: "deterministic", hosts, unattended: false });
  const spec = TOOLS[call.tool];
  if (!spec) return deny([`unknown tool "${call.tool}"`]);
  if (spec.mutating) return deny([`${call.tool} changes state; Crenel never runs mutating tools`]);
  const requests = call.requests ?? [];
  if (!spec.network) {
    if (requests.length) return deny([`${call.tool} is an offline tool and cannot send requests`]);
    return { verdict: "allow", reasons: ["offline tool"], stage: "deterministic", hosts: [], unattended: false };
  }
  if (requests.length === 0) return { verdict: "allow", reasons: ["no request planned"], stage: "deterministic", hosts: [], unattended: false };

  const reasons: string[] = [];
  const hosts = new Set<string>();
  for (const r of requests) {
    const method = r.method.toUpperCase();
    const host = hostOf(r.url);
    if (!host) { reasons.push(`invalid URL ${r.url}`); continue; }
    const proto = new URL(r.url).protocol;
    if (proto !== "http:" && proto !== "https:") reasons.push(`${proto} is not http(s)`);
    if (!SAFE_METHODS.has(method)) reasons.push(`${method} ${r.url}: only GET, HEAD and OPTIONS are ever sent`);
    if (!ctx.scope.isHostAllowed(r.url)) reasons.push(`${host} is not in allowedHosts`);
    const literal = host.replace(/^\[|\]$/g, "");
    if (/^[\d.]+$|:/.test(literal) && isPrivateIp(literal) && !ctx.scope.allowPrivate) reasons.push(`${host} is a private address and allowPrivate is off`);
    if (RISKY_PATH.test(new URL(r.url).pathname)) reasons.push(`${new URL(r.url).pathname} looks like a side effect, never probed`);
    hosts.add(host);
  }
  if (spec.active && !ctx.scope.allowActiveTesting) reasons.push(`${call.tool} sends crafted requests and allowActiveTesting is off in the config`);
  if (ctx.mode === "readonly") reasons.push(`mode "Lecture seule": no request leaves the machine`);
  if (reasons.length) return deny([...new Set(reasons)], [...hosts]);

  const hostList = [...hosts];
  if (ctx.mode === "bypass") {
    return { verdict: "allow", reasons: ["bypass mode: no question, perimeter still enforced"], stage: "deterministic", hosts: hostList, unattended: true };
  }
  if (hostList.every((h) => ctx.grants.has(h))) {
    return { verdict: "allow", reasons: ["host allowed for this session"], stage: "deterministic", hosts: hostList, unattended: true };
  }
  return { verdict: "ask", reasons: ["network requests need your approval in this mode"], stage: "deterministic", hosts: hostList, unattended: false };
}

/** A judge may say "pass" (keep stage 1), "ask" (escalate to the user) or "deny". */
export type Judge = (call: ToolCall, ctx: GateContext) => Promise<"pass" | "ask" | "deny">;

const RANK: Record<Verdict, number> = { allow: 0, ask: 1, deny: 2 };

/** Both stages. The judge only runs on what stage 1 did not deny, and can only harden. */
export async function authorize(call: ToolCall, ctx: GateContext, judge?: Judge): Promise<GateDecision> {
  const d = gateDeterministic(call, ctx);
  if (d.verdict === "deny" || !judge) return d;
  let j: "pass" | "ask" | "deny";
  try {
    j = await judge(call, ctx);
  } catch {
    j = "ask";
  }
  if (j === "pass") return d;
  const verdict: Verdict = j;
  if (RANK[verdict] <= RANK[d.verdict]) return d; // a judge can never loosen
  return { ...d, verdict, stage: "judge", reasons: [...d.reasons, `judge: ${j}`], unattended: false };
}
