// Claims and validators (P0 #2 of the research backlog).
//
// The agent, a model or the harness itself NEVER writes `proven`. It submits a
// Claim: "this class of flaw, on this target". A Validator registered for that
// class replays the evidence itself, with deterministic code, using only the
// config and the disk (never a token, URL or body supplied by the claim), and
// decides. A claim whose class has no validator stays `unproven`, labelled as
// such. A script's printed "[VULN]" or a model's confidence never counts.
//
// Every verdict that proves something carries Evidence: the raw request (secrets
// redacted), the raw status line and a capped body excerpt, and a sha256 of the
// full body, so the proof can be replayed and compared later.

import { createHash, randomBytes } from "node:crypto";
import { safeFetch, type SafeResponse } from "../core/net.js";
import type { Scope } from "../core/scope.js";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { scanBaas, readOneRow, type SupabasePair } from "../checks/baas-exposure.js";
import { sameIdentity } from "../checks/authz-matrix.js";

export type ClaimClass = "authz.cross-tenant" | "baas.supabase-rls" | "header.missing" | "check.replay" | (string & {});

export interface Claim {
  id: string;
  class: ClaimClass;
  /** Who proposed it: a deterministic check, the agent loop, or a model. */
  source: "check" | "agent" | "llm";
  /** Class-specific fields. Validators read only what they need and re-derive the rest. */
  detail: Record<string, unknown>;
}

export interface Evidence {
  request: string;
  response: string;
  sha256?: string;
  /** The negative control and what it returned. */
  control?: string;
}

export interface ClaimVerdict {
  claimId: string;
  state: "proven" | "unproven";
  validator: string | null;
  reason: string;
  evidence?: Evidence;
}

export interface ValidatorEnv {
  /** The run's scope: same allowlist, kill switch and observer as the tools. */
  scope: Scope;
  projectDir: string;
  options: Record<string, unknown>;
  stagingUrl?: string;
  /** Checks available for deterministic replay (the registry, or a test double). */
  checks: Check[];
}

export interface Validator {
  class: ClaimClass;
  name: string;
  validate(claim: Claim, env: ValidatorEnv): Promise<ClaimVerdict>;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const excerpt = (s: string, n = 400) => (s.length > n ? s.slice(0, n) + `… (${s.length} chars)` : s);
const DENY = new Set([401, 403, 404]);
const ok2xx = (s: number) => s >= 200 && s < 300;

/* ---------------- authz.cross-tenant ---------------- */

export interface AuthzAccount { token?: string; owns?: Record<string, string[]>; marker?: string }
export interface AuthzResource { name: string; path: string; methods?: string[]; public?: boolean; ownerField?: string }
export interface AuthzOptions {
  resources?: AuthzResource[];
  /** a: test account of another tenant than b; c: optional third tenant; b: the owner. */
  accounts?: { a?: AuthzAccount; b?: AuthzAccount; c?: AuthzAccount };
  /** Trust boundaries: route templates public by design, never reported. */
  publicByDesign?: string[];
}

export interface Observed { status: number; body: string }

/**
 * The oracle, pure so it is tested without a network. Inspired by Autorize and
 * XBOW's IDOR method: a 200 is not proof. The object returned to the attacker
 * must be the owner's (the owner marker in the body, or a body that matches the
 * owner's own response), and a negative control (same route, an id that does
 * not exist) must not return the same thing, or the route just answers
 * everything with a generic page.
 */
export function authzOracle(input: {
  attacker: Observed;
  owner?: Observed;
  control: Observed;
  /** Strings that only appear in the owner's object: B's marker, the owner id field value. */
  ownerMarkers: string[];
}): { verdict: "leak" | "lead" | "denied"; reason: string } {
  const { attacker, owner, control } = input;
  if (DENY.has(attacker.status) || !ok2xx(attacker.status)) return { verdict: "denied", reason: `HTTP ${attacker.status}` };
  const sameAsControl = ok2xx(control.status) && (control.body === attacker.body || sha(control.body) === sha(attacker.body));
  if (sameAsControl) return { verdict: "lead", reason: "the route answers a non-existent id the same way: generic response, not a leak" };
  const marker = input.ownerMarkers.find((m) => m && attacker.body.includes(m));
  if (marker) return { verdict: "leak", reason: `HTTP ${attacker.status} and the body carries the owner's marker` };
  if (owner && ok2xx(owner.status)) {
    if (sha(owner.body) === sha(attacker.body)) return { verdict: "leak", reason: `HTTP ${attacker.status}, body identical to the owner's own response` };
    const a = attacker.body.length, o = owner.body.length;
    if (o > 0 && Math.abs(a - o) / o <= 0.05 && normalize(owner.body) === normalize(attacker.body)) {
      return { verdict: "leak", reason: `HTTP ${attacker.status}, body matches the owner's response (volatile fields aside)` };
    }
    return { verdict: "lead", reason: `HTTP ${attacker.status} but the body differs from the owner's: review by hand` };
  }
  return { verdict: "lead", reason: `HTTP ${attacker.status} with no owner marker to compare: declare accounts.b.marker or accounts.b.token` };
}

// Drop values that change between two reads of the same object (timestamps,
// request ids, csrf tokens), so the comparison is on the object itself.
function normalize(body: string): string {
  return body
    .replace(/"(updated_?at|created_?at|timestamp|now|request_?id|csrf[_-]?token|etag|nonce)"\s*:\s*("[^"]*"|\d+)/gi, '"$1":0')
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?/g, "T");
}

async function get(url: string, scope: Scope, token?: string): Promise<SafeResponse> {
  return safeFetch(url, scope, { method: "GET", headers: token ? { authorization: `Bearer ${token}` } : {} });
}

export function authzUrl(base: string, r: AuthzResource, id: string): string {
  return base.replace(/\/$/, "") + r.path.replace(":id", encodeURIComponent(id));
}

function isPublicByDesign(opts: AuthzOptions, r: AuthzResource): boolean {
  return !!r.public || (opts.publicByDesign ?? []).some((p) => p === r.path || p === r.name);
}

const authzValidator: Validator = {
  class: "authz.cross-tenant",
  name: "authz-replay (owner baseline, attacker, negative control)",
  async validate(claim, env) {
    const opts = (env.options["authz-matrix"] ?? {}) as AuthzOptions;
    const r = (opts.resources ?? []).find((x) => x.name === claim.detail.resource);
    const id = String(claim.detail.id ?? "");
    const actor = claim.detail.actor === "anon" ? "anon" : claim.detail.actor === "c" ? "c" : "a";
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    if (!r || !env.stagingUrl) return no("resource or stagingUrl not declared in the config");
    // The id must be one the config says belongs to B: a claim cannot point the
    // validator at an arbitrary object.
    if (!(opts.accounts?.b?.owns?.[r.name] ?? []).includes(id)) return no(`id ${id} is not declared as owned by account B`);
    if (isPublicByDesign(opts, r)) return no(`${r.path} is public by design (trust boundary in the config)`);
    if (!env.scope.allowActiveTesting) return no("allowActiveTesting is off");
    const same = sameIdentity(opts.accounts?.a?.token, opts.accounts?.b?.token);
    if (same) return no(`accounts A and B ${same}: not two tenants`);
    const tokenA = actor === "anon" ? undefined : opts.accounts?.[actor]?.token;
    if (actor !== "anon" && !tokenA) return no(`no token for account ${actor.toUpperCase()}`);
    const url = authzUrl(env.stagingUrl, r, id);
    const controlUrl = authzUrl(env.stagingUrl, r, `crenel-nonexistent-${randomBytes(6).toString("hex")}`);
    const tokenB = opts.accounts?.b?.token;
    const owner = tokenB ? await get(url, env.scope, tokenB) : undefined;
    const attacker = await get(url, env.scope, tokenA);
    const control = await get(controlUrl, env.scope, tokenA);
    const markers = [opts.accounts?.b?.marker ?? ""].filter(Boolean);
    const o = authzOracle({ attacker, owner, control, ownerMarkers: markers });
    const who = actor === "anon" ? "no token at all" : `account ${actor.toUpperCase()}'s token`;
    const evidence: Evidence = {
      request: `GET ${url}\nauthorization: ${actor === "anon" ? "(none)" : `Bearer <${actor.toUpperCase()}_TOKEN>`}`,
      response: `HTTP ${attacker.status}\n${excerpt(attacker.body)}`,
      sha256: sha(attacker.body),
      control: `GET ${controlUrl} -> HTTP ${control.status}${owner ? `; owner (B) -> HTTP ${owner.status}, sha256 ${sha(owner.body).slice(0, 12)}` : ""}`,
    };
    if (o.verdict === "leak") return { claimId: claim.id, state: "proven", validator: this.name, reason: `${who} read B's ${r.name}: ${o.reason}`, evidence };
    return { ...no(o.reason), evidence: o.verdict === "lead" ? evidence : undefined };
  },
};

/* ---------------- baas.supabase-rls ---------------- */

const baasValidator: Validator = {
  class: "baas.supabase-rls",
  name: "supabase-one-row-read",
  async validate(claim, env) {
    const url = String(claim.detail.url ?? "");
    const table = String(claim.detail.table ?? "");
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    if (!/^[A-Za-z0-9_]+$/.test(table)) return no("invalid table name");
    // The key is re-read from the bundle on disk, never taken from the claim.
    const pair = scanBaas(env.projectDir).find((h): h is SupabasePair => h.kind === "supabase" && h.url === url);
    if (!pair) return no(`no Supabase public key for ${url} in the bundle`);
    if (!env.scope.allowActiveTesting) return no("allowActiveTesting is off");
    const r = await readOneRow(pair, table, [], env.scope);
    if (!r.readable) return no(`HTTP ${r.status}, no row returned with the public key`);
    return {
      claimId: claim.id, state: "proven", validator: this.name,
      reason: `${table} returned a row with only the public key`,
      evidence: { request: `GET ${url}/rest/v1/${table}?select=*&limit=1\napikey: <ANON_KEY>`, response: `HTTP ${r.status}, 1 row, ${r.columns} column(s) (content not kept)` },
    };
  },
};

/* ---------------- header.missing ---------------- */

const headerValidator: Validator = {
  class: "header.missing",
  name: "header-reread",
  async validate(claim, env) {
    const url = String(claim.detail.url ?? env.stagingUrl ?? "");
    const header = String(claim.detail.header ?? "").toLowerCase();
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    if (!url || !/^[a-z0-9-]+$/.test(header)) return no("no URL or header to check");
    if (url !== env.stagingUrl && !url.startsWith(String(env.stagingUrl ?? "\0"))) return no("only the declared stagingUrl is re-read");
    const res = await safeFetch(url, env.scope);
    const head = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n");
    if (res.headers.get(header)) return no(`${header} is present (HTTP ${res.status})`);
    return {
      claimId: claim.id, state: "proven", validator: this.name, reason: `${header} absent from the live response`,
      evidence: { request: `GET ${res.url}`, response: `HTTP ${res.status}\n${excerpt(head, 800)}`, sha256: sha(head) },
    };
  },
};

/* ---------------- check.replay ---------------- */

// A deterministic check that already proved something offline (a regex on a
// key shape, a denylisted lockfile entry): the validator runs the check again
// itself and accepts only if the same finding comes back proven. It never takes
// the earlier output's word for it.
const replayValidator: Validator = {
  class: "check.replay",
  name: "deterministic-check-replay",
  async validate(claim, env) {
    const checkName = String(claim.detail.check ?? "");
    const findingId = String(claim.detail.findingId ?? "");
    const check = env.checks.find((c) => c.name === checkName);
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    if (!check) return no(`no check named ${checkName}`);
    // The check runs again with the same inputs, staging URL included: a check
    // that proved something on the live site (a served .env, an open redirect)
    // must be able to prove it again, through the same scoped client.
    const offline: CheckContext = { scope: env.scope, projectDir: env.projectDir, stagingUrl: env.stagingUrl, options: env.options, log: () => {} };
    const again = (await check.run(offline)).find((f) => f.id === findingId);
    if (!again) return no("the finding did not reproduce");
    if (again.state !== "proven" || !again.proof) return no(`${checkName} reports it as a lead, without a replayable proof`);
    return {
      claimId: claim.id, state: "proven", validator: `${this.name}:${checkName}`, reason: again.proof.method,
      evidence: { request: again.proof.replay, response: again.proof.evidence ?? "(match)" },
    };
  },
};

/* ---------------- check.replay-file ---------------- */

// A lead from an external tool that points at a file (trufflehog: "a secret in
// dist/app.js"). The tool's word is not taken: an offline deterministic check
// runs again on the disk, and the claim is proven only if that check itself
// proves a finding in the same file. Only offline checks are accepted here.
const FILE_REPLAY_CHECKS = new Set(["exposed-secrets", "committed-credentials", "committed-env", "public-env"]);
const fileReplayValidator: Validator = {
  class: "check.replay-file",
  name: "deterministic-check-replay-on-file",
  async validate(claim, env) {
    const checkName = String(claim.detail.check ?? "");
    const file = String(claim.detail.file ?? "").replace(/\\/g, "/");
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    if (!FILE_REPLAY_CHECKS.has(checkName)) return no(`${checkName} is not an offline check that can replay a file`);
    if (!file || file.includes("..")) return no("no file to replay");
    const check = env.checks.find((c) => c.name === checkName);
    if (!check) return no(`no check named ${checkName}`);
    const offline: CheckContext = { scope: env.scope, projectDir: env.projectDir, options: env.options, log: () => {} };
    const line = Number(claim.detail.line ?? 0) || 0;
    // Same file, and the same line when the check reports one: another secret
    // elsewhere in the file does not confirm this lead.
    const hits = (await check.run(offline)).filter((f) => {
      if (f.state !== "proven" || !f.proof) return false;
      const m = f.location.replace(/\\/g, "/").match(/^(.*?)(?::(\d+))?$/);
      if (!m || m[1] !== file) return false;
      return m[2] === undefined || !line || Number(m[2]) === line;
    });
    if (hits.length === 0) return no(`${checkName} proves nothing at ${file}${line ? `:${line}` : ""}: the tool's lead is not confirmed`);
    const f = hits[0]!;
    return {
      claimId: claim.id, state: "proven", validator: `${this.name}:${checkName}`,
      reason: `${checkName} replayed on the disk: ${f.title} at ${f.location}`,
      evidence: { request: f.proof!.replay, response: f.proof!.evidence ?? "(match)" },
    };
  },
};

/* ---------------- http.plain-served ---------------- */

// A declared host said to answer over plain http:// (an httpx lead): one GET
// over http://, redirect not followed, through the scoped client. Proven only
// on a 200; a redirect, an error or a host off the scope stays a lead.
const plainHttpValidator: Validator = {
  class: "http.plain-served",
  name: "plain-http-reread",
  async validate(claim, env) {
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    let u: URL;
    try { u = new URL(String(claim.detail.url ?? "")); } catch { return no("no URL to re-read"); }
    if (u.protocol !== "http:") return no("only an http:// URL is re-read");
    if (!env.scope.isHostAllowed(u.toString())) return no(`${u.hostname} is not a declared host`);
    const url = `http://${u.host}/`;
    const res = await safeFetch(url, env.scope, { followRedirects: false });
    if (res.status !== 200) return no(`http:// answers ${res.status}${res.headers.get("location") ? ` -> ${res.headers.get("location")}` : ""}`);
    const head = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n");
    return {
      claimId: claim.id, state: "proven", validator: this.name, reason: "200 over plain http://, no redirect",
      evidence: { request: `GET ${url} (redirect not followed)`, response: `HTTP ${res.status}\n${excerpt(head, 600)}`, sha256: sha(head) },
    };
  },
};

export const VALIDATORS: Validator[] = [authzValidator, baasValidator, headerValidator, replayValidator, fileReplayValidator, plainHttpValidator];

/** Route a claim to its validator. No validator: unproven, labelled. A validator that throws: unproven. */
export async function validateClaim(claim: Claim, env: ValidatorEnv, validators = VALIDATORS): Promise<ClaimVerdict> {
  const v = validators.find((x) => x.class === claim.class);
  if (!v) return { claimId: claim.id, state: "unproven", validator: null, reason: `no validator for class ${claim.class}` };
  try {
    return await v.validate(claim, env);
  } catch (err) {
    return { claimId: claim.id, state: "unproven", validator: v.name, reason: `replay failed: ${(err as Error).message}` };
  }
}

/** The claim a check's finding turns into. Network-proven classes get their own replay. */
export function claimFor(f: Finding): Claim {
  const base = { id: `claim:${f.id}`, source: "check" as const };
  if (f.check === "baas-exposure" && f.id.startsWith("baas-exposure:supabase-rls:")) {
    const m = f.location.match(/^(.*)\/rest\/v1\/([A-Za-z0-9_]+)$/);
    if (m) return { ...base, class: "baas.supabase-rls", detail: { url: m[1], table: m[2] } };
  }
  if (f.check === "headers" && f.state === "proven") {
    const m = f.id.match(/^headers:(csp|hsts|xcto|xfo|refpol):(.*)$/);
    const header = { csp: "content-security-policy", hsts: "strict-transport-security", xcto: "x-content-type-options", xfo: "x-frame-options", refpol: "referrer-policy" }[m?.[1] ?? ""];
    if (m && header) return { ...base, class: "header.missing", detail: { url: m[2], header } };
  }
  return { ...base, class: "check.replay", detail: { check: f.check, findingId: f.id } };
}
