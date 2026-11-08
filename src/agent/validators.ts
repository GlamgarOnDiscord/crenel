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
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { readOnlyPost, safeFetch, type SafeResponse } from "../core/net.js";
import type { Scope } from "../core/scope.js";
import type { Check, CheckContext, Finding } from "../core/types.js";
import { scanBaas, readOneRow, type SupabasePair } from "../checks/baas-exposure.js";
import { sameIdentity } from "../checks/authz-matrix.js";
import { isPlaceholder, PATTERNS } from "../checks/exposed-secrets.js";
import { checkLiveness, verifierHost } from "../checks/key-liveness.js";
import { xssOracle, sqliOracle, templateOracle, nonce } from "./inject.js";
import { startCallback, ssrfOracle } from "./ssrf.js";
import { proveDomXss, domXssPayload } from "./domxss.js";
import type { Severity } from "../core/types.js";

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
  /** The highest severity this proof supports (generic validators): a model's severity is capped to it. */
  ceiling?: Severity;
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

/* ---------------- generic validators (free exploration) ----------------
 *
 * A model exploring freely finds things no check's schema describes (a route
 * shape nobody declared, a debug endpoint with a custom name). Its claims are
 * proven by these four validators, which do not depend on any check: they
 * replay requests and read files themselves, with the config's accounts and
 * the disk, and each one has a negative control. What they prove is stated
 * exactly (who obtains what, and what the control obtained), and the severity
 * a model proposes is capped by what the proof shows. A claim none of them can
 * prove stays an unproven lead, kept with the model's reasoning.
 */

export type Actor = "a" | "b" | "c" | "anon";
export const ACTORS: readonly Actor[] = ["a", "b", "c", "anon"];

/** A request as a model describes it. Credentials are never in it: `as` names a configured account. */
export interface ExploreRequest {
  method?: string;
  /** Absolute URL, or a path resolved against the stagingUrl. */
  url: string;
  as?: Actor;
  headers?: Record<string, string>;
  body?: string;
}

/** Absolute http(s) URL for `url`, a path being resolved against `base`; null when it is neither. */
export function resolveExploreUrl(url: string, base?: string): string | null {
  try {
    const u = /^[a-z][a-z0-9+.-]*:/i.test(url) ? new URL(url) : base ? new URL(url, base.endsWith("/") ? base : base + "/") : null;
    if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return null;
    return u.toString();
  } catch {
    return null;
  }
}

// Headers a model may not set: credentials come from the config (`as`), framing is the client's.
const BLOCKED_HEADERS = /^(authorization|cookie|host|content-length|transfer-encoding|connection|proxy-.*|cf-access-.*|x-forwarded-.*|forwarded)$/i;

/** The model's headers, minus credentials and framing, at most 10, no CR/LF. */
export function cleanHeaders(h: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h ?? {}).slice(0, 10)) {
    if (!/^[A-Za-z0-9-]{1,64}$/.test(k) || BLOCKED_HEADERS.test(k) || typeof v !== "string" || /[\r\n]/.test(v) || v.length > 500) continue;
    out[k.toLowerCase()] = v;
  }
  return out;
}

/** Bearer token of a configured account, from options.authz-matrix.accounts (never from a model). */
export function actorToken(options: Record<string, unknown>, actor: Actor | undefined): string | undefined {
  if (!actor || actor === "anon") return undefined;
  return ((options["authz-matrix"] ?? {}) as AuthzOptions).accounts?.[actor]?.token || undefined;
}

export function actorMarker(options: Record<string, unknown>, actor: Actor): string | undefined {
  if (actor === "anon") return undefined;
  return ((options["authz-matrix"] ?? {}) as AuthzOptions).accounts?.[actor]?.marker || undefined;
}

/** Send a model-described request as `actor`, through the scoped client. */
export async function sendAs(req: ExploreRequest, actor: Actor | undefined, env: Pick<ValidatorEnv, "scope" | "options" | "stagingUrl">, urlOverride?: string): Promise<SafeResponse> {
  const url = urlOverride ?? resolveExploreUrl(req.url, env.stagingUrl);
  if (!url) throw new Error(`not an http(s) URL: ${String(req.url).slice(0, 120)}`);
  const token = actorToken(env.options, actor);
  if (actor && actor !== "anon" && !token) throw new Error(`no token configured for account ${actor.toUpperCase()}`);
  const headers = { ...cleanHeaders(req.headers), ...(token ? { authorization: `Bearer ${token}` } : {}) };
  const method = (req.method ?? "GET").toUpperCase();
  return safeFetch(url, env.scope, { method, headers, body: req.body, maxBytes: 512 * 1024 });
}

const isReadRequest = (r: ExploreRequest, url: string) => {
  const m = (r.method ?? "GET").toUpperCase();
  return m === "GET" || m === "HEAD" || (m === "POST" && readOnlyPost(url, r.body) !== null);
};

/** The same URL with its object id (or, without one, its last path segment) replaced by one that cannot exist. */
export function controlUrl(url: string, id?: string): string {
  const fake = `crenel-nonexistent-${randomBytes(6).toString("hex")}`;
  const u = new URL(url);
  if (id && id.length >= 3) {
    const enc = encodeURIComponent(id);
    if (u.pathname.includes(enc) || u.pathname.includes(id)) { u.pathname = u.pathname.split(enc).join(fake).split(id).join(fake); return u.toString(); }
    let hit = false;
    for (const [k, v] of [...u.searchParams]) if (v === id) { u.searchParams.set(k, fake); hit = true; }
    if (hit) return u.toString();
  }
  const segs = u.pathname.split("/");
  const last = segs.length - 1 - [...segs].reverse().findIndex((s) => s !== "");
  if (last >= 1 && last < segs.length && segs[last]) segs[last] = fake; else segs.push(fake);
  u.pathname = segs.join("/");
  return u.toString();
}

const reqLine = (method: string, url: string, actor?: Actor) => `${method} ${url}\nauthorization: ${!actor || actor === "anon" ? "(none)" : `Bearer <${actor.toUpperCase()}_TOKEN>`}`;
const parseActor = (x: unknown): Actor | undefined => (ACTORS as readonly unknown[]).includes(x) ? (x as Actor) : undefined;

function parseRequest(x: unknown): ExploreRequest | null {
  if (!x || typeof x !== "object") return null;
  const r = x as Record<string, unknown>;
  if (typeof r.url !== "string" || !r.url) return null;
  return {
    url: r.url, method: typeof r.method === "string" ? r.method : undefined, as: parseActor(r.as),
    headers: r.headers && typeof r.headers === "object" ? (r.headers as Record<string, string>) : undefined,
    body: typeof r.body === "string" ? r.body : undefined,
  };
}

/* explore.replay: replay the request, check what the model said it returns,
 * then a negative control (same request without credentials or as another
 * actor) and a path control (an object that cannot exist) must NOT return it.
 * Proven only when the expected text is another account's marker: a replayed
 * fact with no such oracle stays a lead, with its evidence. */
const exploreReplayValidator: Validator = {
  class: "explore.replay",
  name: "request-replay (expected status and body, negative control)",
  async validate(claim, env) {
    const no = (reason: string, evidence?: Evidence): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason, evidence });
    const req = parseRequest(claim.detail.request);
    if (!req) return no("no request to replay");
    const url = resolveExploreUrl(req.url, env.stagingUrl);
    if (!url) return no("not an http(s) URL");
    if (!isReadRequest(req, url)) return no(`${(req.method ?? "GET").toUpperCase()} changes state: a write is never replayed (it would write again)`);
    const expect = (claim.detail.expect ?? {}) as { status?: unknown; bodyIncludes?: unknown };
    const includes = (Array.isArray(expect.bodyIncludes) ? expect.bodyIncludes : []).filter((s): s is string => typeof s === "string" && s.length > 0).slice(0, 5);
    if (!includes.some((s) => s.length >= 6)) return no("no expected body text of 6 characters or more: a status alone proves nothing");
    // Text the request itself carries would be an echo, not data the server holds.
    const sent = `${url} ${JSON.stringify(req.headers ?? {})} ${req.body ?? ""}`.toLowerCase();
    let sentDecoded = sent;
    try { sentDecoded = decodeURIComponent(sent); } catch { /* keep */ }
    const echoed = includes.find((s) => sent.includes(s.toLowerCase()) || sentDecoded.includes(s.toLowerCase()));
    if (echoed) return no(`"${echoed}" is in the request itself: an echo is not data`);
    const actor = req.as ?? "anon";
    const method = (req.method ?? "GET").toUpperCase();
    const res = await sendAs(req, actor, env, url);
    const status = typeof expect.status === "number" ? expect.status : undefined;
    const missing = includes.filter((s) => !res.body.includes(s));
    const evidence: Evidence = { request: reqLine(method, url, actor), response: `HTTP ${res.status}\n${excerpt(res.body)}`, sha256: sha(res.body) };
    if (status !== undefined && res.status !== status) return no(`HTTP ${res.status}, the claim expected ${status}`, evidence);
    if (!ok2xx(res.status)) return no(`HTTP ${res.status}: not a successful read`, evidence);
    if (missing.length) return no(`the body does not contain ${missing.map((s) => `"${s.slice(0, 40)}"`).join(", ")}`, evidence);
    // Negative controls: none of them may return any of the expected texts.
    const ctlActor = parseActor((claim.detail.control as { as?: unknown } | undefined)?.as);
    const controls: { label: string; actor: Actor; url: string }[] = [];
    if (actor !== "anon") controls.push({ label: "without credentials", actor: "anon", url });
    if (ctlActor && ctlActor !== actor && ctlActor !== "anon") controls.push({ label: `as account ${ctlActor.toUpperCase()}`, actor: ctlActor, url });
    controls.push({ label: "an object that cannot exist", actor, url: controlUrl(url, typeof claim.detail.id === "string" ? claim.detail.id : undefined) });
    const seen: string[] = [];
    for (const c of controls) {
      let r: SafeResponse;
      try { r = await sendAs(req, c.actor, env, c.url); } catch (err) { return no(`the control (${c.label}) could not be sent: ${(err as Error).message}`, evidence); }
      seen.push(`${c.label}: ${method} ${c.url} -> HTTP ${r.status}`);
      const leaked = includes.filter((s) => r.body.includes(s));
      if (ok2xx(r.status) && leaked.length) return no(`the control (${c.label}) also returns "${leaked[0]!.slice(0, 40)}": the text is not specific to this request`, { ...evidence, control: seen.join("; ") });
    }
    // A replay proves a fact (who obtains what). It is a flaw only when a deterministic oracle says so:
    // the marker of an account other than the requester in the body is that account's data.
    const foreign = (["a", "b", "c"] as const).filter((k) => k !== actor).map((k) => [k, actorMarker(env.options, k)] as const).find(([, m]) => m && includes.includes(m) && res.body.includes(m));
    const fact = `${actor === "anon" ? "without credentials" : `as account ${actor.toUpperCase()}`}, ${method} ${pathOnly(url)} returns ${includes.map((s) => `"${s.slice(0, 40)}"`).join(", ")}; ${controls.map((c) => c.label).join(" and ")} do not`;
    if (!foreign) {
      return no(`replayed (${fact}), but nothing in it is another account's data: whether it is a flaw is the model's reading. Expect another account's marker, or use the secret class for a key`, { ...evidence, control: seen.join("; ") });
    }
    return {
      claimId: claim.id, state: "proven", validator: this.name,
      reason: `${fact}; the body carries account ${foreign[0].toUpperCase()}'s marker`,
      evidence: { ...evidence, control: seen.join("; ") },
      ceiling: "critical",
    };
  },
};

/* explore.cross-actor: the same URL read by the owner (B), the attacker and
 * anonymous; the oracle of authz-matrix decides, with a control id. */
const exploreCrossActorValidator: Validator = {
  class: "explore.cross-actor",
  name: "cross-actor diff (owner, attacker, anonymous, control id)",
  async validate(claim, env) {
    const no = (reason: string, evidence?: Evidence): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason, evidence });
    const url = resolveExploreUrl(String(claim.detail.url ?? ""), env.stagingUrl);
    if (!url) return no("not an http(s) URL");
    const owner = parseActor(claim.detail.owner) ?? "b";
    const attacker = parseActor(claim.detail.attacker) ?? "a";
    if (owner === "anon") return no("the owner must be a configured account");
    if (owner === attacker) return no("owner and attacker are the same account");
    const opts = (env.options["authz-matrix"] ?? {}) as AuthzOptions;
    const ownerToken = actorToken(env.options, owner);
    if (!ownerToken) return no(`no token for account ${owner.toUpperCase()}: the owner's own read is the baseline`);
    if (attacker !== "anon") {
      const t = actorToken(env.options, attacker);
      if (!t) return no(`no token for account ${attacker.toUpperCase()}`);
      const same = sameIdentity(t, ownerToken);
      if (same) return no(`accounts ${attacker.toUpperCase()} and ${owner.toUpperCase()} ${same}: not two tenants`);
    }
    const path = pathOnly(url);
    const templ = (p: string) => new RegExp("^" + p.split("?")[0]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/:id/g, "[^/]+") + "$");
    if ((opts.publicByDesign ?? []).some((p) => p.startsWith("/") && templ(p).test(new URL(url).pathname)) || (opts.resources ?? []).some((r) => r.public && templ(r.path).test(new URL(url).pathname))) {
      return no(`${path} is public by design (trust boundary in the config)`);
    }
    const req: ExploreRequest = { url };
    const ownerRes = await sendAs(req, owner, env, url);
    if (!ok2xx(ownerRes.status)) return no(`the owner (${owner.toUpperCase()}) gets HTTP ${ownerRes.status}: no object to compare`);
    const marker = actorMarker(env.options, owner);
    if (marker && !ownerRes.body.includes(marker)) return no(`the owner's response does not carry ${owner.toUpperCase()}'s marker: not shown to be ${owner.toUpperCase()}'s object`);
    const id = typeof claim.detail.id === "string" ? claim.detail.id : undefined;
    const ctl = controlUrl(url, id);
    const attackerRes = await sendAs(req, attacker, env, url);
    const controlRes = await sendAs(req, attacker, env, ctl);
    const markers = marker ? [marker] : [];
    const o = authzOracle({ attacker: attackerRes, owner: ownerRes, control: controlRes, ownerMarkers: markers });
    const who = attacker === "anon" ? "no token at all" : `account ${attacker.toUpperCase()}'s token`;
    const evidence: Evidence = {
      request: reqLine("GET", url, attacker), response: `HTTP ${attackerRes.status}\n${excerpt(attackerRes.body)}`, sha256: sha(attackerRes.body),
      control: `GET ${ctl} -> HTTP ${controlRes.status}; owner (${owner.toUpperCase()}) -> HTTP ${ownerRes.status}, sha256 ${sha(ownerRes.body).slice(0, 12)}`,
    };
    if (o.verdict !== "leak") return no(o.reason, o.verdict === "lead" ? evidence : undefined);
    // Content everyone gets is public, not a cross-tenant read: an anonymous read of the same object rules it out.
    if (attacker !== "anon") {
      const anonRes = await sendAs(req, "anon", env, url);
      evidence.control += `; anonymous -> HTTP ${anonRes.status}`;
      if (ok2xx(anonRes.status) && authzOracle({ attacker: anonRes, owner: ownerRes, control: controlRes, ownerMarkers: markers }).verdict === "leak") {
        return no("an anonymous visitor gets the same object: public content, not a read across tenants (claim it for anon if that is the flaw)", evidence);
      }
    } else if (!marker) {
      return no("an anonymous read can only be told from public content by the owner's marker: declare accounts.b.marker", evidence);
    }
    // Stable: a second read gives the same verdict.
    const again = await sendAs(req, attacker, env, url);
    if (authzOracle({ attacker: again, owner: ownerRes, control: controlRes, ownerMarkers: markers }).verdict !== "leak") return no("the second replay did not reproduce", evidence);
    return { claimId: claim.id, state: "proven", validator: this.name, reason: `${who} reads ${owner.toUpperCase()}'s object at ${path}: ${o.reason}`, evidence, ceiling: "critical" };
  },
};

/* explore.secret: a secret of a known shape in a response, not echoed from the request. */
const exploreSecretValidator: Validator = {
  class: "explore.secret",
  name: "secret-in-response (key pattern, optional liveness)",
  async validate(claim, env) {
    const no = (reason: string, evidence?: Evidence): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason, evidence });
    const req = parseRequest(claim.detail.request);
    if (!req) return no("no request to replay");
    const url = resolveExploreUrl(req.url, env.stagingUrl);
    if (!url) return no("not an http(s) URL");
    if (!isReadRequest(req, url)) return no("only a read is replayed");
    const actor = req.as ?? "anon";
    const res = await sendAs(req, actor, env, url);
    const sent = `${url} ${JSON.stringify(req.headers ?? {})} ${req.body ?? ""}`;
    const evidence = (what: string): Evidence => ({ request: reqLine((req.method ?? "GET").toUpperCase(), url, actor), response: `HTTP ${res.status}\n${what}`, sha256: sha(res.body) });
    if (!ok2xx(res.status)) return no(`HTTP ${res.status}`, evidence("(no body kept)"));
    for (const p of PATTERNS) {
      if (p.sensitive === false) continue;
      p.regex.lastIndex = 0;
      for (const m of res.body.matchAll(new RegExp(p.regex.source, "g"))) {
        const key = m[0];
        if (isPlaceholder(key) || sent.includes(key)) continue;
        if (p.accept && !p.accept(key, res.body, m.index ?? 0)) continue;
        const masked = `${key.slice(0, Math.min(12, key.length - 4))}…${key.slice(-4)}`;
        let live = "";
        if ((env.options.explore as { secretLiveness?: boolean } | undefined)?.secretLiveness && verifierHost(p.id)) {
          const r = await checkLiveness(p.id, key, env.scope);
          live = r.liveness === "unknown" ? `; liveness unknown${r.host && !env.scope.isHostAllowed(`https://${r.host}/`) ? ` (declare ${r.host} to check it)` : ""}` : `; liveness: ${r.liveness} (HTTP ${r.status} from ${r.host})`;
          if (r.liveness === "revoked") return { claimId: claim.id, state: "proven", validator: this.name, reason: `${p.title} served at ${pathOnly(url)}, revoked${live}`, evidence: evidence(`${p.title}: ${masked}`), ceiling: "low" };
        }
        return { claimId: claim.id, state: "proven", validator: this.name, reason: `${p.title} served at ${pathOnly(url)} to ${actor === "anon" ? "anyone" : `account ${actor.toUpperCase()}`}${live}`, evidence: evidence(`${p.title}: ${masked}`), ceiling: p.severity };
      }
    }
    return no("no secret of a known shape in the response (publishable keys and placeholders do not count)", evidence("(no secret)"));
  },
};

/* explore.file-match: the quoted text is in the file, inside the project. */
const exploreFileValidator: Validator = {
  class: "explore.file-match",
  name: "file-content match in the repository",
  async validate(claim, env) {
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    const rel = String(claim.detail.file ?? "").replace(/\\/g, "/");
    const text = String(claim.detail.text ?? "");
    if (text.trim().length < 12) return no("the quote must be 12 characters or more");
    const full = insideProject(env.projectDir, rel);
    if (!full) return no(`${rel || "(no file)"} is not a file inside the project`);
    const st = statSync(full);
    if (st.size > 2 * 1024 * 1024) return no("file over 2 MB");
    const body = readFileSync(full, "utf8");
    if (body.slice(0, 8000).includes("\u0000")) return no("binary file");
    const line = Number(claim.detail.line ?? 0) || 0;
    const lines = body.split("\n");
    const at = line ? (lines[line - 1] ?? "").includes(text.split("\n")[0]!) && body.includes(text) : body.includes(text);
    if (!at) return no(line ? `the quote is not at ${rel}:${line}` : `the quote is not in ${rel}`);
    const n = line || body.slice(0, body.indexOf(text)).split("\n").length;
    return {
      claimId: claim.id, state: "proven", validator: this.name, reason: `the quoted code is at ${rel}:${n} (what it means is the model's reading)`,
      evidence: { request: `${rel}:${n}`, response: excerpt(text, 300), sha256: sha(body) }, ceiling: "medium",
    };
  },
};

/** Absolute path of `rel` when it is a regular file inside `root` (symlinks resolved), else null. */
export function insideProject(root: string, rel: string): string | null {
  if (!rel || rel.includes("\u0000") || isAbsolute(rel)) return null;
  try {
    const base = realpathSync(root);
    const full = realpathSync(resolve(base, rel));
    if (full !== base && !full.startsWith(base + sep)) return null;
    return statSync(full).isFile() ? full : null;
  } catch {
    return null;
  }
}

const pathOnly = (url: string) => { try { const u = new URL(url); return u.pathname + u.search; } catch { return url; } };

/* ---------------- explore.injection ---------------- */
// Proves an injection by a differential, a reflection or a computation the server
// performed — never by a signature. The exploration model submits a candidate
// point { url, param, where?: "query"|"body", method?, value? }; this validator
// generates its OWN payloads from a fresh nonce and the oracles in inject.ts
// decide. A static page that ignores the param can never be proven (the SQLi
// oracle needs a clean TRUE/FALSE differential). See inject.test.ts.

/** Put `value` into `param` of a request, in the query string or the form body. Pure, tested. */
export function injectParam(base: ExploreRequest, param: string, value: string, where: "query" | "body"): ExploreRequest {
  if (where === "body") {
    const body = new URLSearchParams(base.body ?? "");
    body.set(param, value);
    return { ...base, method: base.method ?? "POST", body: body.toString(), headers: { "content-type": "application/x-www-form-urlencoded", ...(base.headers ?? {}) } };
  }
  // query: rebuild on top of the url's existing search
  const u = new URL(base.url, "http://x");
  u.searchParams.set(param, value);
  const rel = base.url.startsWith("http") ? u.toString() : u.pathname + u.search;
  return { ...base, url: rel, method: base.method ?? "GET" };
}

/** GraphQL injection: the model gives a query with the literal marker __INJECT__
 * inside a string argument; the validator substitutes each payload (escaped for a
 * GraphQL double-quoted string) and sends it as a POST JSON body. Generic: the
 * same oracles decide on the response. */
export function injectGraphql(url: string, gqlTemplate: string, value: string): ExploreRequest {
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const query = gqlTemplate.includes("__INJECT__") ? gqlTemplate.replace(/__INJECT__/g, escaped) : gqlTemplate;
  return { url, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query }) };
}

const exploreInjectionValidator: Validator = {
  class: "explore.injection",
  name: "injection (generic oracle: differential, reflection, computation)",
  async validate(claim, env) {
    const d = claim.detail as { url?: unknown; param?: unknown; where?: unknown; method?: unknown; value?: unknown; as?: unknown; gql?: unknown };
    const no = (reason: string, ev?: Evidence): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason, evidence: ev });
    const gql = typeof d.gql === "string" && d.gql.includes("__INJECT__") ? d.gql : null;
    if (typeof d.url !== "string") return no("need detail.url");
    if (!gql && typeof d.param !== "string") return no("need detail.param (REST) or detail.gql with __INJECT__ (GraphQL)");
    const url0 = resolveExploreUrl(d.url, env.stagingUrl);
    if (!url0) return no("not an http(s) URL");
    const where: "query" | "body" = d.where === "body" ? "body" : "query";
    const baseVal = typeof d.value === "string" && d.value ? d.value : "1";
    const pname = typeof d.param === "string" ? d.param : "gql-arg";
    const actor = parseActor(d.as);
    const base: ExploreRequest = { url: d.url, method: typeof d.method === "string" ? d.method : (where === "body" ? "POST" : "GET"), as: actor };
    const fetchWith = async (value: string) => {
      const req = gql ? { ...injectGraphql(d.url as string, gql, value), as: actor } : injectParam(base, d.param as string, value, where);
      const res = await sendAs(req, actor, env, resolveExploreUrl(req.url, env.stagingUrl) ?? url0);
      return { status: res.status, body: res.body };
    };
    const ev = (what: string): Evidence => ({ request: `${(base.method ?? "GET")} ${pathOnly(url0)} (${pname}=…)`, response: what });
    const leads: string[] = [];

    // 1. SQL injection — boolean/error differential (strongest, hardest to fake).
    // Try standard breakout contexts (string with different closers, and numeric):
    // generic SQLi technique, not a signature for any target. First clean proof wins.
    try {
      const baseline = await fetchWith(baseVal);
      const contexts: Array<{ t: string; f: string }> = [
        { t: `${baseVal}' OR '1'='1`, f: `${baseVal}' AND '1'='2` },           // string, single quote
        { t: `${baseVal}' OR 1=1-- `, f: `${baseVal}' AND 1=2-- ` },           // string, commented tail
        { t: `${baseVal}') OR ('1'='1`, f: `${baseVal}') AND ('1'='2` },       // one paren
        { t: `${baseVal}')) OR (('1'='1`, f: `${baseVal}')) AND (('1'='2` },   // two parens
        { t: `${baseVal}" OR "1"="1`, f: `${baseVal}" AND "1"="2` },           // double quote
        { t: `${baseVal} OR 1=1`, f: `${baseVal} AND 1=2` },                   // numeric, no quote
      ];
      let decided = false;
      for (const c of contexts) {
        const truthy = await fetchWith(c.t);
        const falsy = await fetchWith(c.f);
        const r = sqliOracle({ baseline, truthy, falsy });
        if (r.verdict === "proven") return { claimId: claim.id, state: "proven", validator: this.name, reason: `SQL injection in ${pname} at ${pathOnly(url0)}: ${r.reason}`, evidence: ev(r.reason), ceiling: "high" };
        if (r.verdict === "lead" && !decided) { leads.push(r.reason); decided = true; }
      }
    } catch (e) { leads.push(`sqli probe failed: ${(e as Error).message}`); }

    // 2. Reflected XSS — unescaped markup.
    try {
      const t = nonce(pname);
      const res = await fetchWith(`<svg/onload=1>${t}`);
      const r = xssOracle({ token: t, body: res.body, status: res.status });
      if (r.verdict === "proven") return { claimId: claim.id, state: "proven", validator: this.name, reason: `Reflected XSS in ${pname} at ${pathOnly(url0)}: ${r.reason}`, evidence: ev(r.reason), ceiling: "medium" };
      if (r.verdict === "lead") leads.push(r.reason);
    } catch (e) { leads.push(`xss probe failed: ${(e as Error).message}`); }

    // 3. Template / expression injection — a computation the server performed.
    for (const form of ["${N}", "{{N}}", "#{N}", "<%= N %>"]) {
      try {
        const t = nonce(pname + form);
        const res = await fetchWith(`${t}${form.replace("N", "7*7")}`);
        const r = templateOracle({ token: t, product: "49", body: res.body });
        if (r.verdict === "proven") return { claimId: claim.id, state: "proven", validator: this.name, reason: `Template/expression injection in ${pname} at ${pathOnly(url0)} (${form}): ${r.reason}`, evidence: ev(r.reason), ceiling: "high" };
        if (r.verdict === "lead") leads.push(`${form}: ${r.reason}`);
      } catch (e) { leads.push(`template probe failed: ${(e as Error).message}`); }
    }

    // 4. OS command injection — the shell computed an arithmetic tied to the nonce.
    // Generic shell break-outs (not a signature); $((7*7)) is evaluated to 49 only
    // if the value reaches a shell. The template oracle proves nonce+"49" adjacency.
    for (const form of [`; echo T$((7*7))`, `| echo T$((7*7))`, `$(echo T$((7*7)))`, `\`echo T$((7*7))\``, `&& echo T$((7*7))`]) {
      try {
        const t = nonce(pname + form);
        const res = await fetchWith(`${baseVal}${form.replace("T", t)}`);
        const r = templateOracle({ token: t, product: "49", body: res.body });
        if (r.verdict === "proven") return { claimId: claim.id, state: "proven", validator: this.name, reason: `OS command injection in ${pname} at ${pathOnly(url0)} (${form.trim()}): the shell evaluated the expression`, evidence: ev(r.reason), ceiling: "critical" };
        if (r.verdict === "lead") leads.push(`cmd ${form.trim()}: ${r.reason}`);
      } catch (e) { leads.push(`command probe failed: ${(e as Error).message}`); }
    }

    return no(leads.length ? `not proven; leads: ${leads.slice(0, 3).join("; ")}` : "no injection proven (no differential, reflection or computation)", ev(leads.slice(0, 2).join(" | ")));
  },
};

/* ---------------- explore.ssrf ---------------- */
// Proves SSRF out-of-band: the model points at a candidate parameter (REST or
// GraphQL) that it thinks the server fetches; this validator stands up a listener
// and injects a callback URL with a nonce. A hit proves the server made the
// request. The callback host must be reachable from the target (config/detail).
const exploreSsrfValidator: Validator = {
  class: "explore.ssrf",
  name: "ssrf (out-of-band callback)",
  async validate(claim, env) {
    const d = claim.detail as { url?: unknown; param?: unknown; where?: unknown; method?: unknown; gql?: unknown; as?: unknown; callbackHost?: unknown };
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    const gql = typeof d.gql === "string" && d.gql.includes("__INJECT__") ? d.gql : null;
    if (typeof d.url !== "string") return no("need detail.url");
    if (!gql && typeof d.param !== "string") return no("need detail.param (REST) or detail.gql with __INJECT__ (GraphQL)");
    const url0 = resolveExploreUrl(d.url, env.stagingUrl);
    if (!url0) return no("not an http(s) URL");
    const opts = (env.options.explore as { ssrfCallbackHost?: string; ssrfCallbackPort?: number } | undefined) ?? {};
    const host = (typeof d.callbackHost === "string" && d.callbackHost) || opts.ssrfCallbackHost || "127.0.0.1";
    const actor = parseActor(d.as);
    const where: "query" | "body" = d.where === "body" ? "body" : "query";
    const cb = await startCallback(host, typeof opts.ssrfCallbackPort === "number" ? opts.ssrfCallbackPort : 0);
    try {
      const n = nonce(String(d.param ?? "gql"));
      // Single URL parameter: inject the whole callback URL (validator composes it).
      // Structured/GraphQL (host/port/path split): the model built the callback from
      // the advertised host:port and left __INJECT__ as the nonce slot, so inject the nonce.
      const payload = gql ? n : cb.url(n);
      const base: ExploreRequest = { url: d.url, method: typeof d.method === "string" ? d.method : (where === "body" ? "POST" : "GET"), as: actor };
      const req = gql ? { ...injectGraphql(d.url, gql, payload), as: actor } : injectParam(base, d.param as string, payload, where);
      // The server often BLOCKS on the outbound SSRF request, so sendAs may time
      // out or error — the callback can still have fired. Fire-and-forget, then
      // poll the listener regardless of the request's own outcome.
      sendAs(req, actor, env, resolveExploreUrl(req.url, env.stagingUrl) ?? url0).catch(() => {});
      // give the server time to make the outbound call (longer than one HTTP timeout)
      for (let i = 0; i < 60 && !cb.hits().includes(n); i++) await new Promise((r) => setTimeout(r, 250));
      const r = ssrfOracle({ nonce: n, hits: cb.hits() });
      if (r.verdict === "proven") return { claimId: claim.id, state: "proven", validator: this.name, reason: `SSRF in ${String(d.param ?? "gql")} at ${pathOnly(url0)}: ${r.reason}`, evidence: { request: `${base.method} ${pathOnly(url0)} (callback ${payload})`, response: "out-of-band hit received" }, ceiling: "high" };
      return no(`${r.reason} (callback host ${host}:${cb.port}; set detail.callbackHost or options.explore.ssrfCallbackHost to an address the target can reach)`);
    } finally {
      await cb.close();
    }
  },
};

/* ---------------- explore.stored-xss ---------------- */
// Stored XSS lives across two requests: one STORES attacker markup, another SERVES
// it. The model gives both; the validator injects a nonce-tagged <svg> into the
// store request, then reads the retrieve request and applies the reflected-XSS
// oracle to that body. Generic (no target signature); proven only if the markup
// comes back UNescaped in the served page.
const exploreStoredXssValidator: Validator = {
  class: "explore.stored-xss",
  name: "stored XSS (store then serve, unescaped markup)",
  async validate(claim, env) {
    const d = claim.detail as { storeUrl?: unknown; storeParam?: unknown; storeWhere?: unknown; storeGql?: unknown; storeMethod?: unknown; retrieveUrl?: unknown; retrieveGql?: unknown; as?: unknown };
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    const storeGql = typeof d.storeGql === "string" && d.storeGql.includes("__INJECT__") ? d.storeGql : null;
    if (typeof d.storeUrl !== "string") return no("need detail.storeUrl");
    if (!storeGql && typeof d.storeParam !== "string") return no("need detail.storeParam (REST) or detail.storeGql with __INJECT__ (GraphQL)");
    if (typeof d.retrieveUrl !== "string") return no("need detail.retrieveUrl (where the stored value is served)");
    const sUrl = resolveExploreUrl(d.storeUrl, env.stagingUrl), rUrl = resolveExploreUrl(d.retrieveUrl, env.stagingUrl);
    if (!sUrl || !rUrl) return no("not http(s) URLs");
    const actor = parseActor(d.as);
    const where: "query" | "body" = d.storeWhere === "query" ? "query" : "body";
    const t = nonce(String(d.storeParam ?? "stored"));
    const payload = `<svg/onload=1>${t}`;
    const sBase: ExploreRequest = { url: d.storeUrl, method: typeof d.storeMethod === "string" ? d.storeMethod : (storeGql ? "POST" : "POST"), as: actor };
    const sReq = storeGql ? { ...injectGraphql(d.storeUrl, storeGql, payload), as: actor } : injectParam(sBase, d.storeParam as string, payload, where);
    try { await sendAs(sReq, actor, env, resolveExploreUrl(sReq.url, env.stagingUrl) ?? sUrl); } catch (e) { return no(`store request failed: ${(e as Error).message}`); }
    let body: string;
    try {
      const rReq: ExploreRequest = typeof d.retrieveGql === "string"
        ? { url: d.retrieveUrl, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query: d.retrieveGql }), as: actor }
        : { url: d.retrieveUrl, method: "GET", as: actor };
      const res = await sendAs(rReq, actor, env, rUrl);
      body = res.body;
    } catch (e) { return no(`retrieve request failed: ${(e as Error).message}`); }
    const r = xssOracle({ token: t, body, status: 200 });
    if (r.verdict === "proven") return { claimId: claim.id, state: "proven", validator: this.name, reason: `Stored XSS: markup stored via ${pathOnly(sUrl)} is served unescaped at ${pathOnly(rUrl)}`, evidence: { request: `store ${pathOnly(sUrl)} → serve ${pathOnly(rUrl)}`, response: r.reason }, ceiling: "high" };
    return no(r.verdict === "lead" ? `${r.reason} (stored but check escaping/context)` : "the stored marker is not served unescaped");
  },
};

/* ---------------- explore.dom-xss ---------------- */
// Proves DOM XSS by running the page in a real headless browser: the payload
// calls alert(nonce); if that dialog fires, the injected script executed. The
// browser is optional (Playwright imported dynamically) — absent, it stays a lead.
const exploreDomXssValidator: Validator = {
  class: "explore.dom-xss",
  name: "DOM XSS (real browser, script execution)",
  async validate(claim, env) {
    const d = claim.detail as { url?: unknown; param?: unknown; where?: unknown; as?: unknown };
    const no = (reason: string): ClaimVerdict => ({ claimId: claim.id, state: "unproven", validator: this.name, reason });
    // Either a plain {url, param} (payload goes in the query), or a url template
    // with __INJECT__ marking where the payload goes — needed for SPA hash routes
    // (e.g. http://app/#/search?q=__INJECT__) which carry the sink in the fragment.
    const tmpl = typeof d.url === "string" && d.url.includes("__INJECT__");
    if (typeof d.url !== "string") return no("need detail.url");
    if (!tmpl && typeof d.param !== "string") return no("need detail.param, or put __INJECT__ in detail.url (SPA hash/path)");
    const url0 = resolveExploreUrl(tmpl ? d.url.replace(/__INJECT__/g, "x") : d.url, env.stagingUrl);
    if (!url0) return no("not an http(s) URL");
    if (!env.scope.isHostAllowed(url0)) return no("off-scope host");
    const where: "query" | "body" = d.where === "body" ? "body" : "query";
    if (!tmpl && where === "body") return no("DOM XSS proof loads a URL in a browser: use a query parameter or a __INJECT__ url");
    const t = nonce(String(d.param ?? "dom"));
    let full: string;
    if (tmpl) {
      const payloadEnc = encodeURIComponent(domXssPayload(t));
      full = resolveExploreUrl(d.url.replace(/__INJECT__/g, payloadEnc), env.stagingUrl) ?? url0;
    } else {
      const base: ExploreRequest = { url: d.url, method: "GET", as: parseActor(d.as) };
      const req = injectParam(base, d.param as string, domXssPayload(t), where);
      full = resolveExploreUrl(req.url, env.stagingUrl) ?? url0;
    }
    const opts = (env.options.explore as { domXssBrowser?: string; domXssPlaywright?: string } | undefined) ?? {};
    const r = await proveDomXss(full, t, { executablePath: opts.domXssBrowser, playwrightPath: opts.domXssPlaywright });
    if (!r.available) return no(r.reason);
    if (r.executed) return { claimId: claim.id, state: "proven", validator: this.name, reason: `DOM XSS in ${d.param ?? "url"} at ${tmpl ? (d.url as string).slice(0, 80) : pathOnly(url0)}: ${r.reason}`, evidence: { request: `GET ${pathOnly(full)} (browser-executed)`, response: r.reason }, ceiling: "high" };
    return no(r.reason);
  },
};

export const GENERIC_VALIDATORS: Validator[] = [exploreReplayValidator, exploreCrossActorValidator, exploreSecretValidator, exploreFileValidator, exploreInjectionValidator, exploreSsrfValidator, exploreStoredXssValidator, exploreDomXssValidator];

export const VALIDATORS: Validator[] = [authzValidator, baasValidator, headerValidator, replayValidator, fileReplayValidator, plainHttpValidator, ...GENERIC_VALIDATORS];

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
