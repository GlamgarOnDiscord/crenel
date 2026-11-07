// Shared plumbing for the active-mode checks (authz-write, mass-assignment,
// race). These are the only checks in Crenel that send writes, so they share
// one set of rules, enforced here rather than repeated in each file:
//
//   - off unless the check's own options say `enabled: true`, AND the scope has
//     allowActiveTesting (a check that is enabled without it throws a
//     ScopeError, so the run says why nothing was sent);
//   - every request goes through safeFetch (declared hosts, journal, kill switch)
//     and through a per-run budget with a hard ceiling;
//   - targets and ids come only from the config: nothing discovered is written;
//   - every write is recorded with what was sent, its answer and whether the
//     previous value was put back, and the run reports that list verbatim.

import { randomBytes } from "node:crypto";
import { safeFetch } from "../core/net.js";
import type { CheckContext, Finding } from "../core/types.js";

/** A test account as declared in the config (staging tokens only). */
export interface ActiveAccount { token?: string }
export interface ActiveAccounts { a?: ActiveAccount; b?: ActiveAccount }

export const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
/** Hard ceiling on requests per active check per run, whatever the config says. */
export const HARD_MAX_REQUESTS = 150;
/** Hard ceiling on declared targets per active check. */
export const MAX_TARGETS = 10;

export interface ActiveBase { enabled?: boolean; accounts?: ActiveAccounts; maxRequests?: number }

/**
 * The options of an active check, or null when it is not enabled. Accounts
 * fall back to the ones declared for authz-matrix, so a user declares their
 * test accounts once.
 */
export function activeOptions<T extends ActiveBase>(ctx: CheckContext, name: string): (T & { accounts: ActiveAccounts }) | null {
  const o = (ctx.options[name] ?? {}) as T;
  if (o.enabled !== true) {
    ctx.log(`${name}: off (set options.${name}.enabled: true to run it on staging)`);
    return null;
  }
  // Enabled but active testing is off: refuse loudly, nothing leaves the machine.
  ctx.scope.assertActiveAllowed(name);
  const fallback = ((ctx.options["authz-matrix"] ?? {}) as { accounts?: ActiveAccounts }).accounts ?? {};
  return { ...o, accounts: o.accounts ?? fallback };
}

export const nonce = () => randomBytes(6).toString("hex");
export const canary = () => `crenel-canary-${nonce()}`;
export const ok2xx = (s: number) => s >= 200 && s < 300;

/** Read a dotted path ("data.profile.role") out of a parsed JSON value. */
export function getField(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const k of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

/** A copy of `obj` with the dotted path set to `value` (intermediate objects created). */
export function setField(obj: unknown, path: string, value: unknown): Record<string, unknown> {
  const root: Record<string, unknown> = obj && typeof obj === "object" && !Array.isArray(obj) ? structuredClone(obj as Record<string, unknown>) : {};
  const keys = path.split(".");
  let cur = root;
  for (const k of keys.slice(0, -1)) {
    const next = cur[k];
    cur[k] = next && typeof next === "object" && !Array.isArray(next) ? next : {};
    cur = cur[k] as Record<string, unknown>;
  }
  cur[keys[keys.length - 1]!] = value;
  return root;
}

export const same = (x: unknown, y: unknown) => JSON.stringify(x) === JSON.stringify(y);

export function parseJson(body: string): unknown {
  try { return JSON.parse(body); } catch { return undefined; }
}

export function urlOf(base: string, path: string, id?: string): string {
  return base.replace(/\/+$/, "") + (id === undefined ? path : path.replace(":id", encodeURIComponent(id)));
}

/** One write sent to staging, as the report shows it. */
export interface WriteRecord {
  method: string;
  url: string;
  actor: string;
  body?: string;
  status?: number;
  purpose: string;
  /** "restored", "not restored: why", or "nothing to restore" (refused, or the state did not change). */
  restore?: string;
}

export interface Answer { status: number; body: string; json: unknown }

/**
 * The only way the active checks talk to the target: scoped client, budget,
 * and a record of every write.
 */
export class ActiveClient {
  readonly writes: WriteRecord[] = [];
  private sent = 0;
  private readonly max: number;

  constructor(private readonly ctx: CheckContext, private readonly check: string, maxRequests?: number) {
    this.max = Math.max(1, Math.min(maxRequests ?? HARD_MAX_REQUESTS, HARD_MAX_REQUESTS));
  }

  get requests(): number { return this.sent; }

  /** Reserve `n` requests up front (a race burst), or throw before anything is sent. */
  reserve(n: number): void {
    if (this.sent + n > this.max) throw new Error(`${this.check}: request budget reached (${this.max}), stopped`);
  }

  async send(method: string, url: string, token: string | undefined, body?: unknown, record?: Omit<WriteRecord, "method" | "url" | "body" | "status">): Promise<Answer & { record?: WriteRecord }> {
    this.reserve(1);
    this.sent++;
    const m = method.toUpperCase();
    const headers: Record<string, string> = token ? { authorization: `Bearer ${token}` } : {};
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (payload !== undefined) headers["content-type"] = "application/json";
    let rec: WriteRecord | undefined;
    if (WRITE_METHODS.has(m)) {
      rec = { method: m, url, body: payload, actor: record?.actor ?? "?", purpose: record?.purpose ?? "", restore: record?.restore };
      this.writes.push(rec);
    }
    const res = await safeFetch(url, this.ctx.scope, { method: m, headers, body: payload, followRedirects: false });
    if (rec) rec.status = res.status;
    return { status: res.status, body: res.body, json: parseJson(res.body), record: rec };
  }

  read(url: string, token: string | undefined): Promise<Answer> {
    return this.send("GET", url, token);
  }
}

/** The write list, one line per write, for the report. */
export function renderWrites(writes: WriteRecord[]): string {
  return writes.map((w) => `${w.method} ${w.url} as ${w.actor}${w.body ? ` body ${w.body.length > 160 ? w.body.slice(0, 160) + "…" : w.body}` : ""} -> ${w.status ?? "not sent"} (${w.purpose}${w.restore ? `; ${w.restore}` : ""})`).join("\n");
}

/**
 * The summary every active check emits when it sent at least one write: what
 * was written, and whether each change was put back. Info, never proven: it is
 * the receipt, not a flaw.
 */
export function writesFinding(check: string, base: string, writes: WriteRecord[], notes: string[]): Finding | null {
  if (writes.length === 0 && notes.length === 0) return null;
  const left = writes.filter((w) => w.restore?.startsWith("not restored"));
  return {
    id: `${check}:writes`,
    check,
    title: `Active mode: ${writes.length} write(s) sent to staging${left.length ? `, ${left.length} change(s) NOT restored` : ", every change restored or refused"}`,
    severity: "info",
    state: "unproven",
    location: base,
    description:
      `${check} wrote to your staging with the declared test accounts. ` +
      (left.length ? `Put these back by hand: ${left.map((w) => `${w.method} ${w.url} (${w.restore})`).join("; ")}. ` : "") +
      (notes.length ? `Notes: ${notes.join(" ")}` : ""),
    remediation: left.length ? "Restore the objects listed above (or recreate the disposable ones) before the next run." : "Nothing to do: this is the record of what the active check sent.",
    proof: { method: "record of every write sent by the check", replay: "see evidence", evidence: renderWrites(writes) || "(no write sent)" },
  };
}

/** Why two bearer tokens are the same identity, or null (same rule as authz-matrix). */
export { sameIdentity } from "./authz-matrix.js";
