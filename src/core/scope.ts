// The scope guard is the safety core of Crenel.
//
// Every action that leaves the local filesystem has to pass through here first.
// The rule is simple and deliberately strict: you may only touch a host you have
// listed as yours, active (non read-only) testing is off unless you opt in, and
// anything destructive is never allowed. This is what makes the tool publishable:
// pointed at a stranger's site it refuses to do anything but read public,
// already-visible responses.
//
// The research behind this: agents that are handed scope in a prompt drift out
// of it under goal pressure. So scope lives in code, not in an instruction.

export interface ScopeConfig {
  /** Hostnames you declare you own or are authorised to test. */
  allowedHosts: string[];
  /** Turn on active, non read-only checks. Off by default. */
  allowActiveTesting?: boolean;
  /** A staging base URL; must resolve to an allowed host. */
  stagingUrl?: string;
  /** Allow targets that resolve to private IPs (an internal staging box). Off by default. */
  allowPrivate?: boolean;
  /**
   * Kill switch for everything sent under this scope. When it aborts, the
   * scoped client refuses new requests and cancels the one in flight, so
   * stopping a run really stops it (not only the loop around it).
   */
  signal?: AbortSignal;
  /** Observer called for every request the scoped client sends or refuses (journal, audit, budgets). */
  onRequest?: (e: NetEvent) => void;
  /**
   * Cloudflare Access service tokens, per exact host: the names of the two
   * environment variables holding the Client ID and Secret (never the values).
   */
  access?: Record<string, AccessTokenRef>;
  /** Environment the access variables are read from (tests). Defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  /** Pace every request sent under this scope to at most this many per second. */
  ratePerSec?: number;
  /** Refuse any request past this many in the life of the scope (a run's budget). */
  maxRequests?: number;
}

/** One request seen by the scoped client: sent (with a status or an error) or refused. */
export interface NetEvent {
  method: string;
  url: string;
  status?: number;
  error?: string;
  /** Set when the scope refused the request before anything left the machine. */
  refused?: string;
}

import { resolveAccess, type AccessGate, type AccessTokenRef } from "./access.js";

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeError";
  }
}

/** Thrown by safeFetch when the response is Cloudflare Access, not the app: the host was not reached. */
export class AccessGateError extends ScopeError {
  constructor(readonly gate: AccessGate) {
    super(`Not reached: ${gate.host} is behind Cloudflare Access (${gate.reason}); the response is its login page, not the app`);
    this.name = "AccessGateError";
  }
}

export class Scope {
  private readonly allowed: Set<string>;
  readonly allowActiveTesting: boolean;
  readonly allowPrivate: boolean;
  readonly stagingUrl?: string;
  readonly signal?: AbortSignal;
  readonly onRequest?: (e: NetEvent) => void;
  readonly ratePerSec?: number;
  readonly maxRequests?: number;
  /** Requests reserved so far (budget and pacing). */
  private sent = 0;
  private nextAt = 0;
  private readonly hostHeaders: Record<string, Record<string, string>> = {};
  /** Hosts whose access token could not be loaded, with the reason. */
  readonly accessMissing: Record<string, string> = {};
  /** Hosts seen behind Cloudflare Access during this scope's life (first sighting kept). */
  readonly accessGates = new Map<string, AccessGate>();

  /** The declared hosts, for checks that look at each of them (DNS, takeover). */
  get allowedHosts(): string[] { return [...this.allowed]; }

  constructor(config: ScopeConfig) {
    this.signal = config.signal;
    this.onRequest = config.onRequest;
    this.allowed = new Set(config.allowedHosts.map((h) => h.toLowerCase().trim()));
    this.allowActiveTesting = config.allowActiveTesting ?? false;
    this.allowPrivate = config.allowPrivate ?? false;
    if (config.ratePerSec !== undefined && config.ratePerSec > 0) this.ratePerSec = config.ratePerSec;
    if (config.maxRequests !== undefined && config.maxRequests > 0) this.maxRequests = config.maxRequests;
    if (config.access && Object.keys(config.access).length) {
      for (const h of Object.keys(config.access)) {
        if (!this.allowed.has(h.toLowerCase().trim())) throw new ScopeError(`Refused: scope.access names ${h}, which is not in allowedHosts`);
      }
      const r = resolveAccess(config.access, config.env ?? process.env);
      Object.assign(this.hostHeaders, r.headers);
      Object.assign(this.accessMissing, r.missing);
    }
    if (config.stagingUrl) {
      // Validate the staging URL against the allowlist at construction time, so a
      // misconfigured run fails before any check gets to make a request.
      this.assertUrlAllowed(config.stagingUrl);
      this.stagingUrl = config.stagingUrl;
    }
  }

  /** True when the host of `url` is in the allowlist. */
  isHostAllowed(url: string): boolean {
    let host: string;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      return false;
    }
    return this.allowed.has(host);
  }

  /** Throws unless `url` targets a declared, owned host. */
  assertUrlAllowed(url: string): void {
    if (!this.isHostAllowed(url)) {
      throw new ScopeError(
        `Refused: ${safeHost(url)} is not in allowedHosts. ` +
          `Crenel only tests hosts you have declared you own.`,
      );
    }
  }

  /** Gate for a check that writes, mutates, or sends attack payloads. */
  assertActiveAllowed(checkName: string): void {
    if (!this.allowActiveTesting) {
      throw new ScopeError(
        `Refused: check "${checkName}" is not read-only and allowActiveTesting is off. ` +
          `Enable it in the config only for a target you own, on staging.`,
      );
    }
  }

  /**
   * Extra headers for a request to exactly this URL: the service token of its
   * host, over https only. A redirect to another host, or a plain http:// URL,
   * gets nothing.
   */
  headersFor(url: string): Record<string, string> {
    let u: URL;
    try { u = new URL(url); } catch { return {}; }
    if (u.protocol !== "https:") return {};
    return this.hostHeaders[u.hostname.toLowerCase()] ?? {};
  }

  /** Record that a host answered with Cloudflare Access (first sighting kept, a root sighting preferred). */
  noteAccessGate(gate: AccessGate): void {
    const prev = this.accessGates.get(gate.host);
    // A sighting on the root wins: it means the whole host is the Access application.
    if (!prev || (new URL(prev.url).pathname !== "/" && new URL(gate.url).pathname === "/")) this.accessGates.set(gate.host, gate);
  }

  /**
   * Reserve one request: refuse past maxRequests, wait for the next slot under
   * ratePerSec. The slot is reserved synchronously, so concurrent callers queue.
   */
  async pace(): Promise<void> {
    if (this.maxRequests !== undefined && this.sent >= this.maxRequests) {
      throw new ScopeError(`Refused: request budget exhausted (scope.maxRequests ${this.maxRequests})`);
    }
    this.sent++;
    if (!this.ratePerSec) return;
    const now = Date.now();
    const at = Math.max(now, this.nextAt);
    this.nextAt = at + 1000 / this.ratePerSec;
    if (at > now) await new Promise<void>((res, rej) => {
      const t = setTimeout(res, at - now);
      this.signal?.addEventListener("abort", () => { clearTimeout(t); rej(this.signal!.reason); }, { once: true });
    });
  }

  /** Requests sent (or reserved) under this scope. */
  get requestsSent(): number { return this.sent; }

  get hosts(): string[] {
    return [...this.allowed];
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "(invalid url)";
  }
}

