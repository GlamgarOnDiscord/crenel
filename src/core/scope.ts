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

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeError";
  }
}

export class Scope {
  private readonly allowed: Set<string>;
  readonly allowActiveTesting: boolean;
  readonly allowPrivate: boolean;
  readonly stagingUrl?: string;
  readonly signal?: AbortSignal;
  readonly onRequest?: (e: NetEvent) => void;

  /** The declared hosts, for checks that look at each of them (DNS, takeover). */
  get allowedHosts(): string[] { return [...this.allowed]; }

  constructor(config: ScopeConfig) {
    this.signal = config.signal;
    this.onRequest = config.onRequest;
    this.allowed = new Set(config.allowedHosts.map((h) => h.toLowerCase().trim()));
    this.allowActiveTesting = config.allowActiveTesting ?? false;
    this.allowPrivate = config.allowPrivate ?? false;
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
