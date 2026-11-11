// Authenticated sessions for the authz checks: a test account may declare a
// login flow instead of a pre-obtained token, and the run logs in itself. Short
// tokens (a 60 s JWT) and cookie sessions are out of reach of a static token in
// the config; a fresh login per run reaches them.
//
// A session proves nothing. It only lets the existing oracles (authzOracle, the
// same-identity guard) run as that account; a failed login means fewer probes,
// never a finding. The password is read from the environment at call time, by
// the NAME the config gives (never a value in the config, argv or a log).

import { safeFetch } from "../core/net.js";
import type { CheckContext } from "../core/types.js";
import { getField } from "./active-common.js";

export interface LoginSpec {
  /** Login endpoint: a path on the staging URL or an absolute URL on a declared host. */
  url: string;
  username?: string;
  /** Env var holding the username (instead of `username`). */
  usernameEnv?: string;
  /** Env var holding the password (required: never the value). */
  passwordEnv: string;
  usernameField?: string;
  passwordField?: string;
  /** "json" (default) or "form" (application/x-www-form-urlencoded). */
  format?: "json" | "form";
  /** Dotted path of the token in the JSON answer, when it is not found by shape. */
  tokenPath?: string;
}
export interface Session { token?: string; cookie?: string }
type Answer = { status: number; headers: Headers; body: string };

const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;
const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;
const TOKEN_KEYS = ["access_token", "accessToken", "auth_token", "authToken", "token", "jwt", "id_token", "idToken"];

/** True for a string that is a JWT: three base64url parts whose header decodes to JSON with `alg`. */
export function isJwt(s: string): boolean {
  if (!JWT.test(s)) return false;
  try { return typeof (JSON.parse(Buffer.from(s.split(".")[0]!, "base64url").toString("utf8")) as { alg?: unknown }).alg === "string"; } catch { return false; }
}

function findJwt(v: unknown, depth = 0): string | undefined {
  if (typeof v === "string") return isJwt(v) ? v : undefined;
  if (depth > 6 || !v || typeof v !== "object") return undefined;
  for (const x of Object.values(v as Record<string, unknown>)) { const t = findJwt(x, depth + 1); if (t) return t; }
  return undefined;
}

function findTokenKey(v: unknown, depth = 0): string | undefined {
  if (depth > 6 || !v || typeof v !== "object" || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  for (const k of TOKEN_KEYS) if (typeof o[k] === "string" && (o[k] as string).length >= 16 && !/\s/.test(o[k] as string)) return o[k] as string;
  for (const x of Object.values(o)) { const t = findTokenKey(x, depth + 1); if (t) return t; }
  return undefined;
}

/**
 * The session a login answer carries, or null. Pure: a 2xx/3xx answer, a token
 * (declared path, else a JWT anywhere in the JSON, else a conventional token key)
 * and/or the cookies it sets (cookies being cleared are left out).
 */
export function extractSession(res: Answer, tokenPath?: string): Session | null {
  if (res.status < 200 || res.status >= 400) return null;
  let json: unknown;
  try { json = JSON.parse(res.body); } catch { json = undefined; }
  let token: string | undefined;
  if (json !== undefined) {
    if (tokenPath) { const t = getField(json, tokenPath); token = typeof t === "string" && t ? t : undefined; }
    else token = findJwt(json) ?? findTokenKey(json);
  }
  const pairs: string[] = [];
  for (const sc of res.headers.getSetCookie()) {
    const [pair = "", ...attrs] = sc.split(";");
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const value = pair.slice(eq + 1).trim();
    if (!value || attrs.some((a) => /^\s*max-age\s*=\s*(0|-\d+)\s*$/i.test(a) || /^\s*expires\s*=\s*thu, 01 jan 1970/i.test(a))) continue;
    pairs.push(`${pair.slice(0, eq).trim()}=${value}`);
  }
  const cookie = pairs.length ? pairs.join("; ") : undefined;
  if (!token && !cookie) return null;
  return { ...(token ? { token } : {}), ...(cookie ? { cookie } : {}) };
}

/** Log in once as a declared account. Throws with a reason (never the password) when no session comes back. */
export async function login(ctx: CheckContext, spec: LoginSpec, env: NodeJS.ProcessEnv = process.env): Promise<Session> {
  if (!spec?.url || !ENV_NAME.test(spec.passwordEnv ?? "")) throw new Error("login needs `url` and `passwordEnv` (the NAME of an env var)");
  if (spec.usernameEnv !== undefined && !ENV_NAME.test(spec.usernameEnv)) throw new Error("usernameEnv must be the NAME of an env var");
  const password = env[spec.passwordEnv];
  const username = spec.usernameEnv ? env[spec.usernameEnv] : spec.username;
  if (!password) throw new Error(`${spec.passwordEnv} is not set`);
  if (!username) throw new Error(spec.usernameEnv ? `${spec.usernameEnv} is not set` : "login needs `username` or `usernameEnv`");
  const url = /^https?:\/\//i.test(spec.url) ? spec.url : (ctx.stagingUrl ?? "").replace(/\/$/, "") + "/" + spec.url.replace(/^\//, "");
  const fields = { [spec.usernameField ?? "username"]: username, [spec.passwordField ?? "password"]: password };
  const form = spec.format === "form";
  const body = form ? new URLSearchParams(fields).toString() : JSON.stringify(fields);
  const res = await safeFetch(url, ctx.scope, { method: "POST", body, followRedirects: false, headers: { "content-type": form ? "application/x-www-form-urlencoded" : "application/json", accept: "application/json, */*" } });
  const s = extractSession(res, spec.tokenPath);
  if (!s) throw new Error(`login at ${new URL(url).pathname} answered ${res.status} with no token or session cookie`);
  return s;
}

/**
 * Accounts with a `login` get a fresh session (a declared token or cookie wins).
 * Logging in is a POST, so it needs active testing, like the live probes it serves.
 */
export async function resolveAccounts<A extends Session & { login?: LoginSpec }>(ctx: CheckContext, accounts: Record<string, A | undefined>, check: string, env?: NodeJS.ProcessEnv): Promise<Record<string, A | undefined>> {
  const out: Record<string, A | undefined> = { ...accounts };
  for (const [key, a] of Object.entries(accounts)) {
    if (!a?.login || a.token || a.cookie) continue;
    ctx.scope.assertActiveAllowed(`${check} (login of account ${key})`);
    try {
      const s = await login(ctx, a.login, env);
      out[key] = { ...a, ...s };
      ctx.log(`${check}: account ${key} logged in (${s.token ? "token" : ""}${s.token && s.cookie ? " + " : ""}${s.cookie ? "session cookie" : ""})`);
    } catch (err) {
      ctx.log(`${check}: account ${key} could not log in: ${(err as Error).message}`);
    }
  }
  return out;
}
