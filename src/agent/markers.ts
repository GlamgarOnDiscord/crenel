// Account markers derived at run time (whoami differential).
//
// The validators that decide a cross-account read (cross-actor, replay) need a
// marker per account: a value present only in that account's own objects.
// Declaring one is still the strongest (accounts.<x>.marker). Without it, the
// exploration reads each account's own identity endpoint and keeps a value that
// differential makes specific to that account: an identity field (id, email,
// username, …) of the account's read that appears in no other account's read
// and not in the anonymous one. A generic mechanism (no target name or value);
// a derived marker is used only where none is declared, and the validators keep
// their own controls on top of it. Pure, so it is tested without a network.

export interface Read { status: number; body: string }

// Identity fields, most specific first. Field names, not values: the same for every API.
const ID_KEYS = ["email", "username", "login", "handle", "uuid", "user_id", "userId", "account_id", "accountId", "sub", "id", "_id"];

/** Scalar values of identity keys in a JSON body, in ID_KEYS order (first occurrence in a depth-first walk per key). */
export function identityValues(body: string): string[] {
  let root: unknown;
  try { root = JSON.parse(body); } catch { return []; }
  const found = new Map<string, string>();
  const seen = new Set<unknown>();
  const walk = (n: unknown, depth: number) => {
    if (!n || typeof n !== "object" || seen.has(n) || depth > 4) return;
    seen.add(n);
    if (Array.isArray(n)) return; // a list is not the account itself
    for (const [k, v] of Object.entries(n as Record<string, unknown>)) {
      if (ID_KEYS.includes(k) && !found.has(k) && (typeof v === "string" || typeof v === "number")) found.set(k, String(v));
      else walk(v, depth + 1);
    }
  };
  walk(root, 0);
  return ID_KEYS.filter((k) => found.has(k)).map((k) => found.get(k)!);
}

// Long enough not to occur by chance: 6+ characters with a letter, or 8+ digits.
const distinctive = (v: string) => (/[a-z]/i.test(v) ? v.length >= 6 : v.length >= 8) && v.length <= 200;

/**
 * For each account whose own read succeeded, the first identity value that is
 * distinctive and absent from every other account's read and from the anonymous
 * read. An account with none gets no marker (its claims stay leads, as before).
 */
export function deriveMarkers(reads: Partial<Record<"a" | "b" | "c", Read>>, anon?: Read): Partial<Record<"a" | "b" | "c", string>> {
  const out: Partial<Record<"a" | "b" | "c", string>> = {};
  const ok = (r?: Read) => !!r && r.status >= 200 && r.status < 300;
  const ids = Object.keys(reads) as ("a" | "b" | "c")[];
  for (const k of ids) {
    const r = reads[k];
    if (!ok(r)) continue;
    const others = ids.filter((o) => o !== k).map((o) => reads[o]?.body ?? "");
    // Two accounts whose identity reads are the same are not two identities.
    if (ids.some((o) => o !== k && ok(reads[o]) && reads[o]!.body === r!.body)) continue;
    const m = identityValues(r!.body).find((v) => distinctive(v) && !others.some((b) => b.includes(v)) && !(anon?.body ?? "").includes(v));
    if (m) out[k] = m;
  }
  return out;
}

/** Usual identity endpoints (paths only, the same for any API); options.authz-matrix.whoami puts one first. */
export const WHOAMI_PATHS = ["/api/me", "/api/users/me", "/api/user", "/api/auth/me", "/api/profile", "/me", "/api/v1/me", "/api/account"];

/** Identity values carried by a JWT's payload (sub, id, userId, email, at the root or under data/user). Empty for a non-JWT. */
export function tokenIdentity(token: string | undefined): string[] {
  if (!token) return [];
  let p: unknown;
  try { p = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")); } catch { return []; }
  const out: string[] = [];
  const take = (o: unknown) => {
    if (!o || typeof o !== "object" || Array.isArray(o)) return;
    for (const k of ["sub", "id", "userId", "user_id", "uid", "email"]) { const v = (o as Record<string, unknown>)[k]; if ((typeof v === "string" && v) || typeof v === "number") out.push(String(v)); }
  };
  take(p);
  for (const w of ["data", "user", "account"]) take((p as Record<string, unknown> | null)?.[w]);
  return [...new Set(out)];
}

// Fields that name an object's owner, in any API ("UserId", "owner_id", "accountId", "createdBy", …).
const OWNER_FIELD = /^(user|owner|account|customer|author|member|created_?by|tenant)_?id$|^(owner|created_?by)$/i;

/** Owner-field values of a JSON object (at the root or under one wrapper such as data). Pure. */
export function ownerFieldValues(body: string): string[] {
  let j: unknown;
  try { j = JSON.parse(body); } catch { return []; }
  const out: string[] = [];
  const take = (o: unknown) => {
    if (!o || typeof o !== "object" || Array.isArray(o)) return;
    for (const [k, v] of Object.entries(o as Record<string, unknown>)) if (OWNER_FIELD.test(k) && (typeof v === "string" || typeof v === "number")) out.push(String(v));
  };
  take(j);
  if (j && typeof j === "object" && !Array.isArray(j)) for (const w of Object.values(j as Record<string, unknown>)) take(w);
  return out;
}
