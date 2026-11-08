// Integration secrets: an environment variable first, else .crenel/secrets.json.
//
// The file is written with mode 0600 (owner read/write) through a temp file and
// a rename, and refused when group or others can read it (POSIX only: Windows
// does not carry these mode bits, so there the file relies on the profile's
// ACLs). A secret value never goes to the journal, the audit log, an API
// response or the terminal: callers show `maskUrl()` or "configured" instead,
// and `redact()` scrubs any known value from an error message.

import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

export type SecretSource = "env" | "file" | null;

export class SecretStore {
  readonly path: string;
  constructor(dir: string, private readonly env: NodeJS.ProcessEnv = process.env) {
    this.path = join(dir, "secrets.json");
  }

  private read(): Record<string, string> {
    if (!existsSync(this.path)) return {};
    if (process.platform !== "win32" && (statSync(this.path).mode & 0o077) !== 0) {
      throw new Error(`${this.path} is readable by other users: run chmod 600 on it (Crenel refuses to use it until then)`);
    }
    try {
      const data = JSON.parse(readFileSync(this.path, "utf8")) as unknown;
      return data && typeof data === "object" ? (data as Record<string, string>) : {};
    } catch {
      throw new Error(`${this.path} is not valid JSON`);
    }
  }

  private write(data: Record<string, string>): void {
    mkdirSync(join(this.path, ".."), { recursive: true });
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
    chmodSync(tmp, 0o600); // the umask cannot widen it
    renameSync(tmp, this.path);
  }

  /** The value and where it came from. The env var wins. */
  get(key: string, envVar?: string): { value: string | null; source: SecretSource } {
    const fromEnv = envVar ? this.env[envVar] : undefined;
    if (fromEnv && fromEnv.trim()) return { value: fromEnv.trim(), source: "env" };
    const v = this.read()[key];
    return typeof v === "string" && v ? { value: v, source: "file" } : { value: null, source: null };
  }

  set(key: string, value: string): void {
    const data = this.read();
    data[key] = value;
    this.write(data);
  }

  delete(key: string): boolean {
    const data = this.read();
    if (!(key in data)) return false;
    delete data[key];
    this.write(data);
    return true;
  }

  /** Every value in the file, to scrub them from messages. */
  values(): string[] {
    try { return Object.values(this.read()).filter((v) => typeof v === "string" && v.length >= 8); } catch { return []; }
  }
}

/** Only the scheme and host of a URL, e.g. https://hooks.slack.com/… */
export function maskUrl(url: string): string {
  try { const u = new URL(url); return `${u.protocol}//${u.host}/…`; } catch { return "(invalid URL)"; }
}

/** Replace every known secret (and any URL path or query) in a message. */
export function redact(text: string, secrets: (string | null | undefined)[]): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 8) out = out.split(s).join("[redacted]");
  // A webhook URL's path is its secret: never print one, whatever it is.
  return out.replace(/\b(https?):\/\/([^/\s"']+)\/[^\s"']*/gi, (_m, scheme: string, host: string) => `${scheme}://${host}/[redacted]`);
}
