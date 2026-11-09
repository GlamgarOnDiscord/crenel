// On-disk state of a project, next to its config, in `.crenel/`:
//
//   runs/<id>.jsonl   one append-only journal per run (the source of truth)
//   findings.json     current findings, merged run after run, with verdicts
//   authz.json        the last authorization matrix that was observed
//   tests.json        regression tests generated, and regression.test.ts
//   audit.jsonl       one line per scan, plus every probe sent without asking
//   baseline.json     the snapshot `diff` compares against
//
// Everything is plain JSON so a human (or another tool) can read it. Nothing
// here is written outside `.crenel/`: Crenel never touches the scanned project.

import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, readdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { Finding } from "../core/types.js";
import type { Evidence } from "./validators.js";

export interface StoredFinding extends Finding {
  /** URL-safe id for the console (engine ids carry paths and URLs). */
  uid: string;
  firstSeen: string;
  lastSeen: string;
  /** The validator that decided the state, or null when none exists for its class. */
  validator?: string | null;
  verdict?: string;
  evidence?: Evidence;
  /** A model's opinion, kept apart from the state. Never proof. */
  advice?: string;
  run?: string;
}

export interface AuthzMatrix {
  at: string;
  run: string;
  resources: { id: string; label: string; route: string }[];
  actors: { id: string; label: string; role: string; cells: Record<string, number | undefined> }[];
  /** Replay command per cell, keyed "actor:resource". */
  replay: Record<string, string>;
  notes: string[];
}

export interface StoredTest {
  uid: string;
  name: string;
  check: string;
  status: "draft";
  at: string;
}

export interface ConsoleMeta {
  archived: string[];
  ignored: Record<string, { at: string; reason: string }>;
}

export const uidOf = (id: string) => "f-" + createHash("sha256").update(id).digest("hex").slice(0, 10);

function readJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return fallback;
  }
}

// Write to a temp file then rename, so a crash never leaves half a JSON file.
function writeJson(path: string, data: unknown): void {
  writeFileSync(path + ".tmp", JSON.stringify(data, null, 2));
  renameSync(path + ".tmp", path);
}

export class StateStore {
  constructor(readonly dir: string) {
    mkdirSync(join(dir, "runs"), { recursive: true });
  }

  get auditPath() { return join(this.dir, "audit.jsonl"); }
  get grantsPath() { return join(this.dir, "grants.json"); }
  get baselinePath() { return join(this.dir, "baseline.json"); }
  get regressionPath() { return join(this.dir, "regression.test.ts"); }
  runPath(id: string) { return join(this.dir, "runs", `${id}.jsonl`); }
  runIds(): string[] {
    return readdirSync(join(this.dir, "runs")).filter((f) => f.endsWith(".jsonl")).map((f) => f.slice(0, -6));
  }

  findings(): { updatedAt?: string; checksRun: string[]; items: StoredFinding[] } {
    return readJson(join(this.dir, "findings.json"), { checksRun: [] as string[], items: [] as StoredFinding[] });
  }

  /**
   * Merge a run's findings. Only checks that ran are touched: a previously
   * proven finding that a check no longer reports becomes "fixed"; a lead that
   * disappears is dropped; findings of checks that did not run stay as they were.
   */
  mergeFindings(run: string, found: (Finding & Partial<StoredFinding>)[], checksRun: string[]): StoredFinding[] {
    const now = new Date().toISOString();
    const cur = this.findings();
    const ran = new Set(checksRun);
    const byId = new Map(cur.items.map((f) => [f.id, f]));
    const next: StoredFinding[] = [];
    const seen = new Set<string>();
    for (const f of found) {
      const prev = byId.get(f.id);
      next.push({ ...prev, ...f, uid: uidOf(f.id), firstSeen: prev?.firstSeen ?? now, lastSeen: now, run, advice: prev?.advice });
      seen.add(f.id);
    }
    for (const f of cur.items) {
      if (seen.has(f.id)) continue;
      if (!ran.has(f.check)) { next.push(f); continue; }
      if (f.state === "proven" || f.state === "fixed") next.push({ ...f, state: "fixed" });
    }
    writeJson(join(this.dir, "findings.json"), { updatedAt: now, checksRun: [...new Set([...cur.checksRun, ...checksRun])], items: next });
    return next;
  }

  setAdvice(uid: string, advice: string): StoredFinding | null {
    const cur = this.findings();
    const f = cur.items.find((x) => x.uid === uid);
    if (!f) return null;
    f.advice = advice;
    writeJson(join(this.dir, "findings.json"), cur);
    return f;
  }

  authz(): AuthzMatrix | null { return readJson<AuthzMatrix | null>(join(this.dir, "authz.json"), null); }
  saveAuthz(m: AuthzMatrix): void { writeJson(join(this.dir, "authz.json"), m); }

  tests(): StoredTest[] { return readJson<StoredTest[]>(join(this.dir, "tests.json"), []); }
  saveTests(list: StoredTest[], file: string): void {
    writeJson(join(this.dir, "tests.json"), list);
    writeFileSync(this.regressionPath, file);
  }

  /**
   * Console bookkeeping that is not a finding's truth: runs the user archived
   * and findings the user chose to ignore in the console (with a reason).
   * The validators still decide a finding's state; an ignored finding stays
   * in findings.json and in every report, it is only shown apart.
   */
  consoleMeta(): ConsoleMeta { return readJson<ConsoleMeta>(join(this.dir, "console.json"), { archived: [], ignored: {} }); }
  setArchived(run: string, archived: boolean): void {
    const m = this.consoleMeta();
    m.archived = archived ? [...new Set([...m.archived, run])] : m.archived.filter((x) => x !== run);
    writeJson(join(this.dir, "console.json"), m);
  }
  setIgnored(uid: string, ignored: { at: string; reason: string } | null): void {
    const m = this.consoleMeta();
    if (ignored) m.ignored[uid] = ignored; else delete m.ignored[uid];
    writeJson(join(this.dir, "console.json"), m);
  }

  appendAudit(entry: Record<string, unknown>): void {
    appendFileSync(this.auditPath, JSON.stringify(entry) + "\n");
  }
  audit(): Record<string, unknown>[] {
    if (!existsSync(this.auditPath)) return [];
    const out: Record<string, unknown>[] = [];
    for (const l of readFileSync(this.auditPath, "utf8").split("\n")) {
      if (!l.trim()) continue;
      try { out.push(JSON.parse(l)); } catch { /* skip a torn line */ }
    }
    return out;
  }
}

// Hosts the user allowed "Toujours pour cet hôte", kept in .crenel/grants.json
// so the choice survives a restart. A grant only skips the question: the gate
// still enforces the declared perimeter, and removing a target drops its grant.
export class GrantSet extends Set<string> {
  constructor(private readonly path: string) {
    super();
    try {
      const saved = JSON.parse(readFileSync(path, "utf8")) as unknown;
      if (Array.isArray(saved)) for (const h of saved) if (typeof h === "string") super.add(h.toLowerCase());
    } catch { /* no grants yet */ }
  }
  override add(host: string): this {
    const h = host.toLowerCase();
    if (!this.has(h)) { super.add(h); this.save(); }
    return this;
  }
  override delete(host: string): boolean {
    const gone = super.delete(host.toLowerCase());
    if (gone) this.save();
    return gone;
  }
  private save(): void {
    writeFileSync(this.path, JSON.stringify([...this].sort(), null, 2) + "\n");
  }
}
