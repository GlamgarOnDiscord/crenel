// Append-only event journal for an agent run (P0 #5 of the research backlog).
//
// One JSON line per event, written with an append and never rewritten. Each
// line carries a sequence number and a hash chained to the previous line, so a
// truncated or edited journal is detectable (`verifyJournal`). The journal is
// the source of truth for a run: the live stream (SSE) replays it from any
// sequence number, and the run's state after a restart is rebuilt by reading
// it again (`replayRun`), not by trusting memory. The same events feed the
// monitor that can stop a run.

import { appendFileSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import { redactDeep } from "../core/access.js";

export const JOURNAL_VERSION = 1;

export interface JournalEntry<T = unknown> {
  v: number;
  seq: number;
  ts: string;
  run: string;
  type: string;
  data: T;
  /** Hash of the previous entry ("" for the first one). */
  prev: string;
  /** sha256(prev + canonical body), hex. */
  hash: string;
}

function hashOf(prev: string, body: Omit<JournalEntry, "hash" | "prev">): string {
  return createHash("sha256").update(prev).update(JSON.stringify(body)).digest("hex");
}

export class Journal {
  private seq = 0;
  private last = "";
  private readonly entries: JournalEntry[] = [];
  private readonly subs = new Set<(e: JournalEntry) => void>();

  constructor(readonly path: string, readonly run: string) {
    mkdirSync(dirname(path), { recursive: true });
    // Resume an existing journal: continue its sequence and hash chain.
    if (existsSync(path)) {
      for (const e of readJournal(path)) {
        this.entries.push(e);
        this.seq = e.seq;
        this.last = e.hash;
      }
    }
  }

  append<T>(type: string, raw: T): JournalEntry<T> {
    // A registered secret (an Access service token echoed by a body) never reaches the journal.
    const data = redactDeep(raw);
    const body = { v: JOURNAL_VERSION, seq: this.seq + 1, ts: new Date().toISOString(), run: this.run, type, data };
    const entry: JournalEntry<T> = { ...body, prev: this.last, hash: hashOf(this.last, body) };
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
    this.seq = entry.seq;
    this.last = entry.hash;
    this.entries.push(entry);
    for (const fn of this.subs) {
      try { fn(entry); } catch { /* a broken subscriber never breaks the run */ }
    }
    return entry;
  }

  /** Entries with seq > after, in order. */
  since(after = 0): JournalEntry[] {
    return this.entries.filter((e) => e.seq > after);
  }

  subscribe(fn: (e: JournalEntry) => void): () => void {
    this.subs.add(fn);
    return () => this.subs.delete(fn);
  }

  get lastSeq(): number {
    return this.seq;
  }
}

/** Read a journal file. A torn last line (crash mid-write) is skipped, not fatal. */
export function readJournal(path: string): JournalEntry[] {
  if (!existsSync(path)) return [];
  const out: JournalEntry[] = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as JournalEntry);
    } catch {
      break; // only the tail can be torn; anything after it is untrusted
    }
  }
  return out;
}

/** Check the hash chain. Returns the first bad sequence number, if any. */
export function verifyJournal(entries: JournalEntry[]): { ok: boolean; brokenAt?: number } {
  let prev = "";
  let expectSeq = 1;
  for (const e of entries) {
    const { hash, prev: p, ...body } = e;
    if (p !== prev || e.seq !== expectSeq || hashOf(prev, body) !== hash) return { ok: false, brokenAt: e.seq };
    prev = hash;
    expectSeq++;
  }
  return { ok: true };
}

/** The state of a run, rebuilt from its journal alone. */
export interface RunSummary {
  id: string;
  title: string;
  prompt: string;
  mode: string;
  startedAt: string;
  endedAt?: string;
  status: "running" | "waiting" | "done" | "stopped" | "error";
  outcome?: string;
  proven: number;
  leads: number;
  fixed: number;
  probes: number;
  goal?: { text: string; status: string; verified: boolean };
}

export function replayRun(entries: JournalEntry[]): RunSummary | null {
  const start = entries.find((e) => e.type === "run.start") as JournalEntry<{ prompt: string; title: string; mode: string }> | undefined;
  if (!start) return null;
  const s: RunSummary = {
    id: start.run, title: start.data.title, prompt: start.data.prompt, mode: start.data.mode,
    startedAt: start.ts, status: "running", proven: 0, leads: 0, fixed: 0, probes: 0,
  };
  for (const e of entries) {
    const d = e.data as Record<string, unknown>;
    if (e.type === "phase") s.status = d.phase === "waiting" ? "waiting" : "running";
    if (e.type === "net" && d.status !== undefined) s.probes++;
    if (e.type === "results") { s.proven = Number(d.proven ?? 0); s.leads = Number(d.leads ?? 0); s.fixed = Number(d.fixed ?? 0); }
    if (e.type === "goal.start") s.goal = { text: String(d.text), status: "active", verified: false };
    if (e.type === "goal.end" && s.goal) { s.goal.status = String(d.outcome); s.goal.verified = !!d.verified; }
    if (e.type === "run.end") {
      s.endedAt = e.ts;
      s.outcome = String(d.outcome);
      s.status = d.outcome === "stopped" ? "stopped" : d.outcome === "error" ? "error" : "done";
    }
  }
  return s;
}
