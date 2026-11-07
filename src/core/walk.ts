// Shared, bounded file walk for the filesystem checks. One place for the
// skip-directory policy and the depth cap, so each check declares only what it
// wants to keep rather than re-implementing the traversal.

import { readdirSync } from "node:fs";
import { join } from "node:path";

export interface WalkOptions {
  /** Directory names to never descend into. Defaults to node_modules and .git. */
  skipDirs?: Set<string>;
  /** Maximum recursion depth. */
  maxDepth?: number;
  /** Keep a file when this returns true. Receives the basename and full path. */
  accept?: (name: string, full: string) => boolean;
}

const DEFAULT_SKIP = new Set(["node_modules", ".git"]);

/** Yield every file under `dir` that `accept` keeps, skipping `skipDirs`. */
export function* walkFiles(dir: string, opts: WalkOptions = {}): Generator<string> {
  const skip = opts.skipDirs ?? DEFAULT_SKIP;
  const maxDepth = opts.maxDepth ?? 12;
  const accept = opts.accept ?? (() => true);
  function* rec(d: string, depth: number): Generator<string> {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = join(d, e.name);
      if (e.isDirectory()) {
        if (!skip.has(e.name)) yield* rec(full, depth + 1);
      } else if (e.isFile() && accept(e.name, full)) {
        yield full;
      }
    }
  }
  yield* rec(dir, 0);
}

/** Extension of a basename, including the dot, or "" if none. */
export function extOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.slice(dot) : "";
}
