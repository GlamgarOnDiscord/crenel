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

/**
 * True if the match at `index` sits inside a line comment. A pattern-matching
 * check should skip these: a warning or doc comment that *names* a bad pattern is
 * not the bad pattern, and flagging it is exactly the noise the tool avoids.
 * Handles the common cases: a line whose first non-space is // # or * (JSDoc), or
 * a // earlier on the same line. Not a full parser; block comments can slip by.
 */
export function isCommentedAt(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf("\n", index - 1) + 1;
  const before = text.slice(lineStart, index);
  const trimmed = before.trimStart();
  if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("/*")) return true;
  // an inline // that is not inside a string (cheap heuristic: no quote after it)
  const sl = before.indexOf("//");
  if (sl >= 0) return true;
  return false;
}
