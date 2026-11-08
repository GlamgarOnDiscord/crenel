// Files embedded in the standalone executable (Node.js single executable
// application, see docs/RELEASE.md). When Crenel runs from the single file there
// is no repo layout next to it: the console (web/dist) and the toolbox files
// are read from the executable's own assets instead of the disk.
//
// Keys: "web/<path inside web/dist>" and "toolbox/<file>". The list of keys is
// stored as the "manifest.json" asset (an array of strings) so it does not
// depend on sea.getAssetKeys(), which only exists in newer Node versions.

import { createRequire } from "node:module";

interface SeaApi {
  isSea(): boolean;
  getAsset(key: string): ArrayBuffer;
}

let sea: SeaApi | null | undefined;

function api(): SeaApi | null {
  if (sea !== undefined) return sea;
  sea = null;
  try {
    const mod = createRequire(import.meta.url)("node:sea") as SeaApi;
    if (mod.isSea()) sea = mod;
  } catch {
    /* node:sea missing (old Node) or not a single executable */
  }
  return sea;
}

/** True when running from the standalone executable. */
export function isEmbedded(): boolean {
  return api() !== null;
}

let keys: Set<string> | undefined;

/** Every embedded asset key (empty outside the standalone executable). */
export function embeddedKeys(): Set<string> {
  if (keys) return keys;
  keys = new Set();
  const raw = embeddedAsset("manifest.json");
  if (raw) for (const k of JSON.parse(raw.toString("utf8")) as string[]) keys.add(k);
  return keys;
}

/** An embedded asset's bytes, or null when absent or not in the executable. */
export function embeddedAsset(key: string): Buffer | null {
  const s = api();
  if (!s) return null;
  try {
    return Buffer.from(s.getAsset(key));
  } catch {
    return null;
  }
}
