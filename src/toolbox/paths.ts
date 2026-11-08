// Files shipped next to dist/ (or src/ in development): toolbox/ and its filter.
// The standalone executable embeds them instead (src/core/embedded.ts).

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { embeddedAsset, embeddedKeys, isEmbedded } from "../core/embedded.js";

const TOOLBOX_FILES = ["Dockerfile", "entrypoint.sh", "nuclei-filter.mjs", "nuclei-filter.d.mts"];

/** The toolbox/ directory shipped next to dist/ (or src/ in development). */
export function toolboxDir(): string {
  if (isEmbedded()) return extractEmbeddedToolbox();
  const here = dirname(fileURLToPath(import.meta.url));
  for (const c of [resolve(here, "../toolbox"), resolve(here, "../../toolbox")]) if (existsSync(join(c, "Dockerfile"))) return c;
  return resolve(here, "../toolbox");
}

// `docker build` needs a real directory: write the embedded toolbox once to a
// private temp folder named after its content, so a stale copy is never reused.
function extractEmbeddedToolbox(): string {
  const files = TOOLBOX_FILES.filter((f) => embeddedKeys().has(`toolbox/${f}`)).map((f) => [f, embeddedAsset(`toolbox/${f}`)!] as const);
  const h = createHash("sha256");
  for (const [f, b] of files) h.update(f).update(b);
  const dir = join(tmpdir(), `crenel-toolbox-${h.digest("hex").slice(0, 16)}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const [f, b] of files) writeFileSync(join(dir, f), b, { mode: f.endsWith(".sh") ? 0o755 : 0o644 });
  return dir;
}

/** sha256 (16 hex) of the nuclei template filter: a filtered set made by another filter version is not trusted. */
export function filterHash(): string {
  const bytes = embeddedAsset("toolbox/nuclei-filter.mjs") ?? readFileSync(join(toolboxDir(), "nuclei-filter.mjs"));
  return createHash("sha256").update(bytes).digest("hex").slice(0, 16);
}

/** nuclei templates, pinned like toolbox/Dockerfile (a test keeps both in sync). */
export const NUCLEI_TEMPLATES_VERSION = "10.5.1";
export const NUCLEI_TEMPLATES_SHA256 = "30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb";
export const NUCLEI_TEMPLATES_URL = `https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz`;
