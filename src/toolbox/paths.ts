// Files shipped next to dist/ (or src/ in development): toolbox/ and its filter.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The toolbox/ directory shipped next to dist/ (or src/ in development). */
export function toolboxDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const c of [resolve(here, "../toolbox"), resolve(here, "../../toolbox")]) if (existsSync(join(c, "Dockerfile"))) return c;
  return resolve(here, "../toolbox");
}

/** sha256 (16 hex) of the nuclei template filter: a filtered set made by another filter version is not trusted. */
export function filterHash(): string {
  return createHash("sha256").update(readFileSync(join(toolboxDir(), "nuclei-filter.mjs"))).digest("hex").slice(0, 16);
}

/** nuclei templates, pinned like toolbox/Dockerfile (a test keeps both in sync). */
export const NUCLEI_TEMPLATES_VERSION = "10.5.1";
export const NUCLEI_TEMPLATES_SHA256 = "30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb";
export const NUCLEI_TEMPLATES_URL = `https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz`;
