#!/usr/bin/env node
// Build the standalone `crenel` executable for the current platform as a
// Node.js single executable application (https://nodejs.org/api/single-executable-applications.html).
//
//   1. bundle src/cli.ts and its dependencies into one ES module (esbuild, via tsup);
//   2. embed the built console (web/dist) and toolbox/ as SEA assets, with a
//      manifest.json listing their keys (read by src/core/embedded.ts);
//   3. `node --build-sea` (Node >= 25.5) copies the running node binary and
//      injects the bundle and the assets;
//   4. macOS only: ad-hoc signature (codesign --sign -), required to run on arm64.
//
// Usage: pnpm build:web first, then `node scripts/build-sea.mjs [--out path]`.
// Prints the path of the executable. No network, no install scripts.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "tsup";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const work = join(root, "build", "sea");
const exe = process.platform === "win32" ? ".exe" : "";
const outArg = process.argv.indexOf("--out");
const output = outArg > 0 ? resolve(process.argv[outArg + 1]) : join(root, "build", "release", `crenel${exe}`);

const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 25 || (major === 25 && minor < 5)) {
  console.error(`node --build-sea needs Node.js >= 25.5 (this is ${process.versions.node}); the release workflow pins Node 26 LTS.`);
  process.exit(1);
}

const webDist = join(root, "web", "dist");
if (!existsSync(join(webDist, "index.html"))) {
  console.error("web/dist/index.html is missing: build the console first (pnpm --dir web build).");
  process.exit(1);
}

rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });
mkdirSync(dirname(output), { recursive: true });

// 1. One ES module. CommonJS dependencies (picocolors) call require() on
// built-ins, which an ES module bundle does not have: give it one.
await build({
  config: false,
  entry: { crenel: "src/cli.ts" },
  outDir: work,
  format: ["esm"],
  platform: "node",
  target: "node22",
  bundle: true,
  noExternal: [/.*/],
  splitting: false,
  sourcemap: false,
  minify: false,
  dts: false,
  clean: false,
  silent: true,
  outExtension: () => ({ js: ".mjs" }),
  banner: { js: 'import { createRequire as __crenelCreateRequire } from "node:module"; const require = __crenelCreateRequire(import.meta.url);' },
});
const main = join(work, "crenel.mjs");

// 2. Assets: the console and the toolbox, keyed by a "/" path.
function walk(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const assets = {};
for (const f of walk(webDist)) assets["web/" + relative(webDist, f).split(sep).join("/")] = f;
for (const n of ["Dockerfile", "entrypoint.sh", "nuclei-filter.mjs", "nuclei-filter.d.mts"]) assets[`toolbox/${n}`] = join(root, "toolbox", n);
const manifest = join(work, "manifest.json");
writeFileSync(manifest, JSON.stringify(Object.keys(assets).sort()));
assets["manifest.json"] = manifest;

// 3. Build the executable from this node binary. No code cache or snapshot:
// both are tied to the exact build machine and gain little for a CLI.
const seaConfig = join(work, "sea-config.json");
writeFileSync(seaConfig, JSON.stringify({
  main,
  mainFormat: "module",
  output,
  disableExperimentalSEAWarning: true,
  useCodeCache: false,
  useSnapshot: false,
  assets,
}, null, 2));
rmSync(output, { force: true });
execFileSync(process.execPath, ["--build-sea", seaConfig], { stdio: "inherit" });

// 4. macOS refuses to run an arm64 binary whose signature no longer matches.
if (process.platform === "darwin") execFileSync("codesign", ["--sign", "-", "--force", output], { stdio: "inherit" });

console.log(output);
