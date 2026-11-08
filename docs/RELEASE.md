# Releases: the standalone executable

Crenel ships as one file per platform: `crenel-linux-x64`, `crenel-linux-arm64`, `crenel-windows-x64.exe`, `crenel-macos-arm64`, `crenel-macos-x64`. No Node.js, no `node_modules`, no clone. The engine, its data (the malware denylist, the nuclei template filter) and the built console (`web/dist`) are inside the file, so `crenel serve` works offline from it. The desktop app ([DESKTOP.md](DESKTOP.md)) bundles the same file as its sidecar.

## How it is built

[Node.js single executable applications](https://nodejs.org/api/single-executable-applications.html) (SEA), with `node --build-sea` (Node >= 25.5; the workflow pins Node 26.13.0 LTS). `scripts/build-sea.mjs`:

1. bundles `src/cli.ts` and its three dependencies (`yaml`, `zod`, `picocolors`) into one ES module with esbuild (through tsup, already a dev dependency). The dynamic `import()`s of the CLI become part of the bundle. A `require` shim is added for the CommonJS dependency's built-in `require("tty")`;
2. embeds `web/dist/**` and `toolbox/*` as SEA assets, plus a `manifest.json` of their keys;
3. runs `node --build-sea` with `mainFormat: "module"`, no code cache and no snapshot (both tie the blob to the build machine);
4. on macOS, signs the result ad hoc (`codesign --sign -`), which Apple silicon requires to run a modified binary at all.

At run time `src/core/embedded.ts` asks `node:sea` whether it runs from the executable. If so, the console is served from the embedded assets (`serveEmbedded` in `src/server/http.ts`, a path is only a lookup key, nothing on disk is read), `filterHash()` hashes the embedded `nuclei-filter.mjs`, and `crenel tools build` writes the embedded toolbox to a private temp folder named after its content for `docker build`. JSON data (`src/data/*.json`) and the filter's code are imported statically, so they are in the bundle itself. From a clone or from `dist/`, nothing changes: everything is read from the repo layout as before. The bench (`bench/`) is a development tool and is not embedded.

Native or optional dependencies: none. The three runtime dependencies are pure JavaScript; `esbuild` is only a build tool.

### Why Node SEA and not `bun build --compile` (or pkg, nexe, deno compile)

- **Same runtime as the tests.** The suite, the CI and every user of `pnpm crenel` run on Node. SEA is the very Node binary, so the executable behaves like what is tested. Bun reimplements `node:http`, `node:child_process` and `node:crypto` with known differences; Crenel's server, scoped HTTP client, proxy and subprocess handling (the toolbox, `claude -p`) are exactly the areas where a difference would be a security bug.
- **Official and maintained.** SEA is part of Node.js (Stability 1.1, active development), with assets (`node:sea`) and, since 25.5, a built-in `--build-sea` (no `postject` download). `pkg` is archived; `nexe` is unmaintained.
- **Trade-offs accepted.** Size (about 150 MB uncompressed, 47 MB gzipped, for linux-x64: it is the full Node binary; Bun would be about 60 to 100 MB). Each platform is built on its own runner (SEA cannot inject into a binary of another platform and then run it for the smoke test anyway). Stability 1.1 means the format can still change: the Node version is pinned.

## Build it locally

```bash
pnpm install && pnpm --dir web install && pnpm --dir web build
node scripts/build-sea.mjs                 # with Node >= 25.5; prints build/release/crenel
node scripts/smoke-binary.mjs build/release/crenel
```

The smoke test copies `examples/` to a temp folder and checks `crenel --version`, a `crenel scan` that proves the planted Stripe secret and the known-bad package (which needs the embedded data), and `crenel serve --port 0` answering on 127.0.0.1 (health, token-to-cookie exchange, the embedded console and one of its scripts, an authenticated API call), then stopping when its stdin closes.

## The release workflow

`.github/workflows/release.yml`, on GitHub-hosted runners only:

| Target | Runner |
|---|---|
| linux-x64 | `ubuntu-24.04` |
| linux-arm64 | `ubuntu-24.04-arm` |
| windows-x64 | `windows-2025` |
| macos-arm64 | `macos-15` |
| macos-x64 | `macos-15-intel` |

Each job builds the executable, runs the smoke test on it, then builds the desktop app around it. A `checksums` job writes `SHA256SUMS` over every file and creates [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) (`actions/attest-build-provenance`, Sigstore, free on public repositories; skipped while the repository is private, where they need GitHub Enterprise Cloud).

- **Dry run:** Actions > release > *Run workflow* (or `gh workflow run release.yml`). Everything is built and tested, the files are attached to the run as artifacts. Nothing is published.
- **Release:** push a tag `vX.Y.Z` whose version equals `package.json`, `src/version.ts` and `desktop/src-tauri/tauri.conf.json` (the workflow checks). The `publish` job creates a **draft** release with every file and `SHA256SUMS`; the owner reviews and publishes it.

Least privilege: the workflow's default token has no permission; `build` reads the repository, `checksums` adds `id-token: write` and `attestations: write`, only `publish` gets `contents: write`. Every action is pinned by commit SHA, checkout does not persist credentials, and installs run with `--ignore-scripts`.

Cost: the runners are GitHub's standard hosted runners. On a public repository they are free. On a private one, minutes count against the plan's included minutes (macOS minutes count ten times).

## Unsigned binaries

Nothing is code signed, because signing costs money (an Apple Developer ID is 99 USD a year, a Windows code signing certificate more). What users see:

- **macOS (Gatekeeper):** a downloaded file carries the `com.apple.quarantine` attribute and macOS refuses to open it ("cannot be opened because the developer cannot be verified", or "is damaged" on Apple silicon). After checking the SHA-256: `xattr -d com.apple.quarantine ./crenel-macos-arm64` for the command-line file, `xattr -cr /Applications/Crenel.app` for the app, or right-click > *Open* > *Open*, or System Settings > Privacy & Security > *Open Anyway*. The binaries are ad-hoc signed, which Apple silicon requires, but that does not satisfy Gatekeeper.
- **Windows (SmartScreen):** "Windows protected your PC" for a file without reputation: *More info* > *Run anyway*. The installer (NSIS or MSI) shows "Unknown publisher".
- **Linux:** nothing; `chmod +x` the file.

Verify first: `SHA256SUMS` from the same release, and once the repository is public, `gh attestation verify <file> -R GlamgarOnDiscord/crenel`, which proves the file was built by this workflow from this repository.

### Adding signing later

- **macOS:** an Apple Developer ID Application certificate and notarization. In the workflow: import the certificate into a temporary keychain from encrypted secrets, `codesign --sign "Developer ID Application: ..." --options runtime --entitlements entitlements.plist` (Node needs `com.apple.security.cs.allow-jit`, `allow-unsigned-executable-memory` and `disable-library-validation` under the hardened runtime), then `xcrun notarytool submit --wait` and `xcrun stapler staple` for the `.dmg`. For the desktop app, Tauri does all of it from `APPLE_CERTIFICATE`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`/`APPLE_PASSWORD`/`APPLE_TEAM_ID` (set `bundle.macOS.signingIdentity` and turn `hardenedRuntime` back on with those entitlements).
- **Windows:** an OV/EV certificate or Azure Trusted Signing; `signtool sign /fd SHA256 /tr <timestamp url> /td SHA256` on the `.exe`, or Tauri's `bundle.windows.signCommand`.
- **Alternative to certificates:** keep the attestations (already wired) and document `gh attestation verify`; free, but it does not remove the OS warnings.
