# Desktop app

`desktop/` is a [Tauri v2](https://v2.tauri.app) app: a native window around the Crenel console. It contains no second implementation of anything. The engine is the standalone executable of [RELEASE.md](RELEASE.md), bundled as a Tauri [sidecar](https://v2.tauri.app/develop/sidecar/) (`bundle.externalBin`), and the window shows the console that `crenel serve` already serves.

Bundles: Windows NSIS installer (per-user, no admin) and MSI; macOS `.dmg` for Apple silicon and Intel (two builds, not universal, because the sidecar is per architecture); Linux AppImage and `.deb` for x64 and arm64. Built by `.github/workflows/release.yml` only, see RELEASE.md.

## How it works

```
 Crenel app (Rust, Tauri)                          crenel sidecar (Node SEA)
 ┌──────────────────────────┐   spawn, cwd = project
 │ start page (local files) │ ───────────────────────▶ crenel serve --config crenel.config.yaml
 │  Choose a project folder │                              --port 0 --exit-with-stdin
 │  (dialog plugin, Rust)   │ ◀─── stdout: http://127.0.0.1:<port>/?token=<random>
 └──────────┬───────────────┘
            │ window navigates to the link
            ▼
 console page on http://127.0.0.1:<port>  (token traded for an HttpOnly SameSite=Strict cookie)
```

1. The start page (`desktop/ui`, plain HTML/JS, no framework) asks Rust to open a folder picker (`pick_project`, the dialog plugin called from Rust).
2. `open_project(dir)`: if `dir/crenel.config.yaml` is missing, the page offers to create the starter config (`crenel init`: read-only checks, no host tested until declared). Then Rust spawns `crenel serve` in that folder with `--port 0`: the OS picks a free port at bind time, so there is no window between "find a free port" and "listen on it". Rust reads the link the engine prints when it listens (that is the readiness signal, 45 s timeout, stderr shown on failure) and returns it.
3. The page navigates to the link. The console swaps the token for its cookie exactly as in a browser.
4. File > Open project (Ctrl/Cmd+O) stops the engine and returns to the start page. If the engine stops on its own, the window comes back to the start page with its exit code and last stderr lines.
5. When the app exits, Rust kills the engine. If the app itself is killed, the engine's stdin (a pipe held by the app) closes and `--exit-with-stdin` makes it stop: no orphan server keeps the port and the token.

`CRENEL_PROJECT=<folder>` opens that folder at start (used by the CI screenshot).

## Security model

- **The web never gets the shell.** The sidecar is spawned from Rust with fixed arguments. No capability grants `shell:*`, `fs:*`, `http:*` or `dialog:*` to any page; the shell and dialog plugins are only used from Rust.
- **One local capability.** `capabilities/default.json` applies to the window's local pages only and grants `core:app:allow-version`. The console is on `http://127.0.0.1:<port>`, a remote origin for Tauri, and no capability lists a remote URL, so it has no IPC at all.
- **App commands check their caller.** `pick_project`, `open_project` and `initial_project` refuse to answer unless the calling webview is on the app's own start page (`tauri://localhost` or `http://tauri.localhost` on Windows).
- **Navigation is pinned.** `on_navigation` allows only the start page and `http://127.0.0.1:<current engine port>`. A link to any other site does nothing in the window.
- **CSP.** The start page: `default-src 'self'; script-src 'self'` and no inline script or style; `connect-src` only Tauri's IPC. The console keeps the CSP `crenel serve` sends.
- **The engine is unchanged.** Same 127.0.0.1 binding, random token, Host check against DNS rebinding, Origin check on writes, as documented for `crenel serve`. The token only travels on the sidecar's stdout pipe and in the first URL.
- **No updater.** The auto-updater is off (see below), so the app never downloads code.

## Build

CI only (`release.yml`): Rust stable, on Linux `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev patchelf`. By hand on a machine that has them:

```bash
pnpm --dir web install && pnpm --dir web build
node scripts/build-sea.mjs                       # Node >= 25.5
mkdir -p desktop/src-tauri/binaries
cp build/release/crenel desktop/src-tauri/binaries/crenel-$(rustc --print host-tuple)   # add .exe on Windows
cd desktop && pnpm install && pnpm tauri build -- --locked
```

The bundles land in `desktop/src-tauri/target/release/bundle/`. Icons come from the mascot (`web/public/crenel-icon-1024.png`, regenerated with `pnpm tauri icon ../web/public/crenel-icon-1024.png -o src-tauri/icons`, desktop sizes kept).

On macOS the app is signed ad hoc (`signingIdentity: "-"`) with the hardened runtime off: Apple silicon needs a signature to run, and Node's JIT needs entitlements under the hardened runtime. Real signing is described in RELEASE.md.

## Unsigned app warnings

Same as RELEASE.md, "Unsigned binaries": on macOS right-click Crenel.app > *Open* > *Open*, or `xattr -cr /Applications/Crenel.app` after checking the `.dmg`'s SHA-256; on Windows *More info* > *Run anyway* (and "Unknown publisher" in the installer). On Linux the AppImage needs `chmod +x`, and FUSE 2 (`libfuse2`) or `APPIMAGE_EXTRACT_AND_RUN=1`.

## Enabling the updater later

Tauri's updater checks signatures made with a Tauri key pair, which is free (it is not an OS code signing certificate):

1. `pnpm tauri signer generate -w ~/.tauri/crenel.key` on the owner's machine. The private key and its password go into the repository secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, never into the repository.
2. Add `tauri-plugin-updater`, set `bundle.createUpdaterArtifacts: true`, and `plugins.updater` with the public key and the endpoint (`https://github.com/GlamgarOnDiscord/crenel/releases/latest/download/latest.json`).
3. Have the release workflow produce `latest.json` (tauri-action does it) and grant the updater permission to the start page only.

No key is generated or committed today.
