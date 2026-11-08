<div align="center">

<img src="brand/readme-banner.png" alt="Crenel — the jackdaw that proves the bug it found" width="880">

# Crenel

**Attack your own app before anyone else does.**

Crenel finds exposed secrets and cross-account authorization bugs in your SaaS,<br>
proves each one with a replayable request, and turns it into a regression test.

[![License: MIT](https://img.shields.io/badge/license-MIT-F2B01E?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-1b1d2a?style=flat-square&logo=node.js&logoColor=white)](package.json)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-1b1d2a?style=flat-square&logo=typescript&logoColor=white)](tsconfig.json)
[![Checks](https://img.shields.io/badge/checks-42-1b1d2a?style=flat-square)](docs/CHECKS.md)
[![Tests](https://img.shields.io/badge/tests-377%20passing-1b1d2a?style=flat-square)](#contributing)
[![Platforms](https://img.shields.io/badge/macOS%20%C2%B7%20Linux%20%C2%B7%20Windows-1b1d2a?style=flat-square)](#quick-start)

Free · local · no account · no LLM required

<img src="brand/cli-output.png" alt="crenel scan output: proven findings, leads, and the CI verdict" width="760">

</div>

> [!NOTE]
> **Early days.** Crenel is at the very beginning: it works and is tested, but the
> checks, the exploration validators and the docs are still growing, APIs may
> change, and some capabilities depend on optional tooling. Expect rough edges,
> and please file issues — feedback now shapes where it goes.

## Why

Apps shipped fast, often with AI, keep making the same mistakes: a server key in the client bundle, a Supabase table without RLS, one account able to read another's data. Scanners report hundreds of maybes. Crenel reports what it can **prove**.

- **Proof, not noise.** A finding is `proven` only when a deterministic validator replays it. Everything else is a `lead`. Only proven findings fail your build.
- **Authorization done right.** Two test accounts, a declarative matrix, and a response-body oracle with a negative control. A `200` alone is never a leak.
- **Fixed stays fixed.** Every proven flaw becomes a test in your CI.
- **Scope in code, not in a prompt.** Crenel only reaches hosts you declare. Active probes are opt-in. Writes (active mode) go only to staging objects you declare, and each one is restored or reported.

## Install

Every release on [GitHub Releases](https://github.com/GlamgarOnDiscord/crenel/releases) carries a single-file `crenel` executable (no Node.js needed; the console is inside it) and a desktop app:

| Platform | Command-line executable | Desktop app |
|---|---|---|
| Linux x64 | `crenel-linux-x64` | `Crenel_<version>_amd64.AppImage`, `.deb` |
| Linux arm64 | `crenel-linux-arm64` | `Crenel_<version>_aarch64.AppImage`, `_arm64.deb` |
| Windows x64 | `crenel-windows-x64.exe` | `Crenel_<version>_x64-setup.exe`, `_x64_en-US.msi` |
| macOS Apple silicon | `crenel-macos-arm64` | `Crenel_<version>_aarch64.dmg` |
| macOS Intel | `crenel-macos-x64` | `Crenel_<version>_x64.dmg` |

Download links follow `https://github.com/GlamgarOnDiscord/crenel/releases/download/<tag>/<file>`. Check the file against the release's `SHA256SUMS` before running it:

```bash
TAG=v0.1.0; F=crenel-linux-x64
curl -fLO "https://github.com/GlamgarOnDiscord/crenel/releases/download/$TAG/$F"
curl -fLO "https://github.com/GlamgarOnDiscord/crenel/releases/download/$TAG/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS      # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
chmod +x "$F" && ./"$F" --version
```

On Windows (PowerShell): `(Get-FileHash .\crenel-windows-x64.exe -Algorithm SHA256).Hash` and compare with its line in `SHA256SUMS`. Once the repository is public, `gh attestation verify <file> -R GlamgarOnDiscord/crenel` also checks the build provenance.

**The binaries are not code signed** (signing costs money). Windows SmartScreen shows "Windows protected your PC": *More info* then *Run anyway*. macOS Gatekeeper refuses an app downloaded from the internet: right-click the app, *Open*, then *Open* again (or System Settings > Privacy & Security > *Open Anyway*); for the command-line file, `xattr -d com.apple.quarantine ./crenel-macos-arm64`; for the app, `xattr -cr /Applications/Crenel.app`. Only do this for a file whose checksum matched. Details in [docs/RELEASE.md](docs/RELEASE.md) and [docs/DESKTOP.md](docs/DESKTOP.md).

## Quick start

> Not on npm yet. Run it from a clone.

```bash
pnpm install && pnpm build
pnpm demo                      # offline scan of the bundled vulnerable app
```

On your project:

```bash
pnpm crenel init               # writes crenel.config.yaml
pnpm crenel scan               # point projectDir at your build, list the hosts you own
pnpm crenel generate-tests     # one regression test per finding
```

## What it catches

| | Checks |
| --- | --- |
| **Secrets** | `exposed-secrets` server keys in the bundle (Stripe, AWS, OpenAI, Anthropic, Supabase `service_role`…) · `live-bundle` the same on every JS chunk your live site serves · `git-history` keys deleted from the code but not from the history · `public-env` · `committed-env` · `committed-credentials` · `sourcemaps` |
| **Authorization** | `authz-matrix` account A reaching account B's objects, anonymous access, proven live on staging |
| **Active mode** (opt-in, staging only) | `authz-write` account A changing or deleting account B's objects, proven by B's own read, then restored · `mass-assignment` role, plan or credits accepted in a user's own update · `race` a coupon, credits or an invite used more than allowed by concurrent requests |
| **BaaS & storage** | `baas-exposure` Supabase or Firebase tables readable with the public key (missing RLS) · `supabase-rpc` functions that return data to anonymous visitors · `supabase-functions` Edge Functions acting as service role for anyone · `storage-buckets` S3, R2, GCS buckets anyone can list |
| **Supply chain** | `dependency-risk` known-malware versions, install hooks · `ci-hardening` · `dockerfile` · `mcp-surface` |
| **Server code** | `webhook-signature` unverified Stripe, GitHub or Clerk webhooks · `ssrf` fetching a URL from the request · `business-logic` prices, plans or roles the browser sends (hypotheses) |
| **Deployed site** | `exposed-files` .env, .git, dumps and debug pages your host serves by mistake · `graphql` introspection open to anyone · `open-redirect` login links that bounce anywhere · `next-middleware` CVE-2025-29927 auth bypass · `auth-variants` protected routes reachable through .rsc, //, case · `next-image` image optimizer that fetches any host · `api-docs` OpenAPI/Swagger definition served in production · `subdomain-takeover` · `transport` HTTPS and certificate expiry · `dev-server` · `vercel-preview` · `cache-deception` private pages served from the CDN cache · `cache-poisoning` (opt-in) unkeyed headers stored by the cache |
| **AI stack** | `ai-infra` Ollama, model APIs, Qdrant, Chroma, Weaviate, Flowise, Langflow, MCP servers open without auth |
| **Auth** | `auth-config` open sign-up without email confirmation, published auth API |
| **Mail** | `email-dns` SPF and DMARC, so nobody sends password resets as you |
| **Config** | `headers` · `jwt-config` · `tls-verification` · `cloudflare-audit` |

Details and fixes: [`docs/CHECKS.md`](docs/CHECKS.md).

**Let a model read your chunks too.** `crenel review-bundle` hands every JS chunk the live site serves to `claude -p` and lists what no pattern catches: internal endpoints, browser-only role checks, hidden routes, debug code. Each item quotes the served file verbatim or is dropped, and stays a lead until a deterministic check replays it.

## Web console

```bash
node dist/cli.js serve --config crenel.config.yaml --open
```

A local agent console on `127.0.0.1`: start a task, follow each tool step by step, approve probes (or run in *Bypass*, still inside the perimeter), and set a **goal** the agent works toward until it is proven. See [`docs/CONSOLE.md`](docs/CONSOLE.md).

## In CI

```yaml
- uses: GlamgarOnDiscord/crenel@<sha>
  with:
    config: crenel.config.yaml
    fail-on: high          # proven findings only
    pr-comment: "true"     # optional, needs pull-requests: write
```

Uploads SARIF to GitHub code scanning and can keep one PR comment of the proven findings, with the workflow's own `GITHUB_TOKEN`. JUnit and JSON outputs too: [`docs/USAGE.md`](docs/USAGE.md).

## Integrations

Slack (Incoming Webhook, Block Kit) for new proven critical or high findings, and webhooks signed with HMAC-SHA256 for every new proven finding and finished run. Destinations sit in their own allowlist, never scan targets; secrets stay in an env var or `.crenel/secrets.json` (0600) and out of every log. Set them from the console or the CLI: [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

## Safety

Every request goes through a scoped client that refuses undeclared hosts, private addresses and unsafe methods, and re-checks each redirect. The [active mode](docs/CHECKS.md#active-mode) checks write, so they need `allowActiveTesting` and their own `enabled: true`, touch only declared staging objects with test accounts, and list every write and whether it was restored. Point Crenel only at systems you own or are authorised to test. It is a hardening tool, not an attack tool. [`SECURITY.md`](SECURITY.md)

Optional toolbox: `crenel tools build` then `crenel tools nuclei|katana|trufflehog|httpx` runs those tools in a Docker container whose only network exit is a proxy applying the same perimeter (their results stay leads until a Crenel validator replays them). What it filters, and what it cannot filter over HTTPS: [`docs/TOOLBOX.md`](docs/TOOLBOX.md). On Windows without Docker, `options.toolbox.backend: wsl` runs the same allowlisted tools from a WSL distro (Kali by default; `crenel tools install --wsl` asks before installing them as root, the tools run as your normal user), with weaker confinement spelled out in the same doc.

## Measured, not claimed

[`bench/`](bench/) holds small multi-tenant targets with ground truth: real flaws to find and decoys that must stay quiet. `node bench/run.mjs` scores Crenel, misses included. Other tools get adapters next.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) · `pnpm test` (engine) · `cd web && pnpm test` (console) · [Roadmap](docs/ROADMAP.md)

<div align="center"><sub>MIT · made for founders who ship fast</sub></div>
