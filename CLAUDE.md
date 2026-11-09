# Crenel — notes for Claude

## What this is

Crenel attacks a SaaS you own before anyone else does: it finds exposed secrets and cross-account authorization bugs, **proves** each one with a replayable request, and turns the proof into a regression test. It is a hardening tool, not an attack tool — point it only at systems you own or are authorized to test. Free, local, no account, and it runs fully without an LLM.

## The one idea everything hangs on

**A finding is `proven` only when a deterministic validator replays it.** Everything else is a `lead`. Only proven findings fail a build. This is why Crenel has ~zero false positives — and it is the invariant you must never break to make a number look better.

## How it's built

TypeScript, strict, ESM. Node ≥ 20. No prettier/eslint in the repo — match the surrounding **compact, dense house style** by hand (one-line objects where the file does that). Tests are `node:test` (`node --import tsx --test`), schemas are `zod` with `.strict()`.

- `src/checks/` — the deterministic floor: ~42 checks (secrets, authz matrix, BaaS, headers, SSRF, …). No model needed.
- `src/agent/` — the free-exploration layer. `explore.ts` runs a model (via `src/agent/llm.ts`) through Crenel's own tool loop (`http.request`, `toolbox.run`, `claim.submit`, …); the model only emits JSON, it never runs its own tools. `validators.ts` holds the generic validators that decide what is `proven`. `llm.ts` has the model providers (claude CLI, OpenAI-compatible/Ollama/Anthropic API — keys from env only).
- `src/toolbox/` — optional Docker/WSL tools (nuclei, katana, trufflehog, httpx) behind a proxy that enforces the same perimeter; their output stays a lead until a validator replays it.
- `src/core/` — `scope.ts` (the allowlist, kill switch, active-mode gate), `net.ts` (the scoped fetch: declared hosts only, read methods unless active mode), `config.ts`.
- `web/` — the local agent console. `bench/` — targets with ground truth.
- `docs/ARCHITECTURE.md` lists every claim class and its oracle; `docs/EXPLORATION-ROADMAP.md` is the plan to raise recall.

Build `pnpm build`; engine tests `pnpm test`; a quick loop is `node --import tsx --test 'src/agent/*.test.ts'`. Always run `npx tsc --noEmit` before committing.

## How to improve the harness (raise recall)

Two honest tracks (see `docs/EXPLORATION-ROADMAP.md`):

1. **Add a generic validator.** For a new vulnerability class, write a **pure oracle** (its own file, e.g. `src/agent/cors.ts`) that decides from responses alone, with a **negative control**, then a thin `Validator` in `validators.ts` that sends the probes and calls the oracle, register it in `GENERIC_VALIDATORS`, add the claim class to `CLAIM_CLASSES` + `claimUrls` + the prompt in `explore.ts`, and document it in `ARCHITECTURE.md`. Unit-test the oracle and add one integration test in `explore-validators.test.ts`. Mirror an existing one (`massassign.ts`, `cors.ts`, `reuse.ts`).
2. **Give the model more reach**, not more license to assert: broader tools, higher budgets, more model providers — but proof stays gated by the validators.

## Never cheat, never overfit (hard rules)

These are not style preferences. Breaking one makes the benchmark a lie.

- **No target-specific signatures.** An oracle proves a *mechanism* (a differential, a reflection, a computation, a replay with a control) — never a string, path, or value that matches one bench's answer. If a change would only help one known target, it is overfitting; delete it.
- **Validate on targets the change has never seen.** A new validator must prove its class on benches it was not written against, with the same generic logic.
- **Never self-assert proof.** The model's confidence, a script's `[VULN]`, a tool's output — none of these set `proven`. Only a validator does.
- **Never loosen the scorer to match a finding.** If `bench/*/score.mjs` or a ground-truth regex misses a real finding, that is an honest miss — report it, do not widen the pattern to catch your own output.
- **Never inflate a score** by scoring against the home bench, counting leads as proven, or reporting a number you did not measure. The honest metric excludes the home bench (neutral targets only).
- **Secrets from the environment only.** Never write a key into config, logs, argv, or a committed file; pass the env-var *name*, read the value at call time.
- **Stay in the perimeter.** Every request goes through the scoped client; active (writing) probes need `allowActiveTesting` and touch only declared staging objects. Do not add a path that reaches an undeclared host.

## Conventions

- Git identity is the repo owner (`GlamgarOnDiscord`), never "Claude". **No `Co-Authored-By`, `Claude-Session`, or "Generated with Claude Code" trailers** in commits or PRs.
- Prefer a PR over pushing to the default branch. `tsc --noEmit` and the touched tests must pass before you commit.
- Keep diffs minimal: never run a formatter over existing files (the repo has none; it would explode the diff).
