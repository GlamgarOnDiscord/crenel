# Contributing

## Engine (root)

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm demo        # scan the bundled vulnerable example
```

- Checks go in `src/checks/`, are deterministic and read-only, and are added to
  `src/core/registry.ts`. Every network request goes through `safeFetch`
  (`src/core/net.ts`); never call `fetch` directly from a check.
- A finding is `proven` only via a deterministic match or a replayable probe.
  Give proven findings a `replay` string. Leads are `unproven`.
- Add a unit test next to new code (`*.test.ts`, run by `pnpm test`).
- Scope and safety live in code, not prompts. Do not add a way to reach a host
  outside `allowedHosts`, and keep active (non read-only) checks behind the gate.

## Console (`web/`)

```bash
cd web
pnpm install
pnpm dev
```

- One global design system in `web/src/styles`; components stay clean markup.
- Icons from `lucide-react`. Fonts: Mona Sans (display), Instrument Sans (UI),
  JetBrains Mono (mono). Keep the single dark theme.

## Commits

Conventional, imperative subject. Do not commit secrets or `node_modules`.
Run `pnpm build` and `pnpm test` before opening a PR.
