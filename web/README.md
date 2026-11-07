# Crenel console (web)

The Crenel UI: a static React + Vite SPA that renders the same model the engine
produces (findings, severity, state, proof).

## Run

```bash
pnpm install
pnpm dev        # http://localhost:5173
pnpm build      # -> dist/
pnpm preview
```

## Structure

```
src/
  main.tsx        hash router bootstrap
  App.tsx         routes (landing + /app/* under the Shell)
  styles/
    tokens.css    design tokens (colors, type scale, radii) — Crenel identity
    base.css      the design system: shell, cards, table, chips, console, cmdk…
  brand/Logo.tsx  Mark, Wordmark, Mascot (the jackdaw)
  components/
    Shell.tsx     sidebar (mobile: top bar + drawer), Topbar, Cmd/Ctrl-K palette
    Composer.tsx  prompt composer shared by Home and Agent (target, mode,
                  model, effort pickers, slash menu, attachments)
    CommandPalette.tsx
    ui.tsx        Button, Card, Picker (listbox popover), SeverityChip,
                  StateBadge, GuardBadge, CopyButton, Toggle, TaskList, …
  pages/          Overview (home composer), Agent (transcript), Scans (tasks),
                  Findings, FindingDetail, Targets, Onboarding, Secrets,
                  Authorization, Tests, Integrations, Settings, Landing
  data/api.ts     live data from crenel serve, demo fallback
  data/live-run.ts  Agent page: runs over SSE, approvals, stop, goals
  data/mock.ts    demo data (fallback)
  lib/            types, cn, links, workspace (shared composer choices)
```

## Conventions

- One global design system in `styles/`; components stay clean markup.
- Icons: `lucide-react`. Fonts: Mona Sans (display), Instrument Sans (UI),
  JetBrains Mono (mono). Single dark theme by design.
- Colors come from tokens, never literals. Keep a 16px side gutter and let rows
  stack at phone width.

Served by `crenel serve` (see the root README), the console reads the local
API through `src/data/api.ts` and the Agent page streams real runs
(`src/data/live-run.ts`). Without that API (`pnpm dev` alone, a static build,
the SSR tests) it falls back to the demo data in `src/data/mock.ts` and a
scripted agent run.
