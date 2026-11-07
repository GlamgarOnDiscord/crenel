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
    Shell.tsx     sidebar + topbar + Outlet, Cmd/Ctrl-K palette
    CommandPalette.tsx
    ui.tsx        Button, Card, Kpi parts, SeverityChip, Sparkline, Bars, …
  pages/          Overview, Findings, FindingDetail, Scans, ScanRun (agent),
                  Targets, Onboarding, Secrets, Authorization, Tests,
                  Integrations, Settings, Landing
  data/mock.ts    demo data (no backend)
  lib/            types, cn, links
```

## Conventions

- One global design system in `styles/`; components stay clean markup.
- Icons: `lucide-react`. Fonts: Mona Sans (display), Instrument Sans (UI),
  JetBrains Mono (mono). Single dark theme by design.
- Colors come from tokens, never literals. Keep a 16px side gutter and let rows
  stack at phone width.

In production the console talks to a backend; in this repo it renders mock data
and a scripted agent run, with a working prompt, command palette and filters.
