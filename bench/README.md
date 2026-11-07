# Crenel bench

Small multi-tenant targets with ground truth, to measure a security tool
honestly: real flaws it must find, and decoys it must not flag.

```bash
node bench/run.mjs                    # scores Crenel on every case
node bench/run.mjs --case authz-basic # one case
node bench/run.mjs --json result.json
```

Each case in `cases/` has a `case.json` (title, type `static` or `live`,
`mustFind`, `mustNotFlag`) and, for live cases, a `server.mjs` that starts a
local target. Live targets bind to 127.0.0.1 only.

Tools plug in through `adapters/<tool>.mjs` (`run({ projectDir, baseUrl,
caseConfig, tmp })` returning `{ findings }`). The plan is to add adapters for
the alternatives (gitleaks, trufflehog, Semgrep, Nuclei, ZAP, AuthProbe, ...)
and publish the comparison, misses included. The cases must stay neutral: they
model flaws seen in real SaaS apps, not Crenel's own checks.
