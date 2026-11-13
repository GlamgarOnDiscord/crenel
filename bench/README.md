# Crenel bench

Small multi-tenant targets with ground truth, to measure a security tool
honestly: real flaws it must find, and decoys it must not flag.

```bash
node bench/run.mjs                    # scores Crenel on every case
node bench/run.mjs --case authz-basic # one case
node bench/run.mjs --json result.json
node bench/run.mjs --strict --seed ci-123 # CI: any miss/decoy fails
```

Each case in `cases/` has a `case.json` (title, type `static` or `live`,
`mustFind`, `mustNotFlag`) and, for live cases, a `server.mjs` that starts a
local target. Live targets bind to 127.0.0.1 only.

Tools plug in through `adapters/<tool>.mjs` (`run({ projectDir, baseUrl,
caseConfig, tmp })` returning `{ findings }`). The plan is to add adapters for
the alternatives (gitleaks, trufflehog, Semgrep, Nuclei, ZAP, AuthProbe, ...)
and publish the comparison, misses included. The cases must stay neutral: they
model flaws seen in real SaaS apps, not Crenel's own checks.

The runner randomizes case order from a recorded seed, applies a per-case
timeout, and records duration plus any request metadata the adapter provides. Ground-truth matching is 1:1:
one broad finding cannot satisfy two flaws. Cases may set `maxUnknownHigh` when
their truth is closed, which penalizes high/critical proven spam outside the
declared truth. Recorded model scripts are reported as **replay validation**,
separate from discovery recall. CI uploads the complete JSON manifest.

The `base` adapter ("Claude Code alone") runs `claude -p` in the logged-in
config directory named by `CRENEL_BENCH_CC_CONFIG` (required). By default the
model may only read the case and run `curl` (`--allowedTools
Read,Grep,Glob,Bash(curl:*)`); a full shell needs `CRENEL_BENCH_ALLOW_SHELL=1`,
and then only inside a sandbox whose egress is limited to the bench targets. The
model is `CRENEL_BENCH_MODEL` (default `claude-opus-4-8`). A "proven" finding
with no evidence is scored as a lead.
