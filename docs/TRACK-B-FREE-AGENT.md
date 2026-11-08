# Track B — free-agent exploration (prototype branch)

Goal: close the recall gap to the free LLM agents (Claude Code alone, HexStrike ≈ 59% on neutral targets vs Crenel+exploration 22%) by letting the exploration model **act like a free agent with real tools**, while keeping Crenel's two guarantees intact:

1. **Scope in code, not in a prompt** — every byte on the wire goes through the scoped client / proxy; the model can never reach an undeclared host.
2. **Proof, not noise** — a finding is `proven` only when a deterministic validator replays it. Freedom changes what the agent *reaches*, never what *counts*.

## Why the current design caps recall

Today the model is a text completion (`claude -p`) that emits JSON for Crenel's own loop. It can only call a fixed tool set (`http.request`, `toolbox.run` on 4 allowlisted tools, `claim.submit` on known classes). HexStrike wins because it exposes 150+ tools to the model; Claude Code alone wins because it has a shell and writes its own scripts. Crenel's model cannot chain its own tooling, so it under-explores.

## The safe way to add freedom: the proxied sandbox

The toolbox already runs tools inside a container whose **only network exit is the perimeter proxy** (`docs/TOOLBOX.md`). That container is the safe place to let the model run freely: a shell there can reach the network only through the proxy (declared hosts, read methods unless active mode), and its filesystem is the ephemeral container, not the host.

So the prototype gives the model, **opt-in and full-mode only**, a general command tool *inside that container*, instead of a raw host shell:

- `agent.sh { cmd }` — runs `sh -c <cmd>` in the toolbox container, network-restricted to the proxy, CPU/mem/time capped, output capped and returned as **a lead** (never proof). The model can install nothing new (offline image) but can chain the bundled tools, write and run its own scripts against the target, grep, pipe, etc.
- Everything it finds is still only a `lead` until it submits a `claim.submit` that a **generic validator** replays and proves. No new proof path.

### Safety analysis

| Risk | Mitigation |
|---|---|
| Reaching an undeclared host | Container egress is the proxy only; the proxy enforces the allowlist and method rules exactly as for `http.request`. No host networking, no DNS outside the proxy. |
| Host compromise / file exfiltration | Runs in the ephemeral toolbox container (rootless, `--disable-host-loopback`), not on the host; no host FS mount beyond the scoped workdir. |
| State-changing requests | The proxy still requires `allowActiveTesting` for non-read methods, same gate as everywhere. |
| Fabricated proof | `agent.sh` output is always a `lead`; only a validator sets `proven`. The scorer counts proven only. |
| Cost / runaway | Full-mode budget (calls/requests/tokens/ms) + a per-command timeout and a max number of `agent.sh` runs. |

### What stays forbidden (no overfit, no cheating)

- No target-specific logic anywhere in validators.
- `agent.sh` never writes `proven`; it cannot bypass the validator gate.
- No raw host shell, no host networking, no escaping the proxy.

## Implementation plan (this branch)

1. `src/toolbox/backend.ts`: add `runShell(cmd, opts)` that execs `sh -c` in the same proxied container the tools use, with the proxy env, time/output caps. Gate behind a new `options.explore.agentShell: true` (default off) and full mode.
2. `src/agent/explore.ts`: register the `agent.sh` tool only when enabled; its result is appended to history as a lead, with the usual untrusted-output framing.
3. Tests: a backend test that the command runs in the container and cannot reach a non-allowlisted host (proxy refusal), and an explore test that `agent.sh` output never becomes a finding by itself.
4. Measure on a neutral bench with `agentShell` on vs off; keep it only if it raises *proven* recall without any false positive.

Status: design committed; implementation to follow on this branch, reviewed before any merge. Nothing here changes the default (`agentShell` is off), so the shipped tool keeps its current safety surface until Tom approves.
