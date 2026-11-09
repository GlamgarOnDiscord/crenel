# Exploration: closing the recall gap, honestly

On neutral targets (DVGA + Juice Shop + crAPI, ground truth /32, proven findings only):

| Tool | Recall |
| --- | --- |
| Claude Code alone | 19/32 (59%) |
| HexStrike AI | 19/32 (59%) |
| **Crenel + exploration** | **6/32 (19%)** |
| Crenel floor only | 2/32 (6%) |

## Measured again, 2026-11-09 (Juice Shop + DVGA, /24)

A second, smaller neutral set, run locally in Docker. The ground truth was written
before measuring, from each project's own vulnerability list, keeping only flaws an
API request can prove: Juice Shop 13 (SQLi search and login, unsigned JWT, basket
IDOR, metrics, /ftp, admin registration, DOM XSS, API docs, NoSQL reviews, feedback
deletion, open redirect, basket manipulation), DVGA 11 (introspection, suggestions,
batching, GraphiQL, command injection, SSRF, SQLi, stored XSS, path traversal,
authorization bypass, stack traces). Proven findings only, union of `scan`,
`autoprobe` and one `explore --mode full` run (Opus 4.8, 25 min wall time):

| Pipeline | Juice Shop | DVGA | Total |
| --- | --- | --- | --- |
| Before (main at ed7eee5) | 3/13 | 3/11 | 6/24, plus 2 false cross-account proofs |
| After | 6/13 | 7/11 | 13/24, 0 false proofs found |
| After + owner-field id scan and cross-write validator | 7/13 | 7/11 | **14/24** |

The owner-field id scan (autoprobe reads small ids as the owner and keeps the
ones whose owner field holds the owner's own id) adds Juice Shop's basket IDOR:
it finds B's basket without being told its id. A generic `explore.cross-actor-write`
validator (B creates an object, an anonymous write is the control, A's
DELETE/PUT/PATCH must change what B re-reads) also shipped; it stays silent on
both apps here (Juice Shop's addresses enforce ownership, DVGA's writes are
GraphQL mutations the REST-shaped claim does not target), which is the
no-false-positive behaviour, not a bug.

Caveats: both apps are famous, so a model may know their flaws (the deterministic
`scan` + `autoprobe` alone reach the same 13/24 here: the model added nothing new);
the set is small; the changes were developed while looking at these two targets, so
a held-out target (VAmPI, crAPI) is the next honest check. Misses: the basket IDOR
(no proof — now found by the owner-field id scan), admin registration (proven by the new
create-mode mass assignment when claimed, not claimed in the run), DOM XSS (proven
with a browser configured, not in the run), NoSQL reviews, feedback deletion and
basket manipulation (no cross-account write validator yet), open redirect via an
allowlist bypass, stored XSS (served as JSON: a lead by design), path traversal,
authorization bypass, stack traces.

## Why the gap is structural, not just missing checks

The free LLM agents (Claude Code alone, HexStrike) count every finding their model **asserts** as proven, across every category. Crenel counts a finding only when a **deterministic validator replays it** — its "proof, not noise" guarantee: false positives are kept out by the validators and none has been observed on the bench, which is not a claim that there can be none. That gate is also the ceiling on recall: a real flaw in a category with no generic validator, or one the model reached but could not hand to a validator, never scores.

So the gap closes on two tracks, and neither is overfitting (no target signatures, no self-asserted proofs):

## Track A — more generic validators (incremental)

Each is a pure oracle + a negative control, proving a mechanism, never a signature. Shipped: replay, cross-actor (with anonymous auto-escalation), secret, file-match, injection (SQLi, reflected XSS, template/command, **NoSQL**), SSRF, stored-XSS, DOM-XSS, LFI, JWT alg:none and forgery, mass-assignment (update and create), **cross-account write** (B creates, A deletes or changes), **privilege escalation** (a gate flips denied to allowed after the account's own write), **user enumeration** (two-absent control), **excessive data exposure** (two or more accounts' markers in one response), CORS, business-logic **reuse**, GraphQL suggestions and batching, **open-redirect** (two-sentinel differential).

Candidates next, with an honest oracle:
- **function-level auth (BFLA) across accounts** — a non-admin account reaches a function a declared admin account uses while anonymous is denied; needs a role declared in the config, so it is not yet shipped.

## Track B — let the model work like a free agent (the real lever)

Today the exploration model (the `claude` CLI or a custom provider) is called as a pure text completion that emits JSON for Crenel's own tool loop (`http.request`, `toolbox.run`, `claim.submit`). It cannot run its own tools or skills, and `claim.submit` only accepts known classes. That is why it under-explores versus HexStrike (150+ tools) and Claude Code (full agent).

The plan: run the exploration model as a **free agent with real tools and skills** (shell, scripting, the toolbox, Cloudflare and other skills) — but **inside the proxied perimeter**, so Crenel's "scope in code, not in a prompt" safety guarantee holds, and with **proof still gated by the generic validators**, so freedom raises recall without adding false positives or overfitting.

Enabling pieces:
- **Custom / local model providers** (done): an `Llm` provider registry (`src/agent/llm.ts`) so exploration can target any OpenAI-compatible endpoint, Ollama, or the Anthropic API directly — not only the `claude` CLI. Keys only from the environment.
- A broader, higher-budget toolbox (done: full mode now 24 calls / 300 requests / 10 tool runs / 25 min), and an aggressive, persistent exploitation prompt (done).
- The agent-freedom step itself: give the spawned agent its own tools/skills within the perimeter proxy, keeping every request on the scoped client. A shell alone does not keep it in the perimeter (a direct socket skips the proxy): the agent runs where egress is restricted at the network layer (a container whose only route out is the proxy), as `docs/TRACK-B-FREE-AGENT.md` details.

The guarantee throughout: a finding is `proven` only when a deterministic validator replays it. Freedom and more models change what the agent *reaches*, never what counts as proof.
