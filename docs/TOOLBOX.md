# Toolbox: external tools behind Crenel's perimeter

Crenel can run three open-source tools in a Docker container:

| Tool | Version | What it does here | Network |
|---|---|---|---|
| [nuclei](https://github.com/projectdiscovery/nuclei) | 3.11.1, templates 10.5.1 | non-intrusive http templates only (exposures, misconfigurations, technologies, panels) | through the proxy |
| [katana](https://github.com/projectdiscovery/katana) | 1.8.0 | route discovery, depth 2, bounded duration, no form filling, no headless browser | through the proxy |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | 3.99.8 | secrets in the project directory (filesystem mode) | none by default |

No exploitation tool is shipped (no sqlmap, no brute forcer), and none can be added through the config.

The toolbox is optional. Without Docker, or before the image is built, `crenel tools status` says why, the tools are skipped with a one-line note in agent runs, and every other check works exactly as before.

## Why a proxy

Every request Crenel sends goes through `src/core/net.ts` (declared hosts, no private address, redirects re-checked, read-only methods in the agent loop). An external tool has its own HTTP client and would bypass all of that. So the tool runs where it has **no route out at all**, and its only way to the network is a proxy Crenel starts for the run, which applies the same rules.

```
[tool container] --internal Docker network-- [relay: socat] --Unix socket-- [Crenel egress proxy] --> declared hosts only
```

- The tool container is attached only to a per-run `docker network create --internal` network: no default route, no NAT, and Docker does not forward its DNS queries outside (observed here: `SERVFAIL` for any external name).
- The relay is on that internal network only. It runs `socat` with fixed arguments: TCP 3128 to the proxy's Unix socket, bind-mounted read-only. On Linux, no container of the run has a route out and the proxy listens on no TCP port.
- The proxy asks for a per-run credential, passed to the container through its environment (not the docker argv).
- Both containers: read-only root filesystem, `--cap-drop ALL`, `no-new-privileges`, user 65532, `--pids-limit`, memory and CPU caps, wall-clock timeout, `/tmp` as a small tmpfs. The project is mounted read-only at `/project`. The image entrypoint only runs `nuclei`, `katana`, `trufflehog` (and `socat` for the relay).
- trufflehog without verification runs with `--network none`: no proxy, no relay, nothing.

## What the proxy filters (`src/core/egress-proxy.ts`)

For every request and every tunnel:

1. the host must be in `scope.allowedHosts` (checked before any DNS lookup);
2. the proxy resolves the name itself, refuses if **any** answer is private, loopback, link-local, CGNAT or a cloud metadata address (same list as `isPrivateIp` in net.ts, unless `scope.allowPrivate`), then connects to the address it checked (pinned: a second DNS answer cannot rebind it);
3. a request budget (`maxRequests`), a rate limit (`ratePerSec`, extra requests wait), a 2 MB cap per plain-HTTP response, a 20 MB cap per tunnel, 15 s timeouts, and the run's kill switch;
4. every request and every refusal is one line in the audit JSONL (`.crenel/audit.jsonl`, `kind: "egress"`, with the pinned IP, status, bytes, or the refusal reason), and in the run journal.

**Plain HTTP** (`http://`): the proxy sees the request. Only `GET`, `HEAD` and `OPTIONS` are forwarded; anything else gets `405` and never reaches the target. Redirects are not followed by the proxy: the tool follows them with a new request, which is checked from step 1 again (an off-scope `Location` is also flagged in the audit line).

**HTTPS** (`CONNECT`): the proxy does **not** decrypt. It checks the host, the port (443 or 80 only) and the resolved address, then relays bytes. It cannot see the method, the path or the body inside the tunnel, so **it cannot enforce read-only methods over HTTPS**. That is the honest limit, and why only non-intrusive tool modes are allowed:

- nuclei: templates are filtered when the image is built (`toolbox/nuclei-filter.mjs`, 3,814 of 14,148 kept in 10.5.1). A template stays only if it is an `http/` template in `exposures`, `misconfiguration`, `technologies` or `exposed-panels`; has at least one allowed tag (`exposure, misconfig, tech, panel, config, detect, discovery, disclosure, headers, files, logs, debug`) and no denied tag (`intrusive, dos, fuzz, sqli, xss, rce, lfi, ssrf, cve, default-login, oast, ...`); uses only `GET`/`HEAD`; has no raw request, payloads, fuzzing, body, flow, code, javascript, out-of-band interaction (`interactsh`) or absolute third-party URL. The others are deleted from the image. At run time Crenel adds `-tags`/`-etags` with the same lists, `-ni` (no interactsh) and `-duc` (no update check). `options.toolbox.nuclei.tags` can only narrow the allowlist;
- katana: depth 1 to 5 (default 2), field scope `fqdn`, no form filling, no headless browser, bounded duration;
- trufflehog: no network by default.

A decrypting proxy (MITM with a per-run CA) would let the proxy filter methods over HTTPS too. It is not done, on purpose: it means injecting a CA into the container and handling certificate pinning, and it is a bigger attack surface than the problem it solves for read-only tools.

What is **not** covered:

- a compromised or malicious tool binary can still send any bytes inside an allowed HTTPS tunnel to a declared host (e.g. a `POST`). The perimeter (which hosts) holds; the read-only guarantee over HTTPS rests on the tool and template filtering above;
- the relay container is a peer of the tool on the internal network; a bug in `socat` reachable from the tool is a residual risk (on Linux the relay itself has no route out either);
- Docker itself (daemon, kernel) is trusted.

## From leads to proof

Tool output is untrusted (the target wrote part of it): it is wrapped as an untrusted envelope (capped, hashed, fenced) before anything can show it to a model, text copied into a finding is capped and stripped of control characters, results about hosts outside the scope are dropped, and a secret is never copied (only a hash).

Every result is a lead (`unproven`). It becomes `proven` only when an existing deterministic validator replays it from the config and the disk:

| Tool result | Replayed by | Becomes proven when |
|---|---|---|
| nuclei `http-missing-security-headers` (CSP, HSTS, XCTO, XFO, Referrer-Policy) | `header-reread` | the header is absent from a fresh GET of `stagingUrl` |
| trufflehog secret in `file:line` | `deterministic-check-replay-on-file` (exposed-secrets) | exposed-secrets itself proves a secret at the same file and line |
| katana route with an id (`/api/invoices/inv_b_1`) | suggestion for `options.authz-matrix.resources` | once you declare it with B's ids, `authz-replay` proves the cross-tenant read |

Anything else (a nuclei exposure template, a trufflehog detector Crenel has no pattern for) stays a lead, labelled as such.

## Use it

```bash
crenel tools build                      # docker build of toolbox/ (pinned inputs, a few minutes)
crenel tools status                     # Docker, image, relay mode
crenel tools selftest                   # real escape test, see below
crenel tools trufflehog --config crenel.config.yaml
crenel tools katana     --config crenel.config.yaml
crenel tools nuclei     --config crenel.config.yaml [--json] [--audit log.jsonl]
crenel tools cleanup                    # remove containers/networks left by a crash
```

nuclei and katana target `scope.stagingUrl`. In the console (or the API), `/tools` runs the three tools, and a full scan includes them when `options.toolbox.enabled` is true. In the agent loop they go through the gate like any network tool (`tools.nuclei` counts as active testing and needs `allowActiveTesting`). `GET /api/toolbox` returns the Docker status, the options and the last egress events.

```yaml
options:
  toolbox:
    enabled: false        # include the tools in agent full scans
    ratePerSec: 10        # shared by the run, max 50
    maxRequests: 10000    # then the proxy refuses everything
    timeoutSec: 1200
    memory: 1g
    nuclei:
      tags: []            # empty = Crenel's whole allowlist; can only narrow
      excludeTags: []     # added to Crenel's denylist
      concurrency: 10
    katana: { depth: 2, durationSec: 120 }
```

trufflehog always runs with `--no-verification` and no network. Each of its leads is replayed by `exposed-secrets`, and that check's opt-in liveness (`options.exposed-secrets.verify: true`, provider host declared in `scope.allowedHosts`) makes one read-only `GET` per key through Crenel's own scoped client, where every request is visible and journalled. trufflehog's own verifiers sometimes `POST` over HTTPS, which the proxy cannot see, so they are not used. The old `trufflehog.verify` and `verifyHosts` options are still accepted and ignored.

nuclei counts as active testing: it does not run, from the console or the CLI, unless `scope.allowActiveTesting` is `true`.

A full nuclei run against one host with the whole allowlist is a few thousand GET requests (about 3,400 for the demo app); at the default 10 requests per second that is several minutes. Narrow `nuclei.tags` for a quicker pass.

## The escape test

`crenel tools selftest` (and the `confinement` test in `pnpm test`, skipped when Docker or the image is missing) starts the same containers and tries, with busybox `wget`:

| Probe | Expected | Observed on Linux, Docker 29.9 |
|---|---|---|
| direct `http://example.com/` | no answer | `bad address 'example.com'` (no DNS) |
| direct `http://192.0.2.1/` (RFC 5737, unrouted) | no answer | `Network unreachable` (no route) |
| direct `http://169.254.169.254/` | no answer | `Network unreachable` |
| via proxy `http://example.com/` | refused | `403`, journalled "not in allowedHosts" |
| via proxy `http://169.254.169.254/` | refused | `403` |
| via proxy, declared target | answered | `200` |

A direct probe passes only if no HTTP status line came back at all.

## Windows and macOS

Docker Desktop cannot share a host Unix socket with a container, so on those platforms (or with `CRENEL_PROXY_MODE=tcp`) the relay also joins the default bridge and dials `host.docker.internal`, where the proxy listens on the host loopback. The tool container is unchanged (internal network only); the relay then has a route out, but only runs `socat` with fixed arguments to the proxy. **This path has not been tested by us** (developed and tested on Linux only). Run `crenel tools selftest` first: if a probe fails, do not use the toolbox on that machine.

Environment knobs: `CRENEL_TOOLBOX_IMAGE` (image tag), `CRENEL_DOCKER` (docker binary), `CRENEL_PROXY_MODE` (`unix` or `tcp`), `CRENEL_PROXY_BIND` (listen address in tcp mode).

## Pinning

`toolbox/Dockerfile` pins the base images by digest (`alpine:3.22`, `node:22.23.4-slim` for the filter stage), the release archives by the sha256 published in each project's checksums file (amd64 and arm64), the templates by the sha256 of their tagged release, and the two Alpine packages by version. Updating a tool means updating its version and checksum together; Alpine package versions disappear from the mirrors after updates, so a rebuild may need a bump there too.
