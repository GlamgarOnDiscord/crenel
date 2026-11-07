// Confined execution of the toolbox image.
//
// Layout of one run on Linux:
//
//   [tool container] --internal network-- [relay container] --Unix socket (bind mount)-- [Crenel egress proxy, host]
//
//   - the tool container is attached ONLY to a per-run `--internal` network:
//     Docker gives it no default route, no NAT, and does not forward its DNS
//     queries outside. Its only peer on that network is the relay;
//   - the relay is on that internal network only, too, and runs `socat` with
//     fixed arguments: TCP 3128 to the proxy's Unix socket. No container of the
//     run has a route out, and the proxy listens on no TCP port;
//   - Docker Desktop (macOS, Windows) cannot share a host Unix socket with a
//     container, so there the relay also joins the default bridge and dials
//     host.docker.internal, where the proxy listens on the host loopback
//     (relayMode() below; not tested by us);
//   - the proxy (src/core/egress-proxy.ts) applies the run's scope and asks for
//     a per-run credential;
//   - both containers: read-only root filesystem, no capabilities,
//     no-new-privileges, non-root user, pids/memory/CPU limits, a wall-clock
//     timeout. The project is mounted read-only.
//
// A tool that needs no network at all (trufflehog without verification) runs
// with `--network none` and no proxy.
//
// Everything goes through `docker` argv arrays: no shell, no string building.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startEgressProxy, type EgressProxy, type ProxyEvent } from "../core/egress-proxy.js";
import type { Scope } from "../core/scope.js";

export const TOOLBOX_IMAGE = process.env.CRENEL_TOOLBOX_IMAGE ?? "crenel-toolbox:0.1.0";
const LABEL = "crenel.toolbox=1";
const RELAY_PORT = 3128;

export interface ExecResult { code: number; stdout: string; stderr: string; timedOut: boolean }

/** Run `docker <args>` without a shell. Output is capped (default 16 MB per stream). */
export function docker(args: string[], o: { timeoutMs?: number; env?: NodeJS.ProcessEnv; maxBytes?: number; signal?: AbortSignal } = {}): Promise<ExecResult> {
  const max = o.maxBytes ?? 16 * 1024 * 1024;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(process.env.CRENEL_DOCKER ?? "docker", args, { env: o.env ?? process.env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    } catch (err) {
      return resolve({ code: 127, stdout: "", stderr: (err as Error).message, timedOut: false });
    }
    let out = "", err = "", timedOut = false;
    child.stdout.on("data", (b: Buffer) => { if (out.length < max) out += b.toString("utf8"); });
    child.stderr.on("data", (b: Buffer) => { if (err.length < max) err += b.toString("utf8"); });
    const t = o.timeoutMs ? setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, o.timeoutMs) : undefined;
    const onAbort = () => child.kill("SIGKILL");
    o.signal?.addEventListener("abort", onAbort, { once: true });
    child.on("error", (e) => { err += e.message; });
    child.on("close", (code) => {
      if (t) clearTimeout(t);
      o.signal?.removeEventListener("abort", onAbort);
      resolve({ code: code ?? 1, stdout: out, stderr: err, timedOut });
    });
  });
}

export interface DockerStatus {
  available: boolean;
  version?: string;
  image: string;
  imagePresent: boolean;
  /** Why the toolbox is off, in one sentence for a human. */
  reason?: string;
}

/** Is Docker reachable, and is the toolbox image built? Never throws. */
export async function dockerStatus(image = TOOLBOX_IMAGE): Promise<DockerStatus> {
  const v = await docker(["version", "--format", "{{.Server.Version}}"], { timeoutMs: 8000 });
  if (v.code !== 0) {
    const missing = v.code === 127 || /ENOENT|not found/i.test(v.stderr);
    return { available: false, image, imagePresent: false, reason: missing ? "Docker is not installed (the toolbox is optional; every other Crenel check works without it)" : `Docker daemon unreachable: ${v.stderr.trim().split("\n")[0] ?? ""}` };
  }
  const i = await docker(["image", "inspect", "--format", "{{.Id}}", image], { timeoutMs: 8000 });
  return {
    available: true, version: v.stdout.trim(), image, imagePresent: i.code === 0,
    ...(i.code === 0 ? {} : { reason: `image ${image} is not built yet: run \`crenel tools build\`` }),
  };
}

/** Build the image from the toolbox/ directory shipped with Crenel. */
export async function buildImage(contextDir: string, image = TOOLBOX_IMAGE): Promise<ExecResult> {
  return docker(["build", "-t", image, contextDir], { timeoutMs: 30 * 60_000 });
}

/**
 * How the relay reaches the host proxy.
 *   unix (Linux, default): the proxy listens on a Unix socket bind-mounted into
 *     the relay, which is attached to the internal network ONLY. No container
 *     of the run has any route out; nothing listens on a host TCP port.
 *   tcp (Docker Desktop on macOS/Windows, or CRENEL_PROXY_MODE=tcp): the relay
 *     also sits on the default bridge and dials host.docker.internal, where the
 *     proxy listens on the host loopback. The relay then has a route out, but
 *     it only runs socat with fixed arguments.
 */
export function relayMode(): "unix" | "tcp" {
  const m = process.env.CRENEL_PROXY_MODE;
  if (m === "unix" || m === "tcp") return m;
  return process.platform === "linux" ? "unix" : "tcp";
}

export interface Limits {
  memory: string;
  cpus: string;
  pids: number;
  timeoutMs: number;
}
export const DEFAULT_LIMITS: Limits = { memory: "1g", cpus: "2", pids: 256, timeoutMs: 10 * 60_000 };

/** Flags every toolbox container gets. */
export function hardeningFlags(l: Limits): string[] {
  return [
    "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--user", "65532:65532",
    "--pids-limit", String(l.pids), "--memory", l.memory, "--memory-swap", l.memory, "--cpus", l.cpus,
    "--label", LABEL,
  ];
}

export interface ConfinedOptions {
  /** argv inside the container, e.g. ["nuclei", "-u", ...]. */
  argv: string[];
  /** Mounted read-only at /project. */
  projectDir?: string;
  /** null = no network at all (`--network none`, no proxy). */
  scope: Scope | null;
  tool: string;
  onEvent?: (e: ProxyEvent) => void;
  limits?: Partial<Limits>;
  proxy?: { ratePerSec?: number; maxRequests?: number };
  image?: string;
  signal?: AbortSignal;
  /** Override the image entrypoint (the self-test uses busybox). */
  entrypoint?: string;
  /** Receives the proxy URL as seen from inside the container, to put in the argv. */
  argvWithProxy?: (proxyUrl: string) => string[];
}

export interface ConfinedResult extends ExecResult {
  proxy?: { requests: number; refused: number };
  network: "none" | "internal+proxy";
}

/** Run one tool confined. Cleans up its containers and network even on error. */
export async function runConfined(o: ConfinedOptions): Promise<ConfinedResult> {
  const image = o.image ?? TOOLBOX_IMAGE;
  const limits = { ...DEFAULT_LIMITS, ...(o.limits ?? {}) };
  const id = randomBytes(4).toString("hex");
  const ep = o.entrypoint ? ["--entrypoint", o.entrypoint] : [];
  const mount = o.projectDir ? ["--mount", `type=bind,source=${o.projectDir},target=/project,readonly`] : [];
  const toolName = `crenel-tool-${id}`;

  if (!o.scope) {
    const r = await docker(["run", "--rm", "--name", toolName, "--network", "none", ...hardeningFlags(limits), ...ep, ...mount, image, ...o.argv], { timeoutMs: limits.timeoutMs, signal: o.signal });
    if (r.timedOut) await docker(["rm", "-f", toolName], { timeoutMs: 15_000 });
    return { ...r, network: "none" };
  }

  const net = `crenel-tb-${id}`;
  const relay = `crenel-relay-${id}`;
  const mode = relayMode();
  let proxy: EgressProxy | undefined;
  let sockDir: string | undefined;
  try {
    const common = { scope: o.scope, tool: o.tool, onEvent: o.onEvent, ...o.proxy };
    if (mode === "unix") {
      sockDir = mkdtempSync(join(tmpdir(), "crenel-px-"));
      const socketPath = join(sockDir, "proxy.sock");
      proxy = await startEgressProxy({ ...common, socketPath });
      // The relay runs as uid 65532: it must traverse the directory and write
      // to the socket. The per-run credential still guards the proxy itself.
      chmodSync(sockDir, 0o711);
      chmodSync(socketPath, 0o666);
    } else {
      proxy = await startEgressProxy({ ...common, host: process.env.CRENEL_PROXY_BIND ?? "127.0.0.1" });
    }
    const mk = await docker(["network", "create", "--internal", "--label", LABEL, net], { timeoutMs: 20_000 });
    if (mk.code !== 0) throw new Error(`docker network create failed: ${mk.stderr.trim()}`);
    const relayLimits = hardeningFlags({ memory: "64m", cpus: "0.5", pids: 64, timeoutMs: 0 });
    const rl = mode === "unix"
      ? await docker([
        "run", "-d", "--rm", "--name", relay, "--network", net, "--network-alias", "crenel-proxy", ...relayLimits,
        "--mount", `type=bind,source=${sockDir},target=/run/crenel,readonly`,
        image, "socat", `TCP-LISTEN:${RELAY_PORT},fork,reuseaddr`, "UNIX-CONNECT:/run/crenel/proxy.sock",
      ], { timeoutMs: 30_000 })
      : await docker([
        "run", "-d", "--rm", "--name", relay, "--network", "bridge", "--add-host", "crenel-host:host-gateway", ...relayLimits,
        image, "socat", `TCP-LISTEN:${RELAY_PORT},fork,reuseaddr`, `TCP:crenel-host:${proxy.port}`,
      ], { timeoutMs: 30_000 });
    if (rl.code !== 0) throw new Error(`relay failed to start: ${rl.stderr.trim()}`);
    if (mode === "tcp") {
      const cn = await docker(["network", "connect", "--alias", "crenel-proxy", net, relay], { timeoutMs: 20_000 });
      if (cn.code !== 0) throw new Error(`relay could not join ${net}: ${cn.stderr.trim()}`);
    }

    const inside = `http://crenel:${proxy.token}@crenel-proxy:${RELAY_PORT}`;
    const argv = o.argvWithProxy ? o.argvWithProxy(inside) : o.argv;
    // The credential reaches the container through the environment of the
    // docker CLI (`-e NAME` without a value), not through the docker argv.
    const env = { ...process.env, HTTP_PROXY: inside, HTTPS_PROXY: inside, http_proxy: inside, https_proxy: inside, NO_PROXY: "", no_proxy: "" };
    const r = await docker([
      "run", "--rm", "--name", toolName, "--network", net, ...hardeningFlags(limits),
      "-e", "HTTP_PROXY", "-e", "HTTPS_PROXY", "-e", "http_proxy", "-e", "https_proxy", "-e", "NO_PROXY", "-e", "no_proxy",
      ...ep, ...mount, image, ...argv,
    ], { timeoutMs: limits.timeoutMs, env, signal: o.signal });
    return { ...r, proxy: { ...proxy.stats }, network: "internal+proxy" };
  } finally {
    await docker(["rm", "-f", toolName, relay], { timeoutMs: 20_000 });
    await docker(["network", "rm", net], { timeoutMs: 20_000 });
    await proxy?.close();
    if (sockDir) rmSync(sockDir, { recursive: true, force: true });
  }
}

/** Remove containers and networks a crashed run may have left behind. */
export async function cleanupLeftovers(): Promise<void> {
  const ps = await docker(["ps", "-aq", "--filter", `label=${LABEL}`], { timeoutMs: 15_000 });
  const ids = ps.stdout.split(/\s+/).filter(Boolean);
  if (ids.length) await docker(["rm", "-f", ...ids], { timeoutMs: 30_000 });
  const nets = await docker(["network", "ls", "-q", "--filter", `label=${LABEL}`], { timeoutMs: 15_000 });
  for (const n of nets.stdout.split(/\s+/).filter(Boolean)) await docker(["network", "rm", n], { timeoutMs: 15_000 });
}
