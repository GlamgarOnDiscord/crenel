// Where the toolbox's tools run: the Docker image (default) or a WSL
// distribution (Windows, opt-in). Both run the same allowlist, built by the
// same argv builders, through the same scoped egress proxy; only the
// confinement differs (docs/TOOLBOX.md).

import type { ProxyEvent } from "../core/egress-proxy.js";
import type { Scope } from "../core/scope.js";
import { dockerStatus, relayMode, runConfined, type DockerStatus, type ExecResult } from "./docker.js";
import { TOOL_NAMES, type BackendName, type ToolName } from "./names.js";
import { runWsl, toWslPath, wslStatus, wslToolBlocker, type WslExec, type WslStatus } from "./wsl.js";

export interface BackendStatus {
  backend: BackendName;
  /** Tools can run at all on this backend. */
  ready: boolean;
  reason?: string;
  /** Per tool: can it run here, and if not, why. */
  tools: Record<ToolName, { ready: boolean; reason?: string }>;
  docker?: DockerStatus & { relay: "unix" | "tcp" };
  wsl?: WslStatus;
}

/** Paths and proxy URL as the tool sees them, for the argv builders. */
export interface ToolPaths { proxy: string; projectRoot: string; templatesDir: string }

export interface BackendRun {
  tool: ToolName;
  /** false: the tool needs no network (Docker: --network none; WSL: a proxy that refuses everything). */
  network: boolean;
  scope: Scope;
  build: (p: ToolPaths) => string[];
  projectDir?: string;
  limits: { timeoutMs: number; memory: string };
  proxy: { ratePerSec: number; maxRequests: number };
  onEvent?: (e: ProxyEvent) => void;
  signal?: AbortSignal;
}

export interface BackendResult extends ExecResult {
  network: "none" | "internal+proxy" | "wsl+proxy";
  proxy?: { requests: number; refused: number };
  /** Root of the project as the tool saw it (to make its file paths relative). */
  projectRoot: string;
}

export interface Backend {
  name: BackendName;
  status(): Promise<BackendStatus>;
  run(r: BackendRun, st: BackendStatus): Promise<BackendResult>;
}

export interface BackendOptions {
  backend: BackendName;
  image: string;
  wsl: { distro: string; proxyHost?: string };
}

const allTools = (ready: boolean, reason?: string) =>
  Object.fromEntries(TOOL_NAMES.map((t) => [t, ready ? { ready } : { ready, reason }])) as BackendStatus["tools"];

export function dockerBackend(image: string): Backend {
  return {
    name: "docker",
    async status() {
      const st = await dockerStatus(image);
      const ready = st.available && st.imagePresent;
      const tools = allTools(ready, ready ? undefined : `toolbox off: ${st.reason}`);
      if (ready) for (const t of TOOL_NAMES) if (!(st.tools ?? []).includes(t)) tools[t] = { ready: false, reason: `${t} is not in image ${image}: rebuild it with \`crenel tools build\`` };
      return { backend: "docker", ready, reason: st.reason, tools, docker: { ...st, relay: relayMode() } };
    },
    async run(r) {
      const paths = { projectRoot: "/project", templatesDir: "/opt/nuclei-templates" };
      const res = await runConfined({
        tool: r.tool, scope: r.network ? r.scope : null, image, limits: r.limits, proxy: r.proxy, onEvent: r.onEvent, signal: r.signal,
        projectDir: r.projectDir, argv: r.build({ ...paths, proxy: "" }), argvWithProxy: r.network ? (px) => r.build({ ...paths, proxy: px }) : undefined,
      });
      return { ...res, projectRoot: paths.projectRoot };
    },
  };
}

export function wslBackend(o: { distro: string; proxyHost?: string }, exec?: WslExec): Backend {
  return {
    name: "wsl",
    async status() {
      const st = await wslStatus(o.distro, { exec, proxyHost: o.proxyHost });
      const tools = Object.fromEntries(TOOL_NAMES.map((t) => {
        const why = wslToolBlocker(st, t);
        return [t, why ? { ready: false, reason: why } : { ready: true }];
      })) as BackendStatus["tools"];
      return { backend: "wsl", ready: st.available, reason: st.reason, tools, wsl: st };
    },
    async run(r, st) {
      const w = st.wsl;
      if (!w?.endpoint || !w.home) throw new Error("WSL backend not ready");
      const projectRoot = r.projectDir ? await toWslPath(o.distro, r.projectDir, exec) : w.home;
      const templatesDir = w.templates.dir ?? `${w.home}/.crenel/nuclei-templates`;
      const res = await runWsl({
        tool: r.tool, distro: o.distro, exec, scope: r.network ? r.scope : null, endpoint: w.endpoint,
        timeoutMs: r.limits.timeoutMs, proxy: r.proxy, onEvent: r.onEvent, signal: r.signal,
        argvWithProxy: (px) => r.build({ proxy: px, projectRoot, templatesDir }),
      });
      return { ...res, projectRoot };
    },
  };
}

/** The backend options.toolbox selects. `exec` replaces wsl.exe (tests). */
export function backendFor(o: BackendOptions, deps: { wslExec?: WslExec } = {}): Backend {
  return o.backend === "wsl" ? wslBackend(o.wsl, deps.wslExec) : dockerBackend(o.image);
}
