// WSL backend: run the toolbox's allowlisted tools from a WSL distribution
// (Kali Linux by default) instead of the Docker image. Windows only, off by
// default (options.toolbox.backend: "wsl").
//
//   [tool, default non-root user of the distro] --HTTP(S)_PROXY / -proxy--> [Crenel egress proxy, Windows] --> declared hosts only
//
// What it keeps from the Docker backend: the same allowlist of tools and argv
// builders, the same filtered nuclei templates (pinned, filtered by the same
// nuclei-filter.mjs, then made read-only by root), the scoped egress proxy
// with its budget, rate limit and journal, a wall-clock timeout (coreutils
// `timeout` inside the distro, and a kill of wsl.exe outside), outputs parsed
// as untrusted by the same adapters.
//
// What it does NOT have (docs/TOOLBOX.md, "WSL backend"): there is no
// internal-only network. The proxy is passed to the tool (flag and
// environment), the tool is not *forced* through it: a tool that ignored its
// proxy settings could reach any host. No read-only root filesystem, no
// capability drop, no memory or pids cap, and the project is read through
// /mnt/<drive> (not mounted read-only).
//
// Root: `wsl -d <distro> -u root` needs no password. It is used ONLY by
// `crenel tools install --wsl` (apt-get install of the allowlisted packages,
// then making the filtered templates read-only), after an explicit
// confirmation. Tools always run as the distro's default user, and that user
// must not be root. Crenel never asks for, stores or logs a password.
//
// Every call is `wsl.exe` with an argv array (no Windows shell). The few
// fixed `sh -c` scripts below use no double quotes, so they survive the
// Windows command-line quoting unchanged; their only inputs are positional
// arguments validated beforehand.

import { existsSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { startEgressProxy, type EgressProxy, type ProxyEvent } from "../core/egress-proxy.js";
import { isPrivateIp } from "../core/net.js";
import { Scope } from "../core/scope.js";
import { execCapped, type ExecOptions, type ExecResult } from "./exec.js";
import { TOOL_NAMES, type ToolName } from "./names.js";
import { filterHash, NUCLEI_TEMPLATES_SHA256, NUCLEI_TEMPLATES_URL, NUCLEI_TEMPLATES_VERSION } from "./paths.js";
import { pruneTemplates } from "../../toolbox/nuclei-filter.mjs";

/** How Crenel calls wsl.exe. Injectable: tests pass a fake. */
export type WslExec = (args: string[], o?: ExecOptions) => Promise<ExecResult>;

export const DEFAULT_DISTRO = "kali-linux";
export const DISTRO_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** The program each allowlisted tool is in the distro (Kali package names). */
export const WSL_BINARIES: Record<ToolName, string> = { nuclei: "nuclei", katana: "katana", trufflehog: "trufflehog" };
/** Packages `crenel tools install --wsl` asks apt for, and nothing else. */
export const WSL_PACKAGES = ["nuclei", "katana", "trufflehog", "curl", "ca-certificates"];
/** Filtered templates, relative to the default user's home. */
export const TEMPLATES_REL = ".crenel/nuclei-templates";
const MARKER = ".crenel-filtered";

export function wslBinary(): string {
  return process.env.CRENEL_WSL ?? "wsl.exe";
}

/** wsl.exe's own messages are UTF-16LE on builds that ignore WSL_UTF8; the distro's programs print UTF-8. */
export function decodeWslBytes(b: Buffer): string {
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return b.subarray(2).toString("utf16le");
  let nul = 0;
  for (let i = 1; i < Math.min(b.length, 512); i += 2) if (b[i] === 0) nul++;
  return b.length >= 4 && nul >= Math.min(b.length, 512) / 2 * 0.6 ? b.toString("utf16le") : b.toString("utf8");
}

/** The real wsl.exe, asked for UTF-8 output (WSL_UTF8=1), decoding UTF-16 when it answers in it anyway. */
export const realWsl: WslExec = (args, o = {}) => execCapped(wslBinary(), args, { decode: decodeWslBytes, ...o, env: { ...(o.env ?? process.env), WSL_UTF8: "1" } });

/** wsl.exe prints UTF-16LE for its own messages on older builds: drop the NULs, BOM and CRs. */
export function decode(s: string): string {
  return s.replace(/\u0000/g, "").replace(/\uFEFF/g, "").replace(/\r/g, "");
}

export interface WslStatus {
  /** Ready to run tools (WSL answers, the distro exists, its default user is not root, the proxy can be reached). */
  available: boolean;
  /** wsl.exe answered. */
  wsl: boolean;
  distro: string;
  distroPresent: boolean;
  distros: string[];
  user?: string;
  uid?: number;
  home?: string;
  /** mirrored | nat | wsl1 | virtioproxy | unknown */
  networking?: string;
  /** Default gateway seen from the distro (the Windows host in NAT mode). */
  gateway?: string;
  /** Where the proxy listens on Windows and where the tool dials it. */
  endpoint?: { listen: string; dial: string };
  /** Path of each allowlisted tool in the distro, null when missing. */
  tools: Record<ToolName, string | null>;
  templates: { ready: boolean; dir?: string; version?: string; kept?: number; reason?: string };
  reason?: string;
}

// Fixed probe, run as the default user. No double quotes (see the header).
const INFO_SCRIPT = [
  "echo uid=$(id -u)", "echo user=$(id -un)", "echo home=$HOME",
  "echo net=$(wslinfo --networking-mode 2>/dev/null)", "echo kernel=$(uname -r)",
  "echo gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')",
  `f=$HOME/${TEMPLATES_REL}/${MARKER}`, "if [ -r $f ]; then echo templates=$(head -c 2000 $f | tr -d '\\n'); fi", "true",
].join("; ");

function kv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const l of decode(text).split("\n")) {
    const m = l.match(/^([a-z]+)=(.*)$/);
    if (m && !(m[1]! in out)) out[m[1]!] = m[2]!.trim();
  }
  return out;
}

/** How WSL reaches Windows: from `wslinfo --networking-mode`, else from the kernel name. */
export function networkingOf(net: string, kernel: string): string {
  const n = net.trim().toLowerCase();
  if (["mirrored", "nat", "virtioproxy", "none"].includes(n)) return n;
  if (/microsoft-standard/i.test(kernel)) return "nat"; // WSL 2 without wslinfo: NAT is its default
  if (/microsoft/i.test(kernel)) return "wsl1"; // WSL 1 shares the Windows network stack
  return "unknown";
}

/**
 * Where the proxy must listen on Windows, and the address the tool dials.
 *   mirrored, wsl1: the distro shares Windows' loopback: 127.0.0.1.
 *   nat: the Windows side of the WSL virtual switch is the distro's default
 *        gateway (a private address); the proxy binds to it only.
 *   override (options.toolbox.wsl.proxyHost): both, for unusual setups.
 */
export function proxyEndpoint(networking: string, gateway: string | undefined, override?: string): { listen: string; dial: string } | { error: string } {
  if (override) return isIP(override) ? { listen: override, dial: override } : { error: `options.toolbox.wsl.proxyHost must be an IP address (got ${JSON.stringify(override)})` };
  if (networking === "mirrored" || networking === "wsl1") return { listen: "127.0.0.1", dial: "127.0.0.1" };
  if (networking === "nat") {
    if (!gateway || !isIP(gateway)) return { error: "WSL is in NAT mode but its default gateway could not be read; set options.toolbox.wsl.proxyHost" };
    if (!isPrivateIp(gateway)) return { error: `WSL's default gateway ${gateway} is not a private address: refusing to listen on it; set options.toolbox.wsl.proxyHost` };
    return { listen: gateway, dial: gateway };
  }
  return { error: `cannot tell how WSL reaches Windows (networking: ${networking}); set options.toolbox.wsl.proxyHost` };
}

interface TemplatesMarker { filter?: string; version?: string; kept?: number }

/** Is the filtered template set made by this Crenel (same filter, same pinned version)? */
export function templatesState(markerJson: string | undefined, home: string | undefined, expectFilter = filterHash()): WslStatus["templates"] {
  const dir = home ? `${home}/${TEMPLATES_REL}` : undefined;
  if (!markerJson) return { ready: false, dir, reason: "filtered nuclei templates are not installed: run `crenel tools install --wsl`" };
  let m: TemplatesMarker;
  try { m = JSON.parse(markerJson) as TemplatesMarker; } catch { return { ready: false, dir, reason: "the templates marker is unreadable: run `crenel tools install --wsl` again" }; }
  if (m.filter !== expectFilter || m.version !== NUCLEI_TEMPLATES_VERSION) {
    return { ready: false, dir, version: m.version, kept: m.kept, reason: "the filtered templates were made by another Crenel version: run `crenel tools install --wsl` again" };
  }
  return { ready: true, dir, version: m.version, kept: m.kept };
}

const SAFE_HOME = /^\/[A-Za-z0-9._/-]+$/;

/** Status of the WSL backend. Never throws. */
export async function wslStatus(distro = DEFAULT_DISTRO, o: { exec?: WslExec; proxyHost?: string } = {}): Promise<WslStatus> {
  const exec = o.exec ?? realWsl;
  const tools = Object.fromEntries(TOOL_NAMES.map((t) => [t, null])) as Record<ToolName, string | null>;
  const base: WslStatus = { available: false, wsl: false, distro, distroPresent: false, distros: [], tools, templates: { ready: false } };
  if (!DISTRO_RE.test(distro)) return { ...base, reason: `invalid distro name ${JSON.stringify(distro)}` };
  const l = await exec(["-l", "-q"], { timeoutMs: 15_000 });
  if (l.code !== 0) {
    const missing = l.code === 127 || /ENOENT|not found|not recognized/i.test(l.stderr);
    return { ...base, reason: missing ? "WSL is not installed (wsl.exe not found; the WSL backend is Windows only)" : `wsl.exe failed: ${decode(l.stderr || l.stdout).trim().split("\n")[0] ?? ""}` };
  }
  const distros = decode(l.stdout).split("\n").map((s) => s.trim()).filter(Boolean);
  const present = distros.some((d) => d.toLowerCase() === distro.toLowerCase());
  const st: WslStatus = { ...base, wsl: true, distros, distroPresent: present };
  if (!present) return { ...st, reason: `WSL distro ${distro} is not installed (wsl --install -d ${distro}); installed: ${distros.join(", ") || "none"}` };

  const info = kv((await exec(["-d", distro, "--exec", "sh", "-c", INFO_SCRIPT], { timeoutMs: 30_000 })).stdout);
  const uid = /^\d+$/.test(info.uid ?? "") ? Number(info.uid) : undefined;
  const home = SAFE_HOME.test(info.home ?? "") ? info.home : undefined;
  st.uid = uid; st.user = info.user || undefined; st.home = home;
  st.networking = networkingOf(info.net ?? "", info.kernel ?? "");
  st.gateway = info.gw || undefined;
  st.templates = templatesState(info.templates, home);

  const w = await exec(["-d", distro, "--exec", "which", ...TOOL_NAMES.map((t) => WSL_BINARIES[t])], { timeoutMs: 15_000 });
  const paths = decode(w.stdout).split("\n").map((s) => s.trim()).filter((s) => s.startsWith("/"));
  for (const t of TOOL_NAMES) tools[t] = paths.find((p) => p.split("/").pop() === WSL_BINARIES[t]) ?? null;

  if (uid === undefined || !home) return { ...st, reason: `could not read the default user of ${distro}` };
  if (uid === 0) return { ...st, reason: `the default user of ${distro} is root: tools never run as root. Create a regular user and make it the default (${distro} config --default-user <name>)` };
  const ep = proxyEndpoint(st.networking, st.gateway, o.proxyHost);
  if ("error" in ep) return { ...st, reason: ep.error };
  return { ...st, endpoint: ep, available: true };
}

/** Why a tool cannot run on this distro, or null. */
export function wslToolBlocker(st: WslStatus, tool: ToolName): string | null {
  if (!st.available) return `toolbox off: ${st.reason}`;
  if (!st.tools[tool]) return `${WSL_BINARIES[tool]} is not installed in ${st.distro}: run \`crenel tools install --wsl\``;
  if (tool === "nuclei" && !st.templates.ready) return st.templates.reason ?? "filtered templates missing";
  return null;
}

/** Windows path -> path inside the distro (wslpath -u). */
export async function toWslPath(distro: string, winPath: string, exec: WslExec = realWsl): Promise<string> {
  if (winPath.startsWith("/")) return winPath; // already a Linux path (tests, or a project inside the distro)
  const r = await exec(["-d", distro, "--exec", "wslpath", "-u", winPath], { timeoutMs: 15_000 });
  const p = decode(r.stdout).trim();
  if (r.code !== 0 || !p.startsWith("/") || /[\n\0]/.test(p)) throw new Error(`wslpath could not map ${winPath}: ${decode(r.stderr).trim()}`);
  return p;
}

export interface WslRunOptions {
  tool: string;
  distro: string;
  exec?: WslExec;
  /** null = the tool needs no network: the proxy it is given refuses (and journals) everything. */
  scope: Scope | null;
  /** Receives the proxy URL as the tool sees it. argv[0] must be an allowlisted binary. */
  argvWithProxy: (proxyUrl: string) => string[];
  endpoint: { listen: string; dial: string };
  timeoutMs: number;
  proxy?: { ratePerSec?: number; maxRequests?: number };
  onEvent?: (e: ProxyEvent) => void;
  signal?: AbortSignal;
}

export interface WslRunResult extends ExecResult {
  network: "wsl+proxy";
  proxy: { requests: number; refused: number };
  /** The exact wsl.exe argv (the proxy credential replaced by ***), for the journal. */
  argv: string[];
}

/** Environment the tool gets, carried into the distro by WSLENV (and nothing else is). */
export function toolEnv(proxyUrl: string): Record<string, string> {
  const vars: Record<string, string> = {
    HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, http_proxy: proxyUrl, https_proxy: proxyUrl, ALL_PROXY: proxyUrl, all_proxy: proxyUrl,
    NO_PROXY: "", no_proxy: "",
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD: "true", DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD: "true",
  };
  return { ...vars, WSLENV: Object.keys(vars).join(":") };
}

/** wsl.exe argv for one tool run: default user (no -u), home directory, coreutils timeout. */
export function wslToolArgv(distro: string, timeoutMs: number, argv: string[]): string[] {
  const allowed = new Set(Object.values(WSL_BINARIES));
  if (!argv[0] || !allowed.has(argv[0])) throw new Error(`${argv[0] ?? "(empty)"} is not an allowlisted toolbox program`);
  if (!DISTRO_RE.test(distro)) throw new Error(`invalid distro name ${JSON.stringify(distro)}`);
  return ["-d", distro, "--cd", "~", "--exec", "timeout", "-k", "10", `${Math.max(1, Math.ceil(timeoutMs / 1000))}s`, ...argv];
}

/** Run one allowlisted tool in the distro, its traffic pointed at a scoped proxy started for the run. */
export async function runWsl(o: WslRunOptions): Promise<WslRunResult> {
  const exec = o.exec ?? realWsl;
  let proxy: EgressProxy | undefined;
  try {
    proxy = await startEgressProxy({ scope: o.scope ?? new Scope({ allowedHosts: [] }), host: o.endpoint.listen, tool: o.tool, onEvent: o.onEvent, ...o.proxy });
    const url = `http://crenel:${proxy.token}@${o.endpoint.dial.includes(":") ? `[${o.endpoint.dial}]` : o.endpoint.dial}:${proxy.port}`;
    const args = wslToolArgv(o.distro, o.timeoutMs, o.argvWithProxy(url));
    const r = await exec(args, { timeoutMs: o.timeoutMs + 30_000, env: { ...process.env, ...toolEnv(url) }, signal: o.signal });
    return {
      ...r, stdout: r.stdout, stderr: decode(r.stderr),
      timedOut: r.timedOut || r.code === 124 || r.code === 137,
      network: "wsl+proxy", proxy: { ...proxy.stats }, argv: args.map((a) => a.split(proxy!.token).join("***")),
    };
  } finally {
    await proxy?.close();
  }
}

/* ---------------- install (the only use of root) ---------------- */

export interface InstallStep {
  /** root: `wsl -d <distro> -u root` (no password); user: default user; host: Crenel itself on Windows. */
  as: "root" | "user" | "host";
  argv: string[];
  why: string;
}

// Download, verify and unpack the pinned templates, as the default user. $1 url, $2 sha256, $3 dir.
const FETCH_SCRIPT = [
  "set -eu", "tmp=$(mktemp -d)", "trap 'rm -rf $tmp' EXIT",
  "if command -v curl >/dev/null 2>&1; then curl -fsSL --proto =https -o $tmp/t.tgz $1; else wget -q -O $tmp/t.tgz $1; fi",
  "echo $2'  '$tmp/t.tgz | sha256sum -c - >/dev/null", "mkdir -p $3", "tar -xzf $tmp/t.tgz -C $3 --strip-components=1",
].join("; ");

/** Every step of `crenel tools install --wsl`, shown to the user before anything runs. */
export function installPlan(home: string): InstallStep[] {
  if (!SAFE_HOME.test(home) || home === "/") throw new Error(`unexpected home directory ${JSON.stringify(home)}`);
  const dir = `${home}/${TEMPLATES_REL}`;
  return [
    { as: "root", argv: ["apt-get", "update"], why: "refresh the package lists" },
    { as: "root", argv: ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", ...WSL_PACKAGES], why: "install the allowlisted tools (and curl for the templates)" },
    { as: "root", argv: ["rm", "-rf", dir], why: "remove a previous filtered template set (it is root-owned and read-only)" },
    { as: "user", argv: ["sh", "-c", FETCH_SCRIPT, "sh", NUCLEI_TEMPLATES_URL, NUCLEI_TEMPLATES_SHA256, dir], why: `download nuclei-templates v${NUCLEI_TEMPLATES_VERSION}, check its pinned sha256, unpack it` },
    { as: "host", argv: ["nuclei-filter", dir], why: "delete every template that is not on Crenel's allowlist (same filter as the Docker image)" },
    { as: "root", argv: ["chown", "-R", "root:root", dir], why: "make the filtered set owned by root" },
    { as: "root", argv: ["chmod", "-R", "a-w", dir], why: "and read-only, so the tools' user cannot add a template" },
  ];
}

/** Windows path of a file inside the distro (\\wsl.localhost\<distro>\..., or \\wsl$\ on older builds). */
export function uncPath(distro: string, linuxPath: string): string {
  const tail = linuxPath.replace(/\//g, "\\");
  const modern = `\\\\wsl.localhost\\${distro}`;
  return existsSync(modern) ? `${modern}${tail}` : `\\\\wsl$\\${distro}${tail}`;
}

export interface InstallIo {
  exec?: WslExec;
  /** Asked once, after the plan is printed. Nothing runs unless it resolves true. */
  confirm: (plan: InstallStep[]) => Promise<boolean>;
  out: (s: string) => void;
  /** Linux path in the distro -> path Crenel can open on Windows. Tests map it to a temp dir. */
  hostPath?: (distro: string, linuxPath: string) => string;
}

export interface InstallResult { ok: boolean; reason?: string; kept?: number; removed?: number; ran: InstallStep[] }

/** `crenel tools install --wsl`. Never asks for a password: WSL's `-u root` needs none. */
export async function installWsl(distro: string, io: InstallIo): Promise<InstallResult> {
  const exec = io.exec ?? realWsl;
  const st = await wslStatus(distro, { exec });
  if (!st.wsl || !st.distroPresent) return { ok: false, reason: st.reason, ran: [] };
  if (st.uid === 0) return { ok: false, reason: st.reason, ran: [] };
  if (!st.home) return { ok: false, reason: `could not read the default user of ${distro}`, ran: [] };
  const plan = installPlan(st.home);
  if (!(await io.confirm(plan))) return { ok: false, reason: "cancelled: nothing was run", ran: [] };
  const ran: InstallStep[] = [];
  let kept: number | undefined, removed: number | undefined;
  for (const step of plan) {
    io.out(`${step.as.padEnd(4)}  ${step.why}\n`);
    if (step.as === "host") {
      const dir = (io.hostPath ?? uncPath)(distro, step.argv[1]!);
      const r = pruneTemplates(dir);
      kept = r.kept; removed = r.removed;
      if (r.kept < 50) return { ok: false, reason: `only ${r.kept} templates left after filtering: the download looks wrong`, ran };
      writeFileSync(join(dir, MARKER), JSON.stringify({ filter: filterHash(), version: NUCLEI_TEMPLATES_VERSION, kept: r.kept, at: new Date().toISOString() }));
      ran.push(step);
      continue;
    }
    const args = ["-d", distro, ...(step.as === "root" ? ["-u", "root"] : []), "--exec", ...step.argv];
    const r = await exec(args, { timeoutMs: 20 * 60_000 });
    ran.push(step);
    if (r.code !== 0) return { ok: false, reason: `${step.argv.slice(0, 3).join(" ")} failed (exit ${r.code}): ${decode(r.stderr).trim().split("\n").slice(-3).join(" ")}`, ran };
  }
  return { ok: true, kept, removed, ran };
}
