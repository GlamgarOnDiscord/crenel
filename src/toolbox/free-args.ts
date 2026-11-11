// Free arguments for the toolbox (free exploration, `toolbox.run`).
//
// A model may pick its own flags for an allowlisted tool, but never the ones
// that matter for safety: the egress proxy, the rate, where files are written,
// what code runs locally. Those are refused here, and Crenel's own values are
// set before and after them (the proxy, the rate, nuclei's denied tags), so a run with free
// arguments still leaves only through the scoped proxy, within the budget. Any
// URL must be on a declared host; any path must be a relative template path or
// the tool's temp dir, never a file elsewhere on the machine.

import { ALLOWED_TAGS, DENIED_TAGS } from "../../toolbox/nuclei-filter.mjs";
import type { Scope } from "../core/scope.js";
import type { ToolName } from "./names.js";

/** The only place a tool may write (inside the container or WSL session). */
export const FREE_TMP = "/tmp/crenel-explore/";
const READ_ONLY_PREFIXES = ["/opt/nuclei-templates/"];

// Flags refused for every tool: proxy, output files, config files, updates,
// local code, headless browsers, rate and concurrency (Crenel sets them).
const COMMON_DENY = [
  "proxy", "http-proxy", "proxy-url", "socks-proxy", "no-proxy",
  "o", "output", "sr", "store-response", "srd", "store-response-dir", "store-chain",
  "config", "fc", "form-config", "flc", "field-config", "rc", "resolvers", "r",
  "update", "up", "ut", "update-templates", "ud", "update-template-dir", "duc",
  "resume", "project", "project-path", "elog", "error-log", "tlog", "trace-log",
  "headless", "system-chrome", "sc-path", "system-chrome-path", "cdd", "chrome-data-dir", "hh", "headless-options",
  "rl", "rate-limit", "rlm", "rate-limit-minute", "c", "concurrency", "bs", "bulk-size", "hbs", "headless-bulk-size", "pc", "payload-concurrency",
  "l", "list", "rr", "request", "input-file",
  "ss", "screenshot", "esb", "exclude-screenshot-bytes",
  "je", "json-export", "jle", "jsonl-export", "me", "markdown-export", "se", "sarif-export", "irr", "include-rr",
];
const PER_TOOL_DENY: Record<ToolName, string[]> = {
  nuclei: [
    "p", "code", "lfa", "allow-local-file-access", "ev", "env-vars", "itags", "include-tags", "etags", "exclude-tags",
    "it", "include-templates", "dast", "fuzz", "iserver", "interactsh-server", "interactsh-url", "itoken", "interactsh-token",
    "sf", "secret-file", "tp", "template-profile", "dut", "disable-unsigned-templates", "w", "workflows", "wu", "workflow-url", "tu", "template-url",
    "cloud", "dashboard", "pd", "auth", "ps", "passive",
    "pt", "type", "ept", "exclude-type", "sresp", "store-resp", "store-resp-dir", "profile-mem",
  ],
  katana: ["kf", "known-files", "jc", "js-crawl", "jsl", "jsluice", "xhr", "xhr-extraction", "aff", "automatic-form-fill", "ef", "extension-filter", "p", "parallelism", "sf", "store-field", "sfd", "store-field-dir", "cwu", "chrome-ws-url"],
  httpx: ["t", "threads", "pa", "probe-all-ips", "asn", "cdn", "ldv", "list-dsl-variables", "fep", "favicon"],
  trufflehog: [],
};
// trufflehog runs on the read-only project with no network: only these flags.
const TRUFFLEHOG_ALLOW = new Set(["results", "include-detectors", "exclude-detectors", "include-paths", "exclude-paths", "max-depth", "json", "no-update", "no-verification", "fail"]);

const flagName = (a: string) => a.replace(/^-+/, "").split("=")[0]!.toLowerCase();

/** Why these free arguments are refused, or null when they may run. */
export function freeArgsProblem(tool: ToolName, args: unknown, scope: Scope): string | null {
  if (!Array.isArray(args)) return "args must be a list of strings";
  if (args.length > 40) return "at most 40 arguments";
  const deny = new Set([...COMMON_DENY, ...PER_TOOL_DENY[tool]]);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (typeof a !== "string" || !a.length || a.length > 300) return `argument ${i + 1} is not a short string`;
    if (/[\u0000-\u001f]/.test(a)) return `argument ${i + 1} has a control character`;
    // "--" or "-" ends option parsing in Go's flag package: Crenel's own flags after it would be ignored.
    if (a === "--" || a === "-") return `argument ${i + 1} (${a}) would end option parsing`;
    if (a.startsWith("-")) {
      const f = flagName(a);
      if (tool === "trufflehog" ? !TRUFFLEHOG_ALLOW.has(f) : deny.has(f)) return `flag ${a.split("=")[0]} is set by Crenel or not allowed (proxy, rate, files, local code)`;
      if (tool === "nuclei" && (f === "tags" || f === "t" || f === "templates")) {
        const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : String(args[i + 1] ?? "");
        if (f === "tags" && v.split(",").some((t) => t && !ALLOWED_TAGS.includes(t.trim().toLowerCase()))) return `nuclei tags must be among ${ALLOWED_TAGS.join(", ")}`;
        if (f !== "tags" && !/^(http\/|\/opt\/nuclei-templates\/http\/)[\w./-]*$/.test(v)) return "nuclei templates only from the bundled http/ directory";
      }
    }
    const value = a.includes("=") && a.startsWith("-") ? a.slice(a.indexOf("=") + 1) : a;
    for (const piece of value.split(",")) {
      const p = piece.trim();
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) {
        let u: URL;
        try { u = new URL(p); } catch { return `${p.slice(0, 80)} is not a URL`; }
        if (u.protocol !== "http:" && u.protocol !== "https:") return `${u.protocol} is not http(s)`;
        if (!scope.isHostAllowed(p)) return `${u.hostname} is not in allowedHosts`;
        continue;
      }
      if (/^(file|data|gopher|ftp|dict|ldap|jar):/i.test(p)) return `${p.slice(0, 20)} is not http(s)`;
      if (p.startsWith("~") || p.startsWith("@") || p.includes("..") || p.includes("\\") || /^[A-Za-z]:/.test(p)) return `${p.slice(0, 80)} looks like a path outside the tool's temp dir`;
      if (p.startsWith("/") && !p.startsWith(FREE_TMP) && !READ_ONLY_PREFIXES.some((r) => p.startsWith(r))) return `${p.slice(0, 80)} is a path outside the tool's temp dir (${FREE_TMP})`;
    }
  }
  return null;
}

/**
 * The argv that runs: the tool, Crenel's own flags (proxy, rate, denied tags,
 * no update check), the model's arguments, then Crenel's flags again. First,
 * because Go's flag package stops at the first non-flag argument (a stray word,
 * or a trailing flag that swallows the next one as its value), so flags after
 * the model's could be dropped; last, so a single-value flag keeps Crenel's
 * value. A target is added when the model gave none.
 */
export function freeArgv(tool: ToolName, args: string[], p: { proxy: string; projectRoot: string; templatesDir: string }, o: { ratePerSec: number; target?: string; hosts?: string[] }): string[] {
  const rate = String(Math.max(1, Math.floor(o.ratePerSec)));
  const hasTarget = args.some((a) => ["u", "target", "url"].includes(flagName(a)) && a.startsWith("-"));
  const target = hasTarget ? [] : tool === "httpx" ? ["-u", (o.hosts ?? []).join(",")] : o.target ? ["-u", o.target] : [];
  if (tool === "trufflehog") return ["trufflehog", "filesystem", p.projectRoot, ...args, "--json", "--no-update", "--no-verification"];
  if (tool === "nuclei") {
    const t = args.some((a) => ["t", "templates", "id", "tags"].includes(flagName(a))) ? [] : ["-t", `${p.templatesDir}/http`];
    const own = ["-etags", DENIED_TAGS.join(","), "-pt", "http", "-proxy", p.proxy, "-rl", rate, "-c", "5", "-jsonl", "-silent", "-nc", "-omit-raw", "-duc", "-ni", "-no-stdin"];
    return ["nuclei", ...own, ...target, ...t, ...args.map((a) => a.replace(/^http\//, `${p.templatesDir}/http/`)), ...own];
  }
  if (tool === "katana") {
    const own = ["-fs", "fqdn", "-proxy", p.proxy, "-rl", rate, "-c", "2", "-p", "1", "-jsonl", "-silent", "-nc", "-duc"];
    return ["katana", ...own, ...target, ...args, ...own];
  }
  const own = ["-http-proxy", p.proxy, "-rl", rate, "-t", "5", "-json", "-silent", "-nc", "-duc"];
  return ["httpx", ...own, ...target, ...args, ...own];
}
