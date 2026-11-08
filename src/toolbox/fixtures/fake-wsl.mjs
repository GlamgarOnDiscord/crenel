// A fake `wsl.exe` for the CI-safe WSL tests (this repo is developed on Linux).
//
// It behaves like wsl.exe where Crenel depends on it:
//   - `-l -q` prints the distros in UTF-16LE (as older wsl.exe builds do);
//   - `-d <distro> [-u <user>] [--cd <dir>] --exec <prog> <args...>` runs <prog>
//     without a shell, as the default user unless -u is given;
//   - only the variables listed in WSLENV cross into the "distro";
//   - nuclei, katana and trufflehog are small stand-ins that talk to Crenel's
//     proxy exactly like the real tools would (through -proxy or HTTP_PROXY).
//
// Configuration: FAKE_WSL=<json file> (see wsl.test.ts). Every call is appended
// to the "log" file of that config, with what the distro saw.

import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { join } from "node:path";

const cfg = JSON.parse(readFileSync(process.env.FAKE_WSL, "utf8"));
const argv = process.argv.slice(2);
const crossed = (process.env.WSLENV ?? "").split(":").filter(Boolean).map((v) => v.split("/")[0]);
const env = Object.fromEntries(crossed.filter((k) => k in process.env).map((k) => [k, process.env[k]]));
const fsPath = (p) => join(cfg.root, p);

function log(extra) {
  appendFileSync(cfg.log, JSON.stringify({ argv, crossed, ...extra }) + "\n");
}
function out(s) { process.stdout.write(s); }
function done(code) { process.exitCode = code; }

/** GET `url` through an http://user:pass@host:port proxy. Resolves the status, 0 when nothing answered. */
function viaProxy(proxyUrl, url) {
  return new Promise((resolve) => {
    if (!proxyUrl) return resolve(0);
    const p = new URL(proxyUrl);
    const auth = Buffer.from(`${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`).toString("base64");
    const req = request({ host: p.hostname.replace(/^\[|\]$/g, ""), port: Number(p.port), method: "GET", path: url, headers: { host: new URL(url).host, "proxy-authorization": `Basic ${auth}` }, timeout: 5000 }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", () => resolve(0));
    req.on("timeout", () => { req.destroy(); resolve(0); });
    req.end();
  });
}

const flag = (args, name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

async function tool(args) {
  const [prog, ...rest] = args;
  if (prog === "nuclei") {
    const target = flag(rest, "-u");
    const proxy = flag(rest, "-proxy");
    const status = await viaProxy(proxy, target);
    const stray = await viaProxy(proxy, "http://example.com/");
    log({ tool: "nuclei", proxy: !!proxy, envProxy: !!env.HTTP_PROXY, templates: flag(rest, "-t"), status, stray });
    if (status === 200) out(JSON.stringify({ "template-id": "http-missing-security-headers", "matcher-name": "x-frame-options", "matched-at": target, info: { name: "HTTP Missing Security Headers", severity: "info" } }) + "\n");
    out(JSON.stringify({ "template-id": "x", "matched-at": "http://evil.example/", info: { name: "off scope", severity: "high" } }) + "\n");
    return 0;
  }
  if (prog === "katana") {
    const target = flag(rest, "-u");
    const proxy = flag(rest, "-proxy");
    const page = new URL("/api/invoices/inv_b_1", target).toString();
    const s1 = await viaProxy(proxy, target);
    const s2 = await viaProxy(proxy, page);
    log({ tool: "katana", proxy: !!proxy, s1, s2 });
    out(JSON.stringify({ request: { method: "GET", endpoint: page }, response: { status_code: s2 } }) + "\n");
    return 0;
  }
  if (prog === "httpx-toolkit") {
    const proxy = flag(rest, "-http-proxy");
    for (const h of (flag(rest, "-u") ?? "").split(",").filter(Boolean)) {
      const url = `http://${h}/`;
      const status = await viaProxy(proxy, url);
      log({ tool: "httpx", proxy: !!proxy, url, status });
      if (status) out(JSON.stringify({ url: url.slice(0, -1), status_code: status, webserver: "nginx/1.18.0", tech: ["Nginx"] }) + "\n");
    }
    return 0;
  }
  if (prog === "trufflehog") {
    const root = rest[1];
    // trufflehog needs no network: a stray request must hit the proxy that refuses everything.
    const stray = await viaProxy(env.HTTPS_PROXY, "http://example.com/");
    log({ tool: "trufflehog", root, envProxy: !!env.HTTPS_PROXY, stray });
    const walk = (d) => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? (n === ".crenel" ? [] : walk(p)) : [p]; });
    for (const f of walk(root)) {
      readFileSync(f, "utf8").split("\n").forEach((l, i) => {
        const m = l.match(/ghp_[A-Za-z0-9]{36}/);
        if (m) out(JSON.stringify({ SourceMetadata: { Data: { Filesystem: { file: f, line: i + 1 } } }, DetectorName: "Github", Verified: false, Raw: m[0] }) + "\n");
      });
    }
    return 0;
  }
  process.stderr.write(`fake wsl: ${prog}: command not found\n`);
  return 127;
}

const ALLOWED_TPL = (i) => `id: t${i}\ninfo:\n  name: T${i}\n  severity: info\n  tags: exposure,config\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/.git/config${i}"\n    matchers:\n      - type: word\n        words:\n          - "[core]"\n`;
const DENIED_TPL = (i) => `id: d${i}\ninfo:\n  name: D${i}\n  severity: high\n  tags: exposure,rce\nhttp:\n  - method: POST\n    path:\n      - "{{BaseURL}}/x"\n`;

async function main() {
  if (argv[0] === "-l") {
    log({});
    const text = cfg.distros.join("\r\n") + "\r\n";
    process.stdout.write(cfg.utf16 ? Buffer.from("\uFEFF" + text, "utf16le") : text);
    return 0;
  }
  const distro = flag(argv, "-d");
  const user = flag(argv, "-u") ?? cfg.user;
  const at = argv.indexOf("--exec");
  const cmd = at >= 0 ? argv.slice(at + 1) : [];
  log({ distro, user });
  if (!cfg.distros.includes(distro)) { process.stderr.write(`There is no distribution with the supplied name.\n`); return 1; }
  const [prog, ...args] = cmd;
  const asRoot = user === "root";
  switch (prog) {
    case "sh": {
      const script = args[1] ?? "";
      if (script.includes("echo uid=")) {
        const marker = fsPath(`${cfg.home}/.crenel/nuclei-templates/.crenel-filtered`);
        const tm = existsSync(marker) ? readFileSync(marker, "utf8") : cfg.templatesMarker;
        out([`uid=${asRoot ? 0 : cfg.uid}`, `user=${asRoot ? "root" : cfg.user}`, `home=${asRoot ? "/root" : cfg.home}`, `net=${cfg.net ?? ""}`, `kernel=${cfg.kernel}`, `gw=${cfg.gw ?? ""}`, ...(tm ? [`templates=${tm}`] : [])].join("\n") + "\n");
        return 0;
      }
      if (script.includes("sha256sum")) {
        const dir = fsPath(args[5]);
        mkdirSync(join(dir, "http", "exposures"), { recursive: true });
        mkdirSync(join(dir, "http", "cves"), { recursive: true });
        for (let i = 0; i < 60; i++) writeFileSync(join(dir, "http", "exposures", `t${i}.yaml`), ALLOWED_TPL(i));
        for (let i = 0; i < 5; i++) writeFileSync(join(dir, "http", "cves", `d${i}.yaml`), DENIED_TPL(i));
        log({ fetched: args[3], sha: args[4], asRoot });
        return 0;
      }
      if (script.includes("curl -s -o /dev/null")) {
        const lines = [];
        for (const seg of script.split("; ")) {
          const m = seg.match(/^c=\$\(curl .*? (--noproxy '\*' )?'(.*)' 2>\/dev\/null\)$/);
          const e = seg.match(/^echo (\d+) \$c$/);
          if (m) lines.push({ direct: !!m[1], url: m[2] });
          if (e) {
            const p = lines[lines.length - 1];
            const code = p.direct ? (cfg.directOpen ? 200 : 0) : await viaProxy(env.http_proxy, p.url);
            out(`${e[1]} ${code === 0 ? "000" : code}\n`);
          }
        }
        return 0;
      }
      return 2;
    }
    case "which": {
      let missing = 0;
      for (const n of args) { const p = cfg.tools[n]; if (p) out(p + "\n"); else missing++; }
      return missing ? 1 : 0;
    }
    case "wslpath": return out(args[1].replace(/^([A-Za-z]):\\/, (_, d) => `/mnt/${d.toLowerCase()}/`).replace(/\\/g, "/") + "\n"), 0;
    case "env": case "apt-get": case "chown": case "chmod":
      if (!asRoot) { process.stderr.write("E: Permission denied\n"); return 100; }
      return 0;
    case "rm":
      if (!asRoot) { process.stderr.write("rm: Permission denied\n"); return 1; }
      rmSync(fsPath(args[1]), { recursive: true, force: true });
      return 0;
    case "timeout": {
      if (cfg.timeout) return 124;
      return tool(args.slice(3));
    }
    default:
      process.stderr.write(`fake wsl: ${prog}: not emulated\n`);
      return 127;
  }
}

main().then((c) => done(c ?? 0), (e) => { process.stderr.write(String(e?.stack ?? e)); done(1); });
