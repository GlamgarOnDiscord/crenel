// Spawn a program without a shell, with capped output, a wall-clock timeout
// and an abort signal. Shared by the Docker and WSL backends.

import { spawn } from "node:child_process";

export interface ExecResult { code: number; stdout: string; stderr: string; timedOut: boolean }
export interface ExecOptions {
  timeoutMs?: number; env?: NodeJS.ProcessEnv; maxBytes?: number; signal?: AbortSignal;
  /** Bytes -> text, once the stream is complete (default UTF-8). wsl.exe may print UTF-16LE. */
  decode?: (b: Buffer) => string;
}

/** Run `bin <args>` without a shell. Output is capped (default 16 MB per stream). Never throws. */
export function execCapped(bin: string, args: string[], o: ExecOptions = {}): Promise<ExecResult> {
  const max = o.maxBytes ?? 16 * 1024 * 1024;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { env: o.env ?? process.env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    } catch (err) {
      return resolve({ code: 127, stdout: "", stderr: (err as Error).message, timedOut: false });
    }
    const out: Buffer[] = [], errb: Buffer[] = [];
    let outLen = 0, errLen = 0, err = "", timedOut = false, spawnFailed = false;
    child.stdout.on("data", (b: Buffer) => { if (outLen < max) { out.push(b); outLen += b.length; } });
    child.stderr.on("data", (b: Buffer) => { if (errLen < max) { errb.push(b); errLen += b.length; } });
    const dec = o.decode ?? ((b: Buffer) => b.toString("utf8"));
    const t = o.timeoutMs ? setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, o.timeoutMs) : undefined;
    const onAbort = () => child.kill("SIGKILL");
    o.signal?.addEventListener("abort", onAbort, { once: true });
    child.on("error", (e: NodeJS.ErrnoException) => { err += e.message; if (e.code === "ENOENT") spawnFailed = true; });
    child.on("close", (code) => {
      if (t) clearTimeout(t);
      o.signal?.removeEventListener("abort", onAbort);
      resolve({ code: spawnFailed ? 127 : code ?? 1, stdout: dec(Buffer.concat(out)), stderr: dec(Buffer.concat(errb)) + err, timedOut });
    });
  });
}
