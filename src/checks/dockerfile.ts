// dockerfile: read the project's Dockerfile(s) and flag the container mistakes
// that bite real SaaS. Deterministic and offline, same spirit as ci-hardening:
// no code runs, we just read instructions.
//
//   - no USER: the container runs as root. Medium.
//   - a base image on :latest or with no tag: the build is not reproducible and
//     can pull a changed (or compromised) image. Low.
//   - a secret-looking ENV/ARG with an inline value: it is baked into an image
//     layer anyone who pulls the image can read. Medium.
//   - ADD from a URL: fetches remote content unverified into the image. Low.
//   - a remote script piped straight to a shell (curl ... | sh): arbitrary code
//     at build time. Medium.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import type { Check, CheckContext, Finding, Severity } from "../core/types.js";

function findRoot(start: string): string {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, "package.json")) || existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return start;
}

// Dockerfiles at the root: "Dockerfile", "Dockerfile.*", "*.Dockerfile".
function dockerfilesIn(root: string): string[] {
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return [];
  }
  return names
    .filter((n) => n === "Dockerfile" || n.startsWith("Dockerfile.") || n.endsWith(".Dockerfile"))
    .map((n) => join(root, n))
    .filter((p) => {
      try { return statSync(p).isFile(); } catch { return false; }
    });
}

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

// Keys whose inline value in ENV/ARG is very likely a secret.
const SECRETISH = /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*[=\s]\s*(\S+)/;

export const dockerfile: Check = {
  name: "dockerfile",
  title: "Container hardening in your Dockerfile(s) (root user, unpinned base, baked secrets)",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const root = findRoot(ctx.projectDir);
    const files = dockerfilesIn(root);
    if (files.length === 0) {
      ctx.log("dockerfile: no Dockerfile found");
      return findings;
    }
    const rel = (p: string) => relative(ctx.projectDir, p) || relative(root, p) || p;
    const push = (id: string, sev: Severity, title: string, loc: string, description: string, remediation: string, replay: string) =>
      findings.push({ id, check: "dockerfile", title, severity: sev, state: "unproven", location: loc, description, remediation, proof: { method: "read from Dockerfile", replay } });

    for (const file of files) {
      let text: string;
      try { text = readFileSync(file, "utf8"); } catch { continue; }
      const r = rel(file);
      const lines = text.split("\n");

      // USER: a Dockerfile with a FROM but no USER runs as root.
      const hasFrom = /^\s*FROM\s/im.test(text);
      const hasUser = lines.some((l) => /^\s*USER\s+(?!root\b)\S+/i.test(l));
      if (hasFrom && !hasUser) {
        push(`dockerfile:root:${r}`, "medium", `Container runs as root (no USER) in ${r}`, r,
          "No USER instruction sets a non-root user, so the container runs as root. A process escape then has root in the container.",
          "Add a non-root USER before the entrypoint, and own only the files it needs.",
          `grep -niE '^\\s*USER' "${r}"`);
      }

      // Base image tag.
      for (const m of text.matchAll(/^\s*FROM\s+(\S+)/gim)) {
        const image = m[1]!;
        if (image.startsWith("$")) continue; // build-arg image, cannot judge offline
        const tagless = !image.includes("@") && !/:[^/]+$/.test(image);
        const latest = /:latest$/i.test(image);
        if (tagless || latest) {
          push(`dockerfile:base:${r}:${lineOf(text, m.index!)}`, "low", `Base image not pinned (${image}) in ${r}`, `${r}:${lineOf(text, m.index!)}`,
            `${image} is ${latest ? "pinned to :latest" : "untagged"}, so the build is not reproducible and can pull a changed or compromised image.`,
            "Pin the base image to a digest (image@sha256:...) or at least an immutable version tag.",
            `grep -niE '^\\s*FROM' "${r}"`);
        }
      }

      // Inline secrets in ENV/ARG.
      for (const m of text.matchAll(/^\s*(ENV|ARG)\s+(.+)$/gim)) {
        const sm = m[2]!.match(SECRETISH);
        if (sm && sm[2] && sm[2] !== '""' && !sm[2].startsWith("$")) {
          push(`dockerfile:secret:${r}:${lineOf(text, m.index!)}`, "medium", `Secret-looking ${m[1]!.toUpperCase()} value in ${r}`, `${r}:${lineOf(text, m.index!)}`,
            `${sm[1]} is given an inline value in an ${m[1]!.toUpperCase()} instruction. It is baked into an image layer that anyone who pulls the image can read.`,
            "Pass secrets at run time (not build time), or use BuildKit secret mounts; never bake them into a layer.",
            `grep -niE '^\\s*(ENV|ARG)' "${r}"`);
        }
      }

      // ADD from a URL.
      for (const m of text.matchAll(/^\s*ADD\s+(https?:\/\/\S+)/gim)) {
        push(`dockerfile:add-url:${r}:${lineOf(text, m.index!)}`, "low", `ADD fetches a remote URL in ${r}`, `${r}:${lineOf(text, m.index!)}`,
          `ADD ${m[1]} pulls remote content into the image without integrity checks.`,
          "Prefer COPY of a vendored file, or fetch and verify a checksum explicitly in a RUN step.",
          `grep -niE '^\\s*ADD\\s+https?' "${r}"`);
      }

      // Pipe a remote script to a shell.
      for (const m of text.matchAll(/(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/gi)) {
        push(`dockerfile:pipe-sh:${r}:${lineOf(text, m.index!)}`, "medium", `Remote script piped to a shell in ${r}`, `${r}:${lineOf(text, m.index!)}`,
          "A remote script is piped straight into a shell at build time, so whoever controls that URL runs code in your build.",
          "Download to a file, verify a checksum, then run it; or vendor the script.",
          `grep -niE '(curl|wget).*\\|\\s*(ba)?sh' "${r}"`);
      }
    }

    ctx.log(`dockerfile: ${files.length} file(s), ${findings.length} finding(s)`);
    return findings;
  },
};
