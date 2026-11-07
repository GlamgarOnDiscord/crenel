import { test } from "node:test";
import assert from "node:assert/strict";
import { isAllowedTemplate } from "../../toolbox/nuclei-filter.mjs";

const tpl = (tags: string, http: string, extraTop = "") => `id: t
info:
  name: T
  severity: info
  tags: ${tags}
${extraTop}http:
${http}
`;

const GET = `  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"`;

test("a GET-only exposure template in an allowed directory is kept", () => {
  assert.deepEqual(isAllowedTemplate(tpl("exposure,config,git", GET), "http/exposures/configs/git-config.yaml"), { ok: true, reason: "allowed" });
});

test("intrusive, dos, fuzz and attack tags are removed", () => {
  for (const t of ["intrusive", "dos", "fuzz", "sqli", "rce", "cve", "default-login", "oast"]) {
    assert.equal(isAllowedTemplate(tpl(`exposure,${t}`, GET), "http/exposures/x.yaml").ok, false, t);
  }
});

test("a template with no allowed tag, or outside the allowed directories, is removed", () => {
  assert.equal(isAllowedTemplate(tpl("wordpress", GET), "http/exposures/x.yaml").ok, false);
  for (const d of ["cves", "vulnerabilities", "fuzzing", "default-logins", "osint", "takeovers"]) {
    assert.equal(isAllowedTemplate(tpl("exposure", GET), `http/${d}/x.yaml`).ok, false, d);
  }
  assert.equal(isAllowedTemplate(tpl("exposure", GET), "network/x.yaml").ok, false);
});

test("any non GET/HEAD request, raw request, payloads, body or out-of-band use is removed", () => {
  const cases: [string, string][] = [
    ["POST", GET.replace("method: GET", "method: POST")],
    ["PUT", GET.replace("method: GET", "method: put")],
    ["raw", `  - raw:\n      - |\n        GET / HTTP/1.1\n        Host: {{Hostname}}`],
    ["payloads", `${GET}\n    payloads:\n      p: [a]`],
    ["body", `  - method: GET\n    body: "x"\n    path:\n      - "{{BaseURL}}/"`],
    ["interactsh", GET.replace("[core]", "{{interactsh-url}}")],
    ["absolute", `  - method: GET\n    path:\n      - "https://api.thirdparty.example/v1"`],
  ];
  for (const [name, http] of cases) assert.equal(isAllowedTemplate(tpl("exposure", http), "http/exposures/x.yaml").ok, false, name);
});

test("non-http top-level blocks (flow, code, javascript, dns...) are removed", () => {
  for (const k of ["flow: http(1)", "code:\n  - engine: [sh]", "javascript:\n  - code: x", "variables:\n  a: b"]) {
    assert.equal(isAllowedTemplate(tpl("exposure", GET, `${k}\n`), "http/exposures/x.yaml").ok, false, k);
  }
});
