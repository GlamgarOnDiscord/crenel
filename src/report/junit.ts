// JUnit XML, for CI systems that read test reports rather than SARIF (GitLab,
// Jenkins, Azure). One testcase per check that ran; every PROVEN finding is a
// failure of its check, leads are listed as system-out only (no proof, no
// failure: the same rule as the exit code).

import type { RunResult } from "../core/runner.js";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function toJunit(result: RunResult): string {
  const cases: string[] = [];
  let failures = 0;
  for (const check of result.checksRun) {
    const fs = result.findings.filter((f) => f.check === check);
    const proven = fs.filter((f) => f.state === "proven");
    const leads = fs.filter((f) => f.state !== "proven");
    failures += proven.length ? 1 : 0;
    const body = [
      ...proven.map((f) => `      <failure type="${f.severity}" message="${esc(f.title)}">${esc(`${f.location}\n${f.description}\nreplay: ${f.proof?.replay ?? "-"}`)}</failure>`),
      leads.length ? `      <system-out>${esc(leads.map((f) => `lead (${f.severity}): ${f.title} @ ${f.location}`).join("\n"))}</system-out>` : "",
    ].filter(Boolean);
    cases.push(`    <testcase classname="crenel" name="${esc(check)}">${body.length ? "\n" + body.join("\n") + "\n    " : ""}</testcase>`);
  }
  for (const e of result.errors) cases.push(`    <testcase classname="crenel" name="${esc(e.check)}">\n      <error message="${esc(e.message)}"/>\n    </testcase>`);
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="crenel" tests="${result.checksRun.length + result.errors.length}" failures="${failures}" errors="${result.errors.length}">`,
    `  <testsuite name="${esc(result.project)}" tests="${result.checksRun.length + result.errors.length}" failures="${failures}" errors="${result.errors.length}" timestamp="${result.startedAt}">`,
    ...cases,
    "  </testsuite>",
    "</testsuites>",
    "",
  ].join("\n");
}
