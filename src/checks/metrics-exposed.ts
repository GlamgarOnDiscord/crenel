// metrics-exposed: a Prometheus metrics endpoint served without auth leaks
// internal operational detail (routes, counts, versions, sometimes tokens in
// labels) and is a reconnaissance goldmine. The proof is the document itself: a
// 200 whose body is Prometheus exposition format (`# HELP`/`# TYPE` lines, or
// many `metric_name ... value` samples). An SPA answering index.html never
// matches. GETs on the declared base only. Generic, no target signature.

import type { Check, CheckContext, Finding } from "../core/types.js";
import { safeFetch } from "../core/net.js";

export const METRICS_PATHS = ["/metrics", "/actuator/prometheus", "/actuator/metrics", "/prometheus", "/metrics/prometheus"];

const HELP_TYPE = /^#\s+(HELP|TYPE)\s+\w/m;
const SAMPLE = /^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}\n]*\})?\s+-?[0-9]/m;

/** True when the body is Prometheus exposition format (not an HTML page). */
export function isPrometheus(body: string): boolean {
  const t = body.trimStart();
  if (!t || t.startsWith("<")) return false;
  if (HELP_TYPE.test(body)) return true;
  // No HELP/TYPE comments: require several metric samples to avoid false positives.
  const samples = (body.match(/^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}\n]*\})?\s+-?[0-9]/gm) ?? []).length;
  return samples >= 5 && SAMPLE.test(body);
}

export const metricsExposed: Check = {
  name: "metrics-exposed",
  title: "Prometheus metrics endpoint exposed without auth",
  readOnly: true,
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.stagingUrl) return [];
    const base = ctx.stagingUrl.replace(/\/+$/, "");
    if (!ctx.scope.isHostAllowed(base)) return [];
    const opts = (ctx.options["metrics-exposed"] ?? {}) as { paths?: string[] };
    for (const path of opts.paths ?? METRICS_PATHS) {
      try {
        const res = await safeFetch(base + path, ctx.scope, { headers: { accept: "text/plain" }, maxBytes: 128 * 1024 });
        if (res.status !== 200 || !isPrometheus(res.body)) continue;
        const names = [...new Set([...res.body.matchAll(/^#\s+HELP\s+(\w+)/gm)].map((m) => m[1]!))].slice(0, 8);
        return [{
          id: `metrics-exposed:${path}`,
          check: "metrics-exposed",
          title: `Prometheus metrics exposed without auth on ${path}`,
          severity: "medium",
          state: "proven",
          location: `${base}${path}`,
          description: `${path} serves Prometheus metrics to anyone${names.length ? ` (e.g. ${names.join(", ")})` : ""}: internal counts, route names and versions, useful for reconnaissance and sometimes leaking identifiers in labels.`,
          remediation: "Require auth on the metrics endpoint, or bind it to an internal interface / scrape network only.",
          proof: { method: "read-only GET, no credentials", replay: `curl -s '${base}${path}'`, evidence: `HTTP 200, Prometheus exposition format` },
          regressionHint: `After deploy, ${path} without credentials must not return Prometheus metrics.`,
        }];
      } catch { /* next path */ }
    }
    ctx.log("metrics-exposed: no open Prometheus endpoint on the usual paths");
    return [];
  },
};
