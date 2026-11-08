import { test } from "node:test";
import assert from "node:assert/strict";
import { demoIntegrations, describeDelivery, sourceLabel } from "./integrations.ts";

test("integrations demo state carries no secret, only where each one comes from", () => {
  const json = JSON.stringify(demoIntegrations);
  assert.doesNotMatch(json, /hooks\.slack\.com\/services|secret"\s*:/);
  assert.equal(demoIntegrations.slack.destination, "https://hooks.slack.com/…");
});

test("a delivery line names the host and the status, never a path", () => {
  assert.equal(describeDelivery({ at: "", integration: "slack", event: "test", host: "hooks.slack.com", ok: false, status: 404, error: "no_service" }), "test vers hooks.slack.com, non envoyé (404): no_service");
  assert.equal(describeDelivery({ at: "", integration: "webhook:ops", event: "finding.proven", host: "h.example", ok: true, status: 204 }), "faille prouvée vers h.example, envoyé (204)");
  assert.equal(sourceLabel("env"), "variable d'environnement");
  assert.equal(sourceLabel(null), "absent");
});
