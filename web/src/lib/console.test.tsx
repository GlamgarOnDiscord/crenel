import { test } from "node:test";
import assert from "node:assert/strict";
import { ciWorkflowYaml, failOnOf, revokeHelp, SCHEDULE_YAML } from "./console.ts";

test("revokeHelp: provider from the finding title or the masked value", () => {
  assert.equal(revokeHelp("Stripe secret key (live)")?.provider, "Stripe");
  assert.equal(revokeHelp("Clé secrète", "sk_live_••••3f9a")?.provider, "Stripe");
  assert.equal(revokeHelp("AWS access key id")?.url, "https://console.aws.amazon.com/iam/home#/security_credentials");
  assert.equal(revokeHelp("Clé API Google", "AIzaSy••••")?.url, "https://console.cloud.google.com/apis/credentials");
  assert.equal(revokeHelp("GitHub personal access token")?.url, "https://github.com/settings/tokens");
  assert.equal(revokeHelp("OpenAI project API key")?.url, "https://platform.openai.com/api-keys");
  assert.equal(revokeHelp("Clé", "sk-ant-••••")?.provider, "Anthropic", "sk-ant- is Anthropic, not OpenAI");
  assert.equal(revokeHelp("Anthropic API key")?.url, "https://platform.claude.com/settings/keys");
  assert.equal(revokeHelp("Slack token")?.url, "https://api.slack.com/apps");
  assert.equal(revokeHelp("Clé privée (PEM)", "-----BEGIN PRIVATE KEY-----"), null, "unknown provider: generic guidance");
});

test("failOnOf: high covers critical, nothing means never fail", () => {
  assert.equal(failOnOf({ critical: true, high: true }), "high");
  assert.equal(failOnOf({ critical: false, high: true }), "high");
  assert.equal(failOnOf({ critical: true, high: false }), "critical");
  assert.equal(failOnOf({ critical: false, high: false }), null);
});

test("ciWorkflowYaml: uses the action inputs and the chosen fail-on", () => {
  const y = ciWorkflowYaml({ critical: true, high: false });
  assert.match(y, /uses: GlamgarOnDiscord\/crenel@<sha>/);
  assert.match(y, /config: crenel\.config\.yaml/);
  assert.match(y, /fail-on: critical\n/);
  assert.match(y, /security-events: write/);
  assert.doesNotMatch(y, /continue-on-error/);
  const never = ciWorkflowYaml({ critical: false, high: false });
  assert.match(never, /continue-on-error: true/);
  assert.match(ciWorkflowYaml({ critical: true, high: true }, ""), /fail-on: high/);
  assert.doesNotMatch(ciWorkflowYaml({ critical: true, high: true }, ""), /schedule/);
  assert.match(SCHEDULE_YAML, /cron: "0 6 \* \* \*"/);
});
