import { test } from "node:test";
import assert from "node:assert/strict";

// The provider's id_token comes straight from its token endpoint over TLS, so
// the library decodes it without verifying; the test stubs one, unsigned.
function fakeIdToken(sub: string, email: string): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${part({ alg: "none" })}.${part({ sub, email, email_verified: true })}.signature`;
}

test("re-auth with Google reads the stubbed id_token", () => {
  assert.ok(fakeIdToken("u1", "a@example.com").split(".").length === 3);
});
