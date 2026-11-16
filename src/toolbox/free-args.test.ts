import { test } from "node:test";
import assert from "node:assert/strict";
import { Scope } from "../core/scope.js";
import { freeArgsProblem } from "./free-args.js";

const scope = new Scope({ allowedHosts: ["staging.example.com", "127.0.0.1"], allowPrivate: true });

test("freeArgsProblem: a declared host target is allowed, scheme or not", () => {
  assert.equal(freeArgsProblem("httpx", ["https://staging.example.com/health"], scope), null);
  assert.equal(freeArgsProblem("nuclei", ["staging.example.com"], scope), null);
  assert.equal(freeArgsProblem("nuclei", ["staging.example.com:8443/app"], scope), null);
});

test("T3: a bare host target outside the perimeter is refused (defence in depth)", () => {
  // scheme-less positional host, the gap the proxy used to catch alone
  assert.match(String(freeArgsProblem("nuclei", ["evil.example"], scope)), /not in allowedHosts/);
  assert.match(String(freeArgsProblem("httpx", ["evil.example:8080"], scope)), /not in allowedHosts/);
  assert.match(String(freeArgsProblem("katana", ["evil.example/admin"], scope)), /not in allowedHosts/);
  assert.match(String(freeArgsProblem("nuclei", ["203.0.113.9"], scope)), /not in allowedHosts/);
});

test("T3: a domain-shaped FLAG VALUE is never mistaken for a target (no false positive)", () => {
  // value of a preceding flag: a match pattern that looks like a domain
  assert.equal(freeArgsProblem("httpx", ["-mr", "admin.example"], scope), null);
  // inline =value form on an allowed flag
  assert.equal(freeArgsProblem("httpx", ["-ms=login.portal"], scope), null);
  // a bare non-host word (tag-like, no dot) stays allowed
  assert.equal(freeArgsProblem("nuclei", ["-severity", "high"], scope), null);
});

test("freeArgsProblem: the existing guards still hold", () => {
  assert.match(String(freeArgsProblem("nuclei", ["-proxy", "http://x"], scope)), /set by Crenel|not allowed/);
  assert.match(String(freeArgsProblem("httpx", ["file:///etc/passwd"], scope)), /not http/);
  assert.match(String(freeArgsProblem("nuclei", ["/etc/passwd"], scope)), /outside the tool's temp dir/);
  assert.match(String(freeArgsProblem("httpx", ["--"], scope)), /end option parsing/);
});
