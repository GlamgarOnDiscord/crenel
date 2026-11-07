import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrivateIp } from "./net.js";

test("private and loopback addresses are refused", () => {
  for (const ip of ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.4.4", "172.31.255.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1"]) {
    assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
  }
});

// The exact cloud-metadata endpoints the 2026 agent SSRF CVEs target
// (PraisonAI, Pydantic AI, AgentScope). Pinned so the guard can never regress.
test("cloud metadata endpoints are refused, in every form", () => {
  for (const ip of [
    "169.254.169.254", // AWS/GCP IMDS (IPv4 link-local)
    "fd00:ec2::254", // AWS IMDS over IPv6 (unique-local)
    "100.100.100.200", // Alibaba metadata (CGNAT range)
    "::ffff:169.254.169.254", // IPv4-mapped link-local, dotted form
    "::ffff:a9fe:a9fe", // same address, hex-compressed v4-mapped form
    "::ffff:7f00:1", // 127.0.0.1 in hex-compressed v4-mapped form
  ]) {
    assert.equal(isPrivateIp(ip), true, `${ip} must be refused`);
  }
});

test("public addresses are allowed", () => {
  for (const ip of ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "11.0.0.1", "2606:4700:4700::1111"]) {
    assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
  }
});
