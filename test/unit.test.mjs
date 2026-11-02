import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { openAudit, verifyAudit } from "../src/audit.mjs";
import { matchesPassRule, normalizePolicy, PRESETS } from "../src/policy.mjs";
import { faithful, forDisplay, redact } from "../src/redact.mjs";
import { encodeDoc, generatePairing, signAsDevice, verifyApproval } from "../src/sign.mjs";

describe("redact", () => {
  const cases = [
    ["anthropic key", "x sk-ant-api03-abcDEF123456789012345678 y", "x [redacted key] y"],
    ["openai key", "sk-proj-abcDEF1234567890abcDEF", "[redacted key]"],
    ["github token", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "token [redacted token]"],
    ["github fine grained", "github_pat_11ABCDEFG0abcdefghijkl", "[redacted token]"],
    ["slack", "xoxb-1234567890-abcdefghij", "[redacted token]"],
    ["aws", "AKIAIOSFODNN7EXAMPLE", "[redacted key]"],
    ["google", "AIzaSyA1234567890abcdefghijklmnopqrstuv", "[redacted key]"],
    ["jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123def456", "[redacted jwt]"],
    ["bearer", "Authorization: Bearer abc123def456ghi", "Authorization: [redacted] [redacted]"],
    ["basic in url", "https://bob:hunter2@example.com/x", "https://bob:[redacted]@example.com/x"],
    ["env assignment", "API_KEY=abc123 curl x", "API_KEY=[redacted] curl x"],
    ["quoted assignment", 'password="two words" next', "password=[redacted] next"],
    ["flag with value", "mysql --password hunter2-long", "mysql --password [redacted]"],
    ["json field", '{"secret": "abc123"}', '{"secret": [redacted]}'],
    ["private key", "-----BEGIN RSA PRIVATE KEY-----\nabc\ndef\n-----END RSA PRIVATE KEY-----", "[redacted private key]"],
    ["long hex", "a".repeat(64), "[redacted hex]"],
    ["sayso's own token", "sayso_agent_abcdefg", "[redacted token]"],
  ];
  for (const [name, input, expected] of cases) test(name, () => assert.equal(redact(input), expected));

  test("ordinary commands are left readable", () => {
    for (const text of ["rm -rf build", "git push origin main", "ls -la /tmp", "npm run test -- --watch", "curl https://example.com/a/b.json"]) assert.equal(redact(text), text);
  });
});

describe("faithful display", () => {
  test("hidden characters become visible marks with a warning", () => {
    assert.deepEqual(faithful("a‮b"), { text: "a⟦U+202E⟧b", warnings: ["text direction overrides"] });
    assert.deepEqual(faithful("a​b"), { text: "a⟦U+200B⟧b", warnings: ["invisible characters"] });
    assert.deepEqual(faithful("a\u001b[2Kb"), { text: "a⟦U+001B⟧[2Kb", warnings: ["control characters"] });
    assert.deepEqual(faithful("a\u{E0061}"), { text: "a⟦tag a⟧", warnings: ["hidden tag characters"] });
    assert.deepEqual(faithful("rм -rf x"), { text: "rм -rf x", warnings: ["look-alike letters"] });
  });
  test("runs of spaces and blank lines cannot push text out of view", () => {
    assert.equal(faithful(`a${" ".repeat(50)}b`).text, "a⟦50 spaces⟧b");
    assert.match(faithful(`a${"\n".repeat(30)}b`).text, /⟦30 blank lines⟧/);
  });
  test("over the limit it keeps both ends and says so", () => {
    const shown = forDisplay(`start ${"x y ".repeat(2000)} end`, 200);
    assert.equal(shown.truncated, true);
    assert.ok(shown.warnings.includes("too long to show in full"));
    assert.match(shown.text, /^start /);
    assert.match(shown.text, / end$/);
    assert.match(shown.text, /characters not shown/);
  });
});

describe("policy", () => {
  test("nothing configured means strict", () => {
    const p = normalizePolicy({});
    assert.equal(p.preset, "strict");
    for (const risk of Object.keys(PRESETS.strict.approver)) assert.equal(p.approver[risk], "human");
    assert.equal(p.questions, "options");
    assert.equal(p.messages, false);
  });
  test("catastrophic and self cannot be lowered", () => {
    const p = normalizePolicy({ preset: "trusted-agent", approver: { catastrophic: "agent", self: "agent", destructive: "agent" } });
    assert.equal(p.approver.catastrophic, "human");
    assert.equal(p.approver.self, "human");
    assert.equal(p.approver.destructive, "agent");
    assert.equal(p.notes.length, 2);
  });
  test("hold time stays under the hook timeout", () => {
    assert.equal(normalizePolicy({ hold_seconds: 99999 }).hold_seconds, 3000);
    assert.equal(normalizePolicy({ hold_seconds: 0 }).hold_seconds, 5);
  });
  test("a pass rule never covers a compound command", () => {
    const rules = ["rm -rf cache", "rm -rf cache/.*"];
    assert.equal(matchesPassRule("rm -rf cache", rules), true);
    assert.equal(matchesPassRule("rm -rf cache/a/b", rules), true);
    for (const bad of ["rm -rf cache; rm -rf ~", "rm -rf cache && x", "rm -rf cache | sh", "rm -rf cache/$(whoami)", "rm -rf cache\nrm -rf ~", "rm -rf cache/`x`", "x rm -rf cache"]) {
      assert.equal(matchesPassRule(bad, rules), false, bad);
    }
    assert.equal(matchesPassRule("rm -rf cache", ["(unclosed"]), false);
  });
});

describe("signature", () => {
  const device = generatePairing();
  const keys = [{ id: device.id, public_key: device.public_key, name: "phone" }];
  const doc = encodeDoc({ id: "r_1", display: "rm -rf build" });
  test("a device signature over the document verifies", () => {
    assert.equal(verifyApproval(doc, signAsDevice(doc, device.pkcs8, device.id), keys).ok, true);
  });
  test("one changed character in the document fails", () => {
    const other = encodeDoc({ id: "r_1", display: "rm -rf builf" });
    assert.equal(verifyApproval(other, signAsDevice(doc, device.pkcs8, device.id), keys).ok, false);
  });
  test("an unpaired key fails, even claiming a paired id", () => {
    const stranger = generatePairing();
    assert.equal(verifyApproval(doc, signAsDevice(doc, stranger.pkcs8, stranger.id), keys).ok, false);
    assert.equal(verifyApproval(doc, signAsDevice(doc, stranger.pkcs8, device.id), keys).ok, false);
  });
  test("malformed codes fail without throwing", () => {
    for (const code of ["", "yes", "sayso1.x.y", `sayso1.${device.id}.${"!".repeat(86)}`, null, undefined, 7]) assert.equal(verifyApproval(doc, code, keys).ok, false);
  });
});

describe("audit", () => {
  test("appends across reopen stay chained, and edits show", () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "audit-")), "a.jsonl");
    openAudit(file).append({ decision: "opened" });
    openAudit(file).append({ decision: "denied" });
    assert.deepEqual(verifyAudit(file), { ok: true, count: 2 });
    fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("denied", "approved"));
    assert.equal(verifyAudit(file).ok, false);
  });
});
