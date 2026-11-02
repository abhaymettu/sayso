import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { MAX_HOLD_SECONDS } from "../src/paths.mjs";
import { openAudit, verifyAudit } from "../src/audit.mjs";
import { matchesPassRule, matchesToolRule, normalizePolicy, PRESETS } from "../src/policy.mjs";
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
    ["mysql glued password", "mysql -uroot -pHunterTwo99 db", "mysql -uroot -p[redacted] db"],
    ["mysql glued lowercase password", "mysql -phunter db", "mysql -p[redacted] db"],
    ["glued password on an unknown program", "tool -pHunterTwo99 x", "tool -p[redacted] x"],
    ["PASS assignment", "PASS=hunter2 x", "PASS=[redacted] x"],
    ["DB_PASS assignment", "DB_PASS=hunter2 x", "DB_PASS=[redacted] x"],
    ["MYSQL_PWD assignment", "MYSQL_PWD=hunter2 x", "MYSQL_PWD=[redacted] x"],
    ["creds assignment", "creds=hunter2 x", "creds=[redacted] x"],
    ["password then a value", "password hunter2", "password [redacted]"],
    ["curl basic auth", "curl -u admin:hunter2 https://x.example", "curl -u admin:[redacted] https://x.example"],
    ["curl basic auth long flag", "curl --user admin:hunter2 https://x.example", "curl --user admin:[redacted] https://x.example"],
    ["aws configure", "aws configure set aws_secret_access_key wJalrXUtnFEMI", "aws configure set aws_secret_access_key [redacted]"],
    ["openssl pass", "openssl enc -pass pass:hunter2", "openssl enc -pass pass:[redacted]"],
    ["redis password", "redis-cli -h h -a hunter2 ping", "redis-cli -h h -a [redacted] ping"],
    ["zip password", "zip -P hunter2 a.zip b", "zip -P [redacted] a.zip b"],
    ["stripe live", "sk_live_51Habcdefgh", "[redacted key]"],
    ["stripe test", "rk_test_51Habcdefgh", "[redacted key]"],
    ["hugging face", "hf_abcdefghijklmnopqrstuv", "[redacted token]"],
    ["sendgrid", "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuv", "[redacted key]"],
    ["groq", "gsk_abcdefghijklmnopqrstuv", "[redacted token]"],
    ["xai", "xai-abcdefghijklmnopqrstuv", "[redacted key]"],
    ["google oauth", "ya29.abcdefghijklmnopqrstuv", "[redacted token]"],
    ["resend", "re_abcdefghijklmnopqrstuv", "[redacted key]"],
    ["digitalocean", "dop_v1_abcdefghijklmnopqrstuv", "[redacted token]"],
  ];
  for (const [name, input, expected] of cases) test(name, () => assert.equal(redact(input), expected));

  test("ordinary commands are left readable", () => {
    for (const text of [
      "rm -rf build",
      "git push origin main",
      "ls -la /tmp",
      "npm run test -- --watch",
      "curl https://example.com/a/b.json",
      "mkdir -p some/long/path",
      "docker run -p 8080:80 x",
      "docker run -u 1000:1000 x",
      "ssh -p 2222 host",
      "gcc -pthread a.c",
      "find . -print0",
      "PWD=/tmp/here tool",
      "git log --author=Someone",
      "passwd alice",
      "bypass=1 compass=2 tool",
      "the password is wrong",
      "mysql -p db",
    ]) assert.equal(redact(text), text);
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
    assert.match(faithful(`a${"  \n".repeat(30)}b`).text, /⟦30 blank lines⟧/);
  });
  for (const [name, blank] of [["nbsp", " "], ["em space", " "], ["braille blank", "⠀"], ["hangul filler", "ㅤ"], ["ideographic space", "　"], ["tab", "\t"]]) {
    test(`a long run of ${name} collapses like spaces and warns`, () => {
      const { text, warnings } = faithful(`echo hello${blank.repeat(400)}; rm -rf victim`);
      assert.equal(text, "echo hello⟦400 blank characters⟧; rm -rf victim");
      assert.deepEqual(warnings, ["long run of spaces"]);
    });
  }
  test("a mixed run of blanks collapses as one", () => {
    assert.equal(faithful(`a${"  ".repeat(20)}b`).text, "a⟦40 blank characters⟧b");
  });
  test("a single unusual blank shows as what it is, so rm\\u00a0-rf cannot read as rm -rf", () => {
    assert.deepEqual(faithful("rm -rf x"), { text: "rm⟦U+00A0⟧-rf x", warnings: ["unusual blank characters"] });
  });
  for (const [name, text] of [["armenian", "հ"], ["math bold", "𝐛"], ["long s", "ſ"], ["fullwidth", "ｒ"], ["greek", "ο"], ["cherokee", "Ꭺ"], ["fraction slash", "⁄"]]) {
    test(`look-alike letters include ${name}, shown as themselves`, () => {
      assert.deepEqual(faithful(text), { text, warnings: ["look-alike letters"] });
    });
  }
  test("line separators and more invisible characters are marked", () => {
    assert.equal(faithful("a b").text, "a⟦U+2028⟧b");
    assert.equal(faithful("a͏b").text, "a⟦U+034F⟧b");
    assert.equal(faithful("a️b").text, "a⟦U+FE0F⟧b");
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
  test("the wrapper's deadline sits between the longest hold and the hook timeout", () => {
    const root = new URL("..", import.meta.url);
    const limit = Number(/SAYSO_GATE_LIMIT:-(\d+)/.exec(fs.readFileSync(new URL("hooks/run.sh", root), "utf8"))[1]);
    const table = JSON.parse(fs.readFileSync(new URL("hooks/hooks.json", root), "utf8")).hooks;
    assert.ok(limit > MAX_HOLD_SECONDS + 30);
    for (const event of ["PreToolUse", "PermissionRequest"]) {
      assert.ok(limit < table[event][0].hooks[0].timeout);
      assert.equal(table[event][0].hooks[0].onFailure, "block");
    }
    for (const group of Object.values(table).flat()) for (const hook of group.hooks) assert.deepEqual([hook.command, hook.args.length], ["${CLAUDE_PLUGIN_ROOT}/hooks/run.sh", 1], "no shell starts a hook");
  });
  test("hold time stays under the hook timeout", () => {
    assert.equal(normalizePolicy({ hold_seconds: 99999 }).hold_seconds, 3000);
    assert.equal(normalizePolicy({ hold_seconds: 0 }).hold_seconds, 5);
  });
  test("trust_tools refuses a wildcard that doesn't name a whole server, and says so", () => {
    const p = normalizePolicy({ trust_tools: ["mcp__*", "mcp__git*", "mcp__x__*", "mcp__x__run", "nonsense"] });
    assert.deepEqual(p.trust_tools, ["mcp__x__*", "mcp__x__run"]);
    assert.equal(p.notes.filter((note) => /whole server/.test(note)).length, 3);
    assert.equal(matchesToolRule("mcp__x__evil", p.trust_tools), true);
    assert.equal(matchesToolRule("mcp__x__evil__tool", p.trust_tools), false, "a server named x__evil is another server");
    assert.equal(matchesToolRule("mcp__github-evil__run", ["mcp__git__*"]), false);
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
