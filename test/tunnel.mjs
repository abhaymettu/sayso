#!/usr/bin/env node
// The recipe in the README for an agent on another machine: a quick tunnel, then `sayso expose`. Needs cloudflared and
// network, and opens a public URL to a throwaway install for as long as it runs.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { Rig, sleep, waitUntil } from "./harness/rig.mjs";

const rig = new Rig("tunnel");
await rig.install();
const tunnel = spawn("cloudflared", ["tunnel", "--no-autoupdate", "--url", `http://127.0.0.1:${rig.port}`], { stdio: ["ignore", "pipe", "pipe"] });
let log = "";
tunnel.stderr.on("data", (d) => (log += d));
const say = (line) => console.log(`ok  ${line}`);
let code = 0;
try {
  const url = await waitUntil(() => /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(log)?.[0], 60000, "a tunnel URL");
  const host = new URL(url).host;
  const post = async (tool, args, token, headers = {}) => fetch(`${url}/v1/call/${tool}`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, body: JSON.stringify(args ?? {}) });
  let lastTry = "";
  const firstAnswer = await waitUntil(async () => {
    await sleep(1000);
    try {
      const res = await post("list_sessions", {}, rig.token);
      lastTry = `status ${res.status}`;
      return res.status >= 500 ? null : res;
    } catch (error) {
      lastTry = `${error.message}: ${error.cause?.code ?? error.cause?.message ?? ""}`;
      return null;
    }
  }, 90000, "the tunnel to answer").catch((error) => {
    throw new Error(`${error.message}. Last try: ${lastTry}. Registered: ${log.includes("Registered tunnel connection")}. URL ${url}`);
  });

  assert.equal(firstAnswer.status, 403);
  say("before `sayso expose`, a good token through the tunnel gets 403");

  rig.cli("expose", host);
  assert.equal((await post("list_sessions", {}, null)).status, 401);
  assert.equal((await post("list_sessions", {}, "wrong")).status, 401);
  say("after it, no token or a wrong token gets 401");

  assert.equal((await post("list_sessions", {}, rig.token, { origin: "https://evil.example" })).status, 403);
  say("a request with an Origin header gets 403, so a web page cannot use it");

  await rig.model([{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "finished" }]);
  const session = rig.headless();
  const request = await waitUntil(async () => (await (await post("list_requests", {}, rig.token)).json()).requests?.[0], 30000, "the request over the tunnel");
  const plain = await (await post("approve", { request_id: request.id }, rig.token)).json();
  assert.equal(plain.status, "needs_human");
  assert.equal(rig.destroyed(), false);
  say("over the tunnel, the agent sees the held call and a plain yes is refused");

  const mcp = await fetch(`${url}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${rig.token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  assert.equal(mcp.status, 200);
  assert.ok((await mcp.json()).result.tools.some((t) => t.name === "approve"));
  say("MCP works through the tunnel");

  const signed = await (await post("approve", { request_id: request.id, signature: rig.signFor(plain) }, rig.token)).json();
  assert.equal(signed.status, "approved");
  await session.done;
  assert.equal(rig.destroyed(), true);
  say("the code from the phone comes back through the tunnel, and the call runs");
} catch (error) {
  code = 1;
  console.error(`FAILED: ${error.message}\n${log.slice(-400)}`);
} finally {
  tunnel.kill();
  await sleep(200);
  await rig.close();
}
process.exit(code);
