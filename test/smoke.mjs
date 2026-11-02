#!/usr/bin/env node
// One real install in a temp folder, one real Claude Code session, one real `rm -rf` that waits for a person.
// Needs no account and costs nothing: the session talks to a scripted model. Your own settings are not touched.
import assert from "node:assert/strict";
import fs from "node:fs";
import { Rig, waitUntil } from "./harness/rig.mjs";

const say = (line) => console.log(line);
const rig = new Rig("smoke");
let failed = false;
try {
  await rig.install();
  say("ok  installed into a temp folder, with a daemon and hooks");

  await rig.model([{ tool: "Bash", input: { command: "rm -rf victim", description: "delete the folder" } }, { text: "finished" }]);
  const session = rig.headless();
  const request = await rig.nextRequest(60000);
  assert.equal(rig.destroyed(), false);
  say(`ok  the session asked to run \`${request.untrusted.action}\`, and it is on hold (risk: ${request.risk})`);

  const plain = await rig.tool("approve", { request_id: request.id });
  assert.equal(plain.status, "needs_human");
  assert.equal(rig.destroyed(), false);
  say("ok  your agent said yes, and that was refused: only you can approve this");

  const forged = await rig.tool("approve", { request_id: request.id, signature: `sayso1.${rig.device.id}.${"A".repeat(86)}` });
  assert.equal(forged.status, "refused");
  assert.equal(rig.destroyed(), false);
  say("ok  your agent made up a code, and that was refused too");

  const approved = await rig.tool("approve", { request_id: request.id, signature: rig.signFor(plain) });
  assert.equal(approved.status, "approved");
  await waitUntil(() => rig.destroyed(), 30000, "the approved call to run");
  await session.done;
  say("ok  a signature from the paired device came back, and the command ran");

  const audit = fs.readFileSync(`${rig.home}/audit.jsonl`, "utf8");
  assert.match(audit, /"decision":"approved"/);
  assert.match(audit, /"name":"test phone"/);
  say("ok  the audit log says who answered");
  say("\nThe gate works on this machine.");
} catch (error) {
  failed = true;
  console.error(`\nFAILED: ${error.message}`);
} finally {
  await rig.close();
}
process.exit(failed ? 1 : 0);
