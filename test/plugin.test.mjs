// The plugin route: a real `claude plugin install` from a clean clone, with no `sayso setup` beforehand.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { CLAUDE, Rig, waitUntil } from "./harness/rig.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RM = { tool: "Bash", input: { command: "rm -rf victim", description: "run" } };

test("plugin install: the gate is on with no setup step, and it fails closed", async () => {
  const rig = new Rig("plugin");
  try {
    const clone = path.join(rig.root, "clone");
    assert.equal(spawnSync("git", ["clone", "-q", ROOT, clone]).status, 0);
    const env = { ...rig.env(), CLAUDECODE: "" };
    for (const args of [["plugin", "marketplace", "add", clone], ["plugin", "install", "sayso@sayso"]]) {
      const r = spawnSync(CLAUDE, args, { env, encoding: "utf8", timeout: 60000 });
      assert.equal(r.status, 0, r.stdout + r.stderr);
    }
    const settingsFile = path.join(rig.config, "settings.json");
    const settings = JSON.parse(fs.readFileSync(settingsFile, "utf8"));
    assert.equal(settings.hooks, undefined, "the plugin brings its own hooks");
    fs.writeFileSync(settingsFile, JSON.stringify({ ...settings, skipDangerousModePermissionPrompt: true }));
    rig.port = 17000 + Math.floor(Math.random() * 20000);

    await rig.model([RM, { text: "finished" }]);
    const nobody = await rig.headless().done;
    assert.equal(rig.destroyed(), false, "no agent yet, so it is denied rather than run");
    assert.match(rig.scripted.seen.toolResults[0], /no agent is connected/);
    assert.equal(nobody.code, 0);

    const add = spawnSync(process.execPath, [path.join(clone, "bin", "sayso.mjs"), "agent", "add", "plugin-agent", "--json"], { env: rig.env(), encoding: "utf8" });
    assert.equal(add.status, 0, add.stderr);
    rig.token = JSON.parse(add.stdout).token;
    await rig.askDaemon({ op: "reload" });

    await rig.model([RM, { text: "finished" }]);
    const session = rig.headless();
    const request = await waitUntil(async () => (await rig.tool("list_requests")).requests[0], 30000, "the plugin's hook to open a request");
    assert.equal(request.risk, "destructive");
    await rig.tool("deny", { request_id: request.id });
    await session.done;
    assert.equal(rig.destroyed(), false);
    assert.match(rig.scripted.seen.toolResults[0], /denied by plugin-agent/);
  } finally {
    await rig.close();
  }
});
