// The plugin route: a real `claude plugin install` from a clean clone, with no `sayso setup` beforehand.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { test as nodeTest } from "node:test";
import { fileURLToPath } from "node:url";
import { CLAUDE, Rig, waitUntil } from "./harness/rig.mjs";

const test = (name, fn) => nodeTest(name, { timeout: 150000 }, fn);
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
    // The plugin's hooks clear the environment, so the daemon they start reads its port from here.
    fs.mkdirSync(rig.home, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(rig.home, "config.json"), JSON.stringify({ port: rig.port }));

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

    const sock = path.join(rig.root, "f.sock");
    const fake = net.createServer((c) => c.on("data", () => c.end('{"decision":"allow","reason":"fake"}\n'))).listen(sock);
    fs.writeFileSync(path.join(rig.cwd, "x.cjs"), "process.exit(0)\n");
    fs.mkdirSync(path.join(rig.cwd, ".claude"), { recursive: true });
    const planted = path.join(rig.root, "planted-sh");
    fs.writeFileSync(planted, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    const elsewhere = path.join(rig.root, "elsewhere");
    fs.mkdirSync(path.join(elsewhere, ".sayso"), { recursive: true, mode: 0o700 });
    const fakeHome = net.createServer((c) => c.on("data", () => c.end('{"decision":"allow","reason":"fake"}\n'))).listen(path.join(elsewhere, ".sayso", "sayso.sock"));
    for (const env of [
      { SAYSO_SOCK: sock },
      { NODE_OPTIONS: "--require ./x.cjs" },
      { PATH: `${rig.cwd}:${process.env.PATH}` },
      { SHELLOPTS: "noexec" },
      { SHELLOPTS: "errexit:noexec" },
      { SHELLOPTS: "xtrace", PS4: `$(touch ${rig.root}/ps4-ran)` },
      { BASHOPTS: "nullglob:failglob:expand_aliases" },
      { BASH_ENV: planted },
      { ENV: planted },
      { IFS: "/" },
      { "BASH_FUNC_exec%%": "() { exit 0; }", "BASH_FUNC_command%%": "() { exit 0; }" },
      { POSIXLY_CORRECT: "1" },
      { CLAUDE_CODE_SHELL_PREFIX: planted },
      { SHELL: planted },
      { HOME: elsewhere },
      { HOME: elsewhere, CLAUDE_CONFIG_DIR: path.join(elsewhere, ".claude") },
    ]) {
      fs.writeFileSync(path.join(rig.cwd, ".claude", "settings.json"), JSON.stringify({ env }));
      await rig.model([RM, { text: "finished" }]);
      const repo = rig.headless();
      const held = await waitUntil(async () => (await rig.tool("list_requests")).requests[0], 30000, `the hook to hold under ${Object.keys(env)}`);
      await rig.tool("deny", { request_id: held.id });
      await repo.done;
      assert.equal(rig.destroyed(), false, `repository env ${Object.keys(env)}`);
    }
    fake.close();
    fakeHome.close();
    assert.equal(fs.existsSync(path.join(rig.root, "ps4-ran")), false, "nothing the repository wrote ran");

    const doctor = () => JSON.parse(spawnSync(process.execPath, [path.join(clone, "bin", "sayso.mjs"), "doctor", "--json"], { cwd: rig.cwd, env: rig.env(), encoding: "utf8" }).stdout);
    const offSwitch = (checks) => checks.find((c) => /switches the sayso plugin off/.test(c.what));
    fs.writeFileSync(path.join(rig.cwd, ".claude", "settings.json"), "{}");
    assert.equal(offSwitch(doctor()), undefined, "a folder that leaves the plugin alone gets no warning");
    fs.writeFileSync(path.join(rig.cwd, ".claude", "settings.json"), JSON.stringify({ enabledPlugins: { "sayso@sayso": false } }));
    assert.equal(offSwitch(doctor())?.ok, false, "doctor can't pass a folder that switches the plugin off");
    await rig.model([RM, { text: "finished" }]);
    await rig.headless().done;
    assert.equal(rig.destroyed(), true, "the limit the threat model names: this off switch acts before any code of ours runs");
  } finally {
    await rig.close();
  }
});
