#!/usr/bin/env node
// `sudo sayso harden`, attacked from the account a session runs as. This installs for real and changes the machine, so it
// refuses to run anywhere but a throwaway Linux box. Run as a normal user with passwordless sudo and systemd:
//   SAYSO_THROWAWAY_BOX=yes node test/harden.mjs
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generatePairing, signAsDevice } from "../src/sign.mjs";
import { startScriptedModel } from "./harness/scripted-model.mjs";
import { apiKeyEnv } from "./harness/tui.mjs";

if (process.platform !== "linux" || process.env.SAYSO_THROWAWAY_BOX !== "yes" || process.getuid() === 0) {
  console.error("This changes the machine. Run it as a normal user on a throwaway Linux box with SAYSO_THROWAWAY_BOX=yes.");
  process.exit(2);
}

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLI = path.join(ROOT, "bin", "sayso.mjs");
const CLAUDE = process.env.CLAUDE_BIN || "claude";
const STATE = "/var/lib/sayso";
const SOCK = "/run/sayso/sayso.sock";
const MANAGED = "/etc/claude-code/managed-settings.json";
const PORT = 7428;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "ok  " : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const refused = (name, fn) => {
  try {
    fn();
    check(name, false, "it worked");
  } catch (error) {
    check(name, ["EACCES", "EPERM", "EROFS"].includes(error.code), error.code);
  }
};

const home = os.homedir();
const box = { root: fs.mkdtempSync(path.join(os.tmpdir(), "harden-")), config: path.join(home, ".claude") };
box.cwd = path.join(box.root, "w");
fs.mkdirSync(path.join(box.cwd, "victim"), { recursive: true });
const victim = path.join(box.cwd, "victim", "file.txt");
const refill = () => {
  fs.mkdirSync(path.dirname(victim), { recursive: true });
  fs.writeFileSync(victim, "keep me");
};
refill();

const setup = spawnSync(process.execPath, [CLI, "setup", "--no-pair", "--json", "--agent", "boxagent"], { encoding: "utf8" });
assert.equal(setup.status, 0, setup.stderr);
const { token } = JSON.parse(setup.stdout);
const device = generatePairing();
fs.writeFileSync(path.join(home, ".sayso", "keys.json"), JSON.stringify([{ id: device.id, public_key: device.public_key, name: "test phone" }]));

const harden = spawnSync("sudo", ["-E", process.execPath, CLI, "harden"], { encoding: "utf8" });
check("sudo sayso harden finishes", harden.status === 0, (harden.stderr || "").trim().slice(0, 300));
if (harden.status !== 0) process.exit(1);
await sleep(1500);

const settingsFile = path.join(home, ".claude", "settings.json");
const settings = JSON.parse(fs.readFileSync(settingsFile, "utf8"));
check("user settings no longer carry the hooks", !JSON.stringify(settings).includes("run.sh"));
check("managed settings carry them", fs.readFileSync(MANAGED, "utf8").includes("run.sh"));
fs.writeFileSync(settingsFile, JSON.stringify({ ...settings, skipDangerousModePermissionPrompt: true }));

const call = async (tool, args = {}) => {
  const res = await fetch(`http://127.0.0.1:${PORT}/v1/call/${tool}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(args) });
  return res.json();
};
const nextRequest = async (ms = 30000, not = new Set()) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const { requests } = await call("list_requests");
    const found = requests?.find((r) => !not.has(r.id));
    if (found) return found;
    await sleep(100);
  }
  return null;
};

const model = await startScriptedModel([{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "finished" }]);
const session = (extra = []) => {
  const child = spawn(CLAUDE, ["-p", "go", "--model", "claude-scripted", "--output-format", "json", "--dangerously-skip-permissions", ...extra], { cwd: box.cwd, env: apiKeyEnv(box, model.url, { PATH: process.env.PATH, HOME: home }), stdio: ["ignore", "pipe", "pipe"] });
  child.done = new Promise((r) => child.on("exit", r));
  return child;
};

const seen = new Set();
const heldThenDenied = async (name, extra = []) => {
  refill();
  const child = session(extra);
  const request = await nextRequest(30000, seen);
  if (!request) {
    await child.done;
    check(`${name}: still held`, false, `no request, and the folder ${fs.existsSync(victim) ? "survived" : "IS GONE"}`);
    return;
  }
  seen.add(request.id);
  await call("deny", { request_id: request.id });
  await child.done;
  check(`${name}: still held, and a no stops it`, fs.existsSync(victim));
};

await heldThenDenied("a session with permissions bypassed");

const end = spawn(CLAUDE, ["-p", "go", "--model", "claude-scripted", "--dangerously-skip-permissions"], { cwd: box.cwd, env: apiKeyEnv(box, model.url, { PATH: process.env.PATH, HOME: home }), stdio: "ignore" });
const request = await nextRequest(30000, seen);
seen.add(request.id);
const plain = await call("approve", { request_id: request.id });
check("a plain yes from the agent is refused", plain.status === "needs_human" && fs.existsSync(victim), plain.status);
const signed = await call("approve", { request_id: request.id, signature: signAsDevice(new URL(plain.approval_url).hash.slice(3), device.pkcs8, device.id) });
check("the key paired before hardening still signs", signed.status === "approved", signed.status);
await new Promise((r) => end.on("exit", r));
check("and the approved call runs", !fs.existsSync(victim));

const pid = Number(spawnSync("systemctl", ["show", "-p", "MainPID", "--value", "sayso"], { encoding: "utf8" }).stdout.trim());
check("the daemon runs as its own user", spawnSync("ps", ["-o", "user=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim() === "sayso", `pid ${pid}`);

refused("a session cannot swap the public keys", () => fs.writeFileSync(path.join(STATE, "keys.json"), "[]"));
refused("a session cannot replace the keys file", () => fs.renameSync(path.join(STATE, "keys.json"), path.join(STATE, "keys.old")));
refused("a session cannot weaken the policy", () => fs.writeFileSync(path.join(STATE, "policy.json"), '{"preset":"trusted-agent"}'));
refused("a session cannot rewrite the audit log", () => fs.appendFileSync(path.join(STATE, "audit.jsonl"), "x\n"));
refused("a session cannot read agent token hashes", () => fs.readFileSync(path.join(STATE, "agents.json")));
refused("a session cannot kill the daemon", () => process.kill(pid, "SIGKILL"));
refused("a session cannot edit the managed hooks", () => fs.writeFileSync(MANAGED, "{}"));
refused("a session cannot remove the managed hooks", () => fs.rmSync(MANAGED));
refused("a session cannot edit the gate", () => fs.appendFileSync("/usr/local/lib/sayso/src/hook.mjs", "\n"));

const socketSays = (line) =>
  new Promise((resolve) => {
    let out = "";
    const socket = net.connect(SOCK);
    socket.setEncoding("utf8");
    socket.on("data", (d) => (out += d));
    socket.on("error", (e) => resolve(`error ${e.code}`));
    socket.on("close", () => resolve(out));
    socket.on("connect", () => socket.write(`${line}\n`));
    setTimeout(() => socket.destroy(), 1500);
  });
const held = session();
refill();
const pending = await nextRequest(30000, seen);
seen.add(pending.id);
await socketSays(JSON.stringify({ op: "approve", request_id: pending.id }));
await socketSays(JSON.stringify({ op: "answer", request_id: pending.id, decision: "allow" }));
await sleep(500);
check("the socket a session can reach has no verb that approves", fs.existsSync(victim) && (await call("list_requests")).requests.some((r) => r.id === pending.id));
await call("deny", { request_id: pending.id });
await held.done;

fs.writeFileSync(settingsFile, JSON.stringify({ skipDangerousModePermissionPrompt: true, disableAllHooks: true }));
await heldThenDenied("disableAllHooks in user settings");
fs.writeFileSync(settingsFile, JSON.stringify({ skipDangerousModePermissionPrompt: true, hooks: {} }));
await heldThenDenied("an empty hook table in user settings");
await heldThenDenied("--bare", ["--bare"]);
await heldThenDenied("--safe-mode", ["--safe-mode"]);
await heldThenDenied("--setting-sources project", ["--setting-sources", "project"]);

refill();
const dying = session();
const lastHold = await nextRequest(30000, seen);
seen.add(lastHold.id);
spawnSync("sudo", ["systemctl", "kill", "-s", "KILL", "sayso"]);
await dying.done;
check("when the daemon dies during a hold, the call is denied", fs.existsSync(victim));
await sleep(6000);
check("and systemd brings it back", spawnSync("systemctl", ["is-active", "sayso"], { encoding: "utf8" }).stdout.trim() === "active");

model.close();
console.log(failures ? `\n${failures} failed` : "\nall passed");
process.exit(failures ? 1 : 0);
