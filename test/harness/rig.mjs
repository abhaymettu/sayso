// A complete, throwaway install: real `sayso setup` into a temp Claude config, real daemon, real Claude Code binary.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generatePairing, signAsDevice } from "../../src/sign.mjs";
import { startScriptedModel } from "./scripted-model.mjs";
import { Tui, apiKeyEnv, sleep } from "./tui.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CLI = path.join(ROOT, "bin", "sayso.mjs");
export const CLAUDE = process.env.CLAUDE_BIN || "claude";
export { sleep };

const openRigs = new Set();
process.on("exit", () => {
  for (const rig of openRigs) {
    try {
      process.kill(rig.daemonPid());
    } catch {}
    rig.terminal?.kill();
  }
});

function freePort() {
  return new Promise((resolve) => {
    const probe = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

export async function waitUntil(fn, ms = 15000, label = "condition") {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const value = await fn();
    if (value) return value;
    await sleep(25);
  }
  throw new Error(`timed out waiting for ${label}`);
}

export class Rig {
  constructor(name = "rig") {
    // Short path: a Unix socket path has a 104 byte limit on macOS.
    this.root = fs.realpathSync(fs.mkdtempSync(path.join("/tmp", "sy-")));
    this.name = name;
    // A fake HOME with the real layout. The gate is what stands between these tests and `rm -rf ~`, so if it ever
    // fails, the damage lands in this folder.
    this.fakeHome = path.join(this.root, "h");
    this.home = path.join(this.fakeHome, ".sayso");
    this.config = path.join(this.fakeHome, ".claude");
    this.cwd = path.join(this.root, "w");
    this.bin = path.join(this.root, "b");
    this.port = 0;
    fs.mkdirSync(this.config, { recursive: true });
    fs.mkdirSync(path.join(this.cwd, "victim"), { recursive: true });
    fs.writeFileSync(path.join(this.cwd, "victim", "file.txt"), "keep me");
    this.victim = path.join(this.cwd, "victim", "file.txt");
    this.children = [];
  }

  env(extra = {}) {
    return {
      PATH: process.env.PATH,
      HOME: this.fakeHome,
      TMPDIR: process.env.TMPDIR,
      SAYSO_HOME: this.home,
      SAYSO_PORT: String(this.port),
      SAYSO_BIN_DIR: this.bin,
      CLAUDE_CONFIG_DIR: this.config,
      ...extra,
    };
  }

  cli(...args) {
    const r = spawnSync(process.execPath, [CLI, ...args], { env: this.env(), encoding: "utf8", timeout: 20000 });
    if (r.status !== 0) throw new Error(`sayso ${args.join(" ")} failed: ${r.stderr}${r.stdout}`);
    return r.stdout;
  }

  async install({ policy, agent = "test-agent", pair = true } = {}) {
    this.port = await freePort();
    openRigs.add(this);
    if (policy) {
      fs.mkdirSync(this.home, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(this.home, "policy.json"), JSON.stringify(policy));
    }
    const out = JSON.parse(this.cli("setup", "--no-pair", "--json", ...(agent ? ["--agent", agent] : [])));
    this.token = out.token;
    if (pair) {
      const device = generatePairing();
      this.device = device;
      const keysFile = path.join(this.home, "keys.json");
      fs.writeFileSync(keysFile, JSON.stringify([{ id: device.id, public_key: device.public_key, name: "test phone" }]));
      await this.askDaemon({ op: "reload" });
    }
    const settingsFile = path.join(this.config, "settings.json");
    const settings = JSON.parse(fs.readFileSync(settingsFile, "utf8"));
    settings.skipDangerousModePermissionPrompt = true;
    fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
    return this;
  }

  askDaemon(message) {
    return new Promise((resolve, reject) => {
      const socket = net.connect(path.join(this.home, "sayso.sock"));
      let buffer = "";
      socket.setEncoding("utf8");
      socket.on("data", (d) => (buffer += d));
      socket.on("error", reject);
      socket.on("close", () => {
        try {
          resolve(JSON.parse(buffer));
        } catch {
          resolve(null);
        }
      });
      socket.write(`${JSON.stringify(message)}\n`);
    });
  }

  daemonPid() {
    return Number(fs.readFileSync(path.join(this.home, "daemon.pid"), "utf8"));
  }

  async mcp(method, params, token = this.token) {
    const res = await fetch(`http://127.0.0.1:${this.port}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return { http: res.status, body: await res.json() };
  }

  async tool(name, args = {}, token = this.token) {
    const { http, body } = await this.mcp("tools/call", { name, arguments: args }, token);
    if (http !== 200 || body.error) throw new Error(`${name}: http ${http} ${JSON.stringify(body)}`);
    return body.result.structuredContent;
  }

  async nextRequest(ms = 20000, predicate = () => true) {
    return waitUntil(async () => (await this.tool("list_requests")).requests.find(predicate), ms, "a pending request");
  }

  signFor(request) {
    const doc = new URL(request.approval_url).hash.slice(3);
    return signAsDevice(doc, this.device.pkcs8, this.device.id);
  }

  audit() {
    const file = path.join(this.home, "audit.jsonl");
    return fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  }

  async model(plan, hooks) {
    this.scripted = await startScriptedModel(plan, hooks);
    return this.scripted;
  }

  headless({ mode = "bypassPermissions", prompt = "go", extraEnv = {}, stdin = "ignore" } = {}) {
    const args = ["-p", prompt, "--model", "claude-scripted", "--output-format", "json", "--permission-mode", mode];
    if (mode === "bypassPermissions") args.push("--dangerously-skip-permissions");
    const child = spawn(CLAUDE, args, { cwd: this.cwd, env: apiKeyEnv(this, this.scripted.url, this.env(extraEnv)), stdio: [stdin, "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    this.children.push(child);
    child.done = new Promise((resolve) => child.on("exit", (code) => resolve({ code, stdout, stderr })));
    return child;
  }

  tui(args = ["--dangerously-skip-permissions"], extraEnv = {}) {
    const box = { root: this.root, config: this.config, cwd: this.cwd };
    this.terminal = new Tui(box, apiKeyEnv(this, this.scripted.url, this.env(extraEnv)), ["--model", "claude-scripted", ...args]);
    return this.terminal;
  }

  destroyed() {
    return !fs.existsSync(this.victim);
  }

  async close() {
    for (const c of this.children) if (c.exitCode === null) c.kill("SIGKILL");
    this.terminal?.kill();
    this.scripted?.close();
    await this.askDaemon({ op: "shutdown" }).catch(() => {});
    openRigs.delete(this);
    await sleep(40);
    fs.rmSync(this.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
