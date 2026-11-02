#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { verifyAudit } from "../src/audit.mjs";
import { DEFAULT_PAGE, DEFAULT_PORT, statePaths } from "../src/paths.mjs";
import { PRESETS, loadPolicy } from "../src/policy.mjs";
import { generatePairing } from "../src/sign.mjs";
import { qrcodegen } from "../src/vendor/qrcodegen.mjs";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const paths = statePaths();
const [command, ...args] = process.argv.slice(2);
const flag = (name) => args.includes(`--${name}`);
const option = (name) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : undefined;
};
const die = (message) => {
  console.error(`sayso: ${message}`);
  process.exit(1);
};
const insideSession = () => !!process.env.CLAUDECODE || !!process.env.CLAUDE_CODE_ENTRYPOINT;
const refuseInsideSession = (what) => {
  if (insideSession()) die(`run ${what} in your own terminal, not inside a Claude Code session. It would put a secret in the transcript or let a session change its own guard.`);
};

const readJson = (file, fallback) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
};
const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}`;
  fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, file);
};

const portOf = () => Number(process.env.SAYSO_PORT ?? readJson(paths.config, {}).port ?? DEFAULT_PORT);
const claudeSettingsPath = () => path.join(process.env.CLAUDE_CONFIG_DIR || path.join(homedir(), ".claude"), "settings.json");

function askDaemon(message, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(paths.sock);
    let buffer = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("the daemon did not answer"));
    }, timeoutMs);
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => (buffer += chunk));
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(buffer));
      } catch {
        reject(new Error("no answer from the daemon"));
      }
    });
    socket.write(`${JSON.stringify(message)}\n`);
  });
}

async function ensureDaemon(root = appRoot) {
  try {
    await askDaemon({ op: "status" }, 500);
    return true;
  } catch {}
  const child = spawn(process.execPath, [path.join(root, "src", "server.mjs")], { detached: true, stdio: "ignore", env: process.env });
  child.unref();
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 50));
    try {
      await askDaemon({ op: "status" }, 300);
      return true;
    } catch {}
  }
  return false;
}

const reload = () => askDaemon({ op: "reload" }).catch(() => {});

// ---- hooks in settings.json ----
const MARK = "/hooks/run.sh";
const isOurs = (hook) => typeof hook?.command === "string" && hook.command.includes(MARK) && hook.command.includes("sayso");

function hookTable(root, nodePath) {
  const shared = JSON.parse(fs.readFileSync(path.join(root, "hooks", "hooks.json"), "utf8")).hooks;
  const prefix = `SAYSO_NODE=${JSON.stringify(nodePath)} SAYSO_HOME=${JSON.stringify(paths.dir)} `;
  const out = {};
  for (const [event, groups] of Object.entries(shared))
    out[event] = groups.map((group) => ({
      ...group,
      hooks: group.hooks.map((hook) => ({ ...hook, command: prefix + hook.command.replaceAll("${CLAUDE_PLUGIN_ROOT}", root) })),
    }));
  return out;
}

function removeOurHooks(settings) {
  for (const [event, groups] of Object.entries(settings.hooks ?? {})) {
    const kept = groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h) => !isOurs(h)) })).filter((g) => g.hooks.length);
    if (kept.length) settings.hooks[event] = kept;
    else delete settings.hooks[event];
  }
  if (settings.hooks && !Object.keys(settings.hooks).length) delete settings.hooks;
}

function installHooks(root) {
  const file = claudeSettingsPath();
  let settings = {};
  if (fs.existsSync(file)) {
    try {
      settings = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      die(`${file} is not valid JSON, so sayso left it alone`);
    }
    if (!fs.existsSync(`${file}.before-sayso`)) fs.copyFileSync(file, `${file}.before-sayso`);
  }
  removeOurHooks(settings);
  settings.hooks ??= {};
  for (const [event, groups] of Object.entries(hookTable(root, process.execPath))) settings.hooks[event] = [...(settings.hooks[event] ?? []), ...groups];
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(settings, null, 2)}\n`);
  return file;
}

function copyApp() {
  const target = path.join(paths.dir, "app");
  if (path.resolve(appRoot) === path.resolve(target)) return target;
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true, mode: 0o700 });
  for (const entry of ["bin", "src", "hooks", "package.json"]) fs.cpSync(path.join(appRoot, entry), path.join(target, entry), { recursive: true });
  fs.chmodSync(path.join(target, "bin", "sayso.mjs"), 0o755);
  fs.chmodSync(path.join(target, "hooks", "run.sh"), 0o755);
  return target;
}

function linkCli(root) {
  const bin = process.env.SAYSO_BIN_DIR || path.join(homedir(), ".local", "bin");
  try {
    fs.mkdirSync(bin, { recursive: true });
    const link = path.join(bin, "sayso");
    fs.rmSync(link, { force: true });
    fs.symlinkSync(path.join(root, "bin", "sayso.mjs"), link);
    return link;
  } catch {
    return null;
  }
}

// ---- agents ----
function connectionInstructions(name, token) {
  const url = `http://127.0.0.1:${portOf()}/mcp`;
  return `Agent "${name}" added. This token is shown once; sayso keeps only its hash.

  Token   ${token}
  MCP     ${url}   (Streamable HTTP, header  Authorization: Bearer <token>)
  HTTP    POST http://127.0.0.1:${portOf()}/v1/call/<tool>, GET /v1/tools, GET /v1/events/stream

Claude Code as a driver:
  claude mcp add --transport http sayso ${url} --header "Authorization: Bearer ${token}"

Any stdio MCP client (Claude Desktop, and most others):
  { "mcpServers": { "sayso": { "command": "sayso", "args": ["mcp"], "env": { "SAYSO_TOKEN": "${token}" } } } }

Give the token only to that agent. It lets the agent see sessions, deny, and pick offered options.
It cannot approve anything marked human, whoever holds it.`;
}

function addAgent(name) {
  if (!/^[A-Za-z0-9._-]{1,40}$/.test(name ?? "")) die("agent names are letters, digits, dot, dash and underscore");
  const agents = readJson(paths.agents, []);
  if (agents.some((a) => a.name === name && !a.revoked)) die(`agent ${name} already exists. Revoke it first: sayso agent revoke ${name}`);
  const token = `sayso_agent_${crypto.randomBytes(32).toString("base64url")}`;
  agents.push({ name, token_sha256: crypto.createHash("sha256").update(token).digest("hex"), created_at: new Date().toISOString() });
  writeJson(paths.agents, agents);
  return token;
}

// ---- pairing ----
function renderQr(text) {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.LOW);
  const quiet = 2;
  const dark = (x, y) => x >= 0 && y >= 0 && x < qr.size && y < qr.size && qr.getModule(x, y);
  const rows = [];
  for (let y = -quiet; y < qr.size + quiet; y += 2) {
    let row = "";
    for (let x = -quiet; x < qr.size + quiet; x++) {
      const top = dark(x, y);
      const bottom = dark(x, y + 1);
      row += top && bottom ? " " : top ? "▄" : bottom ? "▀" : "█";
    }
    rows.push(row);
  }
  return rows.join("\n");
}

async function pair() {
  refuseInsideSession("sayso pair");
  const name = option("name") ?? "my phone";
  const pageUrl = readJson(paths.config, {}).page_url ?? DEFAULT_PAGE;
  const pairing = generatePairing();
  const url = `${pageUrl}#pair=${pairing.pkcs8}&id=${pairing.id}&name=${encodeURIComponent(name)}`;
  const showSecret = flag("print-url");
  const keys = readJson(paths.keys, []);
  keys.push({ id: pairing.id, public_key: pairing.public_key, name, added_at: new Date().toISOString() });
  if (flag("json")) {
    writeJson(paths.keys, keys);
    await reload();
    console.log(JSON.stringify({ id: pairing.id, url }));
    return;
  }
  console.log(`\nScan this with the device you want to approve from. It opens the sayso page, which keeps the key on that device.\n`);
  console.log(renderQr(url));
  console.log(`\nThe private key exists only in this code. This machine keeps the public half.${showSecret ? `\n\n${url}\n` : "\nNo camera? Run again with --print-url and open the link on the device."}`);
  if (process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    await new Promise((resolve) => rl.question("\nPress Enter once the page says the device is paired (type q to cancel): ", (answer) => {
      rl.close();
      if (answer.trim().toLowerCase() === "q") {
        console.log("Cancelled. Nothing was saved.");
        process.exit(0);
      }
      resolve();
    }));
    process.stdout.write("\x1b[2J\x1b[3J\x1b[H");
  }
  writeJson(paths.keys, keys);
  await reload();
  console.log(`Paired ${name} (key ${pairing.id}). Requests marked human can now be approved from it.`);
}

// ---- stdio bridge for MCP clients that only speak stdio ----
async function mcpBridge() {
  const token = process.env.SAYSO_TOKEN;
  if (!token) die("set SAYSO_TOKEN to the token from `sayso agent add`");
  await ensureDaemon();
  const endpoint = `http://127.0.0.1:${portOf()}/mcp`;
  let chain = Promise.resolve();
  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    chain = chain.then(async () => {
      let id = null;
      try {
        id = JSON.parse(line).id ?? null;
        const res = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: line });
        if (res.status === 202) return;
        process.stdout.write(`${await res.text()}\n`);
      } catch (error) {
        process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: `sayso daemon unreachable: ${error.message}` } })}\n`);
      }
    });
  });
  rl.on("close", () => chain.finally(() => process.exit(0)));
}

// ---- diagnostics ----
async function doctor() {
  const checks = [];
  const check = (ok, what, fix) => checks.push({ ok, what, fix });
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  check(nodeMajor >= 20, `node ${process.versions.node}`, "sayso needs Node 20 or newer");
  const claude = spawnSync("claude", ["--version"], { encoding: "utf8" });
  check(claude.status === 0, `claude ${claude.stdout?.trim() ?? "not found"}`, "install Claude Code");
  const settings = readJson(claudeSettingsPath(), {});
  const inSettings = Object.values(settings.hooks ?? {}).flat().some((g) => (g.hooks ?? []).some(isOurs));
  const asPlugin = Object.keys(settings.enabledPlugins ?? {}).some((p) => p.startsWith("sayso@"));
  check(inSettings || asPlugin, inSettings ? `hooks in ${claudeSettingsPath()}` : asPlugin ? "installed as a plugin" : "hooks not installed", "run: sayso setup");
  let status = null;
  try {
    status = await askDaemon({ op: "status" }, 1000);
  } catch {}
  check(!!status, status ? `daemon pid ${status.pid}, port ${status.port}` : "daemon not running", "it starts with the next session, or run: sayso daemon start");
  try {
    const mode = fs.statSync(paths.dir).mode & 0o777;
    check(mode === 0o700, `state folder ${paths.dir} is private`, `chmod 700 ${paths.dir}`);
  } catch {
    check(false, "state folder missing", "run: sayso setup");
  }
  const policy = loadPolicy(paths.policy);
  check(true, `policy: ${policy.preset}`);
  for (const note of policy.notes) check(false, `policy note: ${note}`, "edit policy.json");
  const keys = readJson(paths.keys, []);
  check(keys.length > 0, keys.length ? `${keys.length} paired device(s)` : "no paired device, so human-only requests can be answered only at a terminal dialog", "run: sayso pair");
  const agents = readJson(paths.agents, []).filter((a) => !a.revoked);
  check(agents.length > 0, agents.length ? `agents: ${agents.map((a) => a.name).join(", ")}` : "no agent connected", "run: sayso agent add <name>");
  const audit = verifyAudit(paths.audit);
  check(audit.ok, audit.ok ? `audit log intact, ${audit.count} entries` : `audit log broken at line ${audit.broken_at}: ${audit.why}`, "something edited the audit log");
  if (flag("json")) return console.log(JSON.stringify(checks, null, 2));
  for (const c of checks) console.log(`${c.ok ? "ok  " : "todo"}  ${c.what}${c.ok || !c.fix ? "" : `\n      ${c.fix}`}`);
  if (checks.some((c) => !c.ok)) process.exitCode = 1;
}

async function setup() {
  refuseSetupIfUnsupported();
  fs.mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  const root = copyApp();
  const settingsFile = flag("plugin") ? null : installHooks(root);
  const link = linkCli(root);
  const up = await ensureDaemon(root);
  const out = { settings: settingsFile, cli: link, daemon: up, port: portOf() };
  const agentName = option("agent");
  let token = null;
  if (agentName) {
    token = addAgent(agentName);
    await reload();
  }
  if (flag("json")) return console.log(JSON.stringify({ ...out, token }));
  console.log(`sayso is installed.
  hooks   ${settingsFile ?? "from the plugin"}
  cli     ${link ?? "could not link; run node " + path.join(root, "bin", "sayso.mjs")}
  daemon  ${up ? `running on 127.0.0.1:${portOf()}` : "did not start, see " + paths.log}
  policy  ${loadPolicy(paths.policy).preset}
`);
  if (token) console.log(`${connectionInstructions(agentName, token)}\n`);
  console.log(`Sessions you start from now on are covered. Restart any session already running.`);
  if (!token) console.log(`\nNext: connect your agent with\n  sayso agent add <name>`);
  if (!flag("no-pair") && process.stdin.isTTY && !insideSession()) await pair();
  else if (!readJson(paths.keys, []).length) console.log(`\nThen, in your own terminal, pair the device you approve from:\n  sayso pair`);
}

function refuseSetupIfUnsupported() {
  if (Number(process.versions.node.split(".")[0]) < 20) die("sayso needs Node 20 or newer");
  if (process.platform === "win32") die("sayso does not support Windows yet");
}

async function uninstall() {
  const file = claudeSettingsPath();
  if (fs.existsSync(file)) {
    const settings = JSON.parse(fs.readFileSync(file, "utf8"));
    removeOurHooks(settings);
    fs.writeFileSync(file, `${JSON.stringify(settings, null, 2)}\n`);
  }
  await askDaemon({ op: "shutdown" }).catch(() => {});
  const link = path.join(process.env.SAYSO_BIN_DIR || path.join(homedir(), ".local", "bin"), "sayso");
  if (fs.existsSync(link) && fs.lstatSync(link).isSymbolicLink()) fs.rmSync(link);
  if (flag("purge")) fs.rmSync(paths.dir, { recursive: true, force: true });
  console.log(`Removed sayso's hooks from ${file}.${flag("purge") ? " State deleted." : ` State and audit log kept in ${paths.dir}.`}`);
}

function printRequests(requests) {
  if (!requests.length) return console.log("no pending requests");
  for (const r of requests) console.log(`${r.id}  ${r.session}  ${r.risk}  approver:${r.approver}  until ${r.expires_at}\n  ${r.untrusted.action.split("\n").join("\n  ")}`);
}

const USAGE = `sayso: your agent can see your Claude Code sessions and answer them. Nothing destructive runs without your say-so.

  sayso setup [--agent NAME] [--no-pair]    install the hooks, start the daemon
  sayso agent add NAME | list | revoke NAME connect a personal agent
  sayso pair [--name NAME]                  pair the device you approve from
  sayso status                              sessions and pending requests
  sayso deny REQUEST_ID                     say no from this terminal
  sayso policy [strict|trusted-agent]       show or change who may approve what
  sayso notify add webhook URL [--secret S] push events to your agent
  sayso notify add command -- ARGV...       or run a command with the event on stdin
  sayso notify list | clear
  sayso expose HOST                         accept requests for HOST, after you set up a tunnel
  sayso audit [--verify] [-n N]             the decision log
  sayso doctor                              check the install
  sayso mcp                                 stdio MCP bridge (needs SAYSO_TOKEN)
  sayso daemon start | stop
  sayso uninstall [--purge]`;

switch (command) {
  case "setup":
    await setup();
    break;
  case "uninstall":
    refuseInsideSession("sayso uninstall");
    await uninstall();
    break;
  case "doctor":
    await doctor();
    break;
  case "mcp":
    await mcpBridge();
    break;
  case "pair":
    await pair();
    break;
  case "status": {
    await ensureDaemon();
    const status = await askDaemon({ op: "status" });
    if (flag("json")) {
      console.log(JSON.stringify(status, null, 2));
      break;
    }
    console.log(`daemon pid ${status.pid}, port ${status.port}, policy ${status.policy.preset}, agents: ${status.agents.join(", ") || "none"}, paired devices: ${status.keys.length}\n`);
    if (!status.sessions.length) console.log("no sessions seen yet");
    for (const s of status.sessions) console.log(`${s.state.padEnd(12)} ${s.name}  ${s.permission_mode ?? ""}  ${s.session_id}`);
    console.log();
    printRequests(status.requests);
    break;
  }
  case "deny": {
    if (!args[0]) die("usage: sayso deny REQUEST_ID");
    console.log(JSON.stringify(await askDaemon({ op: "deny", request_id: args[0], reason: option("reason") })));
    break;
  }
  case "agent": {
    const [sub, name] = args;
    if (sub === "add") {
      refuseInsideSession("sayso agent add");
      const token = addAgent(name);
      await reload();
      console.log(flag("json") ? JSON.stringify({ name, token, url: `http://127.0.0.1:${portOf()}/mcp` }) : connectionInstructions(name, token));
    } else if (sub === "revoke") {
      const agents = readJson(paths.agents, []);
      const found = agents.find((a) => a.name === name && !a.revoked);
      if (!found) die(`no active agent named ${name}`);
      found.revoked = new Date().toISOString();
      writeJson(paths.agents, agents);
      await reload();
      console.log(`Revoked ${name}.`);
    } else {
      for (const a of readJson(paths.agents, [])) console.log(`${a.name}  added ${a.created_at}${a.revoked ? `  revoked ${a.revoked}` : ""}`);
    }
    break;
  }
  case "policy": {
    if (!args[0]) {
      console.log(JSON.stringify(loadPolicy(paths.policy), null, 2));
      break;
    }
    refuseInsideSession("sayso policy");
    if (!PRESETS[args[0]]) die(`unknown policy ${args[0]}. Choose: ${Object.keys(PRESETS).join(", ")}`);
    writeJson(paths.policy, { ...readJson(paths.policy, {}), preset: args[0] });
    await reload();
    console.log(`Policy is now ${args[0]}.`);
    break;
  }
  case "notify": {
    const config = readJson(paths.config, {});
    config.notify ??= [];
    if (args[0] === "add" && args[1] === "webhook") {
      config.notify.push({ type: "webhook", url: args[2], ...(option("secret") ? { secret: option("secret") } : {}) });
    } else if (args[0] === "add" && args[1] === "command") {
      const dash = args.indexOf("--");
      if (dash < 0) die("usage: sayso notify add command -- ARGV...");
      config.notify.push({ type: "command", argv: args.slice(dash + 1) });
    } else if (args[0] === "clear") {
      config.notify = [];
    } else {
      for (const sink of config.notify) console.log(sink.type === "webhook" ? `webhook ${sink.url}` : `command ${sink.argv.join(" ")}`);
      break;
    }
    writeJson(paths.config, config);
    await reload();
    console.log("Saved.");
    break;
  }
  case "expose": {
    refuseInsideSession("sayso expose");
    if (!args[0]) die("usage: sayso expose HOST");
    const config = readJson(paths.config, {});
    config.allowed_hosts = [...new Set([...(config.allowed_hosts ?? []), args[0].toLowerCase()])];
    writeJson(paths.config, config);
    await reload();
    console.log(`Requests for ${args[0]} are now accepted. Every one still needs an agent token.`);
    break;
  }
  case "audit": {
    if (flag("verify")) {
      const result = verifyAudit(paths.audit);
      console.log(result.ok ? `intact, ${result.count} entries` : `BROKEN at line ${result.broken_at}: ${result.why}`);
      if (!result.ok) process.exitCode = 1;
      break;
    }
    const n = Number(option("n") ?? args[args.indexOf("-n") + 1] ?? 20);
    const lines = fs.existsSync(paths.audit) ? fs.readFileSync(paths.audit, "utf8").trim().split("\n").slice(-n) : [];
    for (const line of lines) console.log(line);
    break;
  }
  case "daemon": {
    if (args[0] === "stop") await askDaemon({ op: "shutdown" }).catch(() => {});
    else console.log((await ensureDaemon()) ? "running" : `did not start, see ${paths.log}`);
    break;
  }
  default:
    console.log(USAGE);
    if (command && command !== "help" && command !== "--help") process.exitCode = 1;
}
