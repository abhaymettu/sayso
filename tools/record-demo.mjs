#!/usr/bin/env node
// Records the real flow into assets/demo.gif and assets/demo.mp4: a real Claude Code session with permissions bypassed, a
// real model as the agent, and the real approval page. Only the session's model is scripted, so the take is repeatable.
// Run: CLAUDE_BIN=claude npx -y -p playwright@1.64.1 node tools/record-demo.mjs
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Rig, CLAUDE, sleep, waitUntil } from "../test/harness/rig.mjs";
import { serve } from "../test/page/serve.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "assets");
const require = createRequire(path.join(process.env.NODE_PATH ?? process.cwd(), "x.js"));
const { chromium } = require("playwright");

const LEFT = 72;
const RIGHT = 40;
const ROWS = 30;
const MODEL = "claude-haiku-5-5";
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sayso-demo-"));
const castFile = path.join(tmp, "demo.cast");

const rig = new Rig("demo");
rig.cwd = path.join(rig.root, "my-app");
fs.mkdirSync(path.join(rig.cwd, "data"), { recursive: true });
rig.victim = path.join(rig.cwd, "data", "customers.db");
fs.writeFileSync(rig.victim, "keep me");

const { server, url: pageUrl } = await serve();
fs.mkdirSync(rig.home, { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(rig.home, "config.json"), JSON.stringify({ page_url: pageUrl }));
await rig.install();

function runAgent(prompt) {
  const mcp = path.join(rig.root, "mcp.json");
  fs.writeFileSync(mcp, JSON.stringify({ mcpServers: { sayso: { type: "http", url: `http://127.0.0.1:${rig.port}/mcp`, headers: { Authorization: `Bearer ${rig.token}` } } } }));
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith("SAYSO_")) delete env[k];
  delete env.CLAUDECODE;
  return new Promise((resolve) => {
    const child = require("node:child_process").spawn(CLAUDE, ["-p", prompt, "--model", MODEL, "--output-format", "json", "--setting-sources", "project", "--strict-mcp-config", "--mcp-config", mcp, "--tools", "", "--allowedTools", "mcp__sayso__*", "--permission-mode", "dontAsk"], { cwd: rig.root, env, stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("exit", () => {
      try {
        resolve(JSON.parse(out).result ?? "");
      } catch {
        resolve("");
      }
    });
  });
}

// The right column is the conversation you would have with your agent, wherever it lives.
const panel = [];
const wrap = (text, width) => {
  const out = [];
  for (const para of text.split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/)) {
      if ((line + " " + word).trim().length > width) {
        if (line) out.push(line);
        line = word;
      } else line = `${line} ${word}`.trim();
    }
    out.push(line);
  }
  return out;
};
const say = (who, color, text) => {
  panel.push(`\x1b[${color}m${who}\x1b[0m`);
  for (const l of wrap(text, RIGHT - 3)) panel.push(l);
  panel.push("");
};
const hideLink = (text) => text.replace(/https?:\/\/\S+#r=\S+/g, "[link]").replace(/\*\*/g, "").replace(/`/g, "");

await rig.model([{ tool: "Bash", input: { command: "rm -rf data", description: "Delete the old data folder" } }, { text: "Done. The old data folder is gone." }]);

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 390, height: 780 }, deviceScaleFactor: 1, colorScheme: "dark", recordVideo: { dir: tmp, size: { width: 390, height: 780 } } });
const page = await context.newPage();
const videoStart = Date.now();
await page.goto(`${pageUrl}#pair=${rig.device.pkcs8}&id=${rig.device.id}&name=${encodeURIComponent("my phone")}`);
await page.getByRole("heading", { name: "This device is paired" }).waitFor();

const t = rig.tui();
const tmux = (...args) => spawnSync("tmux", ["-L", t.socket, ...args], { encoding: "utf8" });
tmux("resize-window", "-t", "t", "-x", String(LEFT), "-y", String(ROWS));
await t.waitFor(/bypass permissions|shortcuts/, 20000);

const castStart = Date.now();
const cast = fs.openSync(castFile, "w");
fs.writeSync(cast, `${JSON.stringify({ version: 2, width: LEFT + RIGHT, height: ROWS, env: { TERM: "xterm-256color" } })}\n${JSON.stringify([0, "o", "\x1b[?25l"])}\n`);
let last = "";
let recording = true;
const frames = (async () => {
  while (recording) {
    const left = tmux("capture-pane", "-e", "-p", "-t", "t").stdout.split("\n");
    const shown = panel.slice(-(ROWS - 1));
    let frame = "";
    for (let row = 0; row < ROWS; row++) {
      frame += `\x1b[${row + 1};1H\x1b[0m\x1b[2K${left[row] ?? ""}\x1b[0m\x1b[${row + 1};${LEFT + 1}H\x1b[38;5;240m│\x1b[0m ${shown[row] ?? ""}`;
    }
    if (frame !== last) {
      fs.writeSync(cast, `${JSON.stringify([(Date.now() - castStart) / 1000, "o", frame])}\n`);
      last = frame;
    }
    await sleep(80);
  }
})();

await sleep(1200);
t.type("clean out the old data folder");
await sleep(900);
t.keys("Enter");
await t.waitFor(/Do you want to proceed/, 30000);
const told = (await rig.tool("wait_for_event", { cursor: 0, timeout_seconds: 5 })).events.find((e) => e.type === "request.opened");
say("sayso", "38;5;214", `Told your agent: my-app wants to run ${told.untrusted.action}`);
await sleep(1500);

panel.push("\x1b[2mYour agent is working...\x1b[0m");
const first = await runAgent("You are my personal agent, connected to my Claude Code sessions through sayso. Check what needs attention and handle it, following the rules sayso gives you. Then tell me in two short sentences what you did and what you need from me, with the approval link if there is one.");
panel.pop();
const link = /https?:\/\/\S+#r=[A-Za-z0-9_-]+/.exec(first)?.[0];
if (!link) throw new Error(`no link in: ${first}`);
say("Your agent", "38;5;75", hideLink(first));
await sleep(2500);

await page.goto(link);
await page.locator(".hold").waitFor();
await sleep(3500);
await page.locator(".hold").scrollIntoViewIfNeeded();
const box = await page.locator(".hold").boundingBox();
await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
await page.mouse.down();
await sleep(1100);
await page.mouse.up();
await page.locator(".code").waitFor();
const code = (await page.locator(".code").innerText()).trim();
await sleep(2200);
say("You", "38;5;114", `Here is the code. ${code.slice(0, 20)}...`);
await sleep(1000);

panel.push("\x1b[2mYour agent is working...\x1b[0m");
const request = (await rig.tool("list_requests")).requests[0];
const second = await runAgent(`You are my personal agent, connected through sayso. I read the request on my phone and approved it. Here is the code: ${code}\nFinish it. Request id ${request.id}. Then tell me in one short sentence what happened.`);
panel.pop();
say("Your agent", "38;5;75", hideLink(second.replace(code, "the code")));
await waitUntil(() => rig.destroyed(), 20000, "the approved command to run");
await t.waitFor(/old data folder is gone/, 20000);
await sleep(4000);

recording = false;
await frames;
fs.closeSync(cast);
t.kill();
const video = page.video();
await context.close();
await browser.close();
server.close();
const webm = await video.path();
await rig.close();

const offset = ((castStart - videoStart) / 1000).toFixed(2);
fs.mkdirSync(OUT, { recursive: true });
execFileSync("agg", ["--font-size", "16", "--theme", "github-dark", "--fps-cap", "15", "--last-frame-duration", "4", castFile, path.join(tmp, "term.gif")], { stdio: "ignore" });
const mp4 = path.join(OUT, "demo.mp4");
execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-i", path.join(tmp, "term.gif"), "-ss", offset, "-i", webm, "-filter_complex", "[0:v]fps=15,setpts=PTS-STARTPTS,pad=iw:ih+0:0:0:0x0d1117[t];[1:v]fps=15,setpts=PTS-STARTPTS[p];[p][t]scale2ref=oh*mdar:ih[p2][t2];[t2][p2]hstack=2:shortest=1,scale=trunc(iw/2)*2:trunc(ih/2)*2[v]", "-map", "[v]", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "24", mp4]);
execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-i", mp4, "-filter_complex", "fps=10,scale=1200:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle", path.join(OUT, "demo.gif")]);
fs.rmSync(tmp, { recursive: true, force: true });
console.log(JSON.stringify({ first, second, seconds: (Date.now() - castStart) / 1000 }, null, 2));
process.exit(0);
