#!/usr/bin/env node
// How long from "a session needs input" to "the agent knows", measured on the real binary.
// T0 is the moment the scripted model starts handing Claude Code the tool call. T1 is when each transport hands the
// event to a client in this same process, so both ends share one clock.
// Usage: node bench/latency.mjs [--runs 100] [--overhead-runs 40]
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Rig, CLAUDE, sleep, waitUntil } from "../test/harness/rig.mjs";
import { apiKeyEnv } from "../test/harness/tui.mjs";
import { startScriptedModel } from "../test/harness/scripted-model.mjs";

const arg = (name, fallback) => {
  const at = process.argv.indexOf(`--${name}`);
  return at >= 0 ? Number(process.argv[at + 1]) : fallback;
};
const RUNS = arg("runs", 100);
const OVERHEAD_RUNS = arg("overhead-runs", 40);
const here = path.dirname(fileURLToPath(import.meta.url));

const quantile = (values, q) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
};
const summary = (values) => ({ n: values.length, p50: +quantile(values, 0.5).toFixed(1), p95: +quantile(values, 0.95).toFixed(1), p99: +quantile(values, 0.99).toFixed(1), max: +Math.max(...values).toFixed(1) });

async function told() {
  const rig = new Rig();
  await rig.install();
  const samples = { sse: [], long_poll: [], webhook: [] };
  let t0 = 0;
  const plan = [{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "done" }];
  await rig.model(plan, { onToolEmitted: (_step, t) => (t0 = t) });

  const seenBy = { sse: new Set(), long_poll: new Set(), webhook: new Set() };
  const mark = (transport, requestId) => {
    if (!requestId || seenBy[transport].has(requestId)) return;
    seenBy[transport].add(requestId);
    samples[transport].push(performance.now() - t0);
  };

  const hook = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const event = JSON.parse(body);
      if (event.type === "request.opened") mark("webhook", event.request_id);
      res.end();
    });
  });
  await new Promise((r) => hook.listen(0, "127.0.0.1", r));
  rig.cli("notify", "add", "webhook", `http://127.0.0.1:${hook.address().port}/in`);

  const stream = await fetch(`http://127.0.0.1:${rig.port}/v1/events/stream`, { headers: { authorization: `Bearer ${rig.token}` } });
  const reader = stream.body.getReader();
  let open = true;
  (async () => {
    let buffer = "";
    while (open) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += Buffer.from(value).toString();
      let end;
      while ((end = buffer.indexOf("\n\n")) >= 0) {
        const chunk = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        const data = chunk.split("\n").find((l) => l.startsWith("data: "));
        if (data) {
          const event = JSON.parse(data.slice(6));
          if (event.type === "request.opened") mark("sse", event.request_id);
        }
      }
    }
  })().catch(() => {});

  (async () => {
    let cursor = 0;
    while (open) {
      const result = await rig.tool("wait_for_event", { cursor, timeout_seconds: 5 }).catch(() => null);
      if (!result) return;
      cursor = result.cursor;
      for (const e of result.events) if (e.type === "request.opened") mark("long_poll", e.request_id);
    }
  })();

  for (let i = 0; i < RUNS; i++) {
    fs.mkdirSync(path.dirname(rig.victim), { recursive: true });
    fs.writeFileSync(rig.victim, "keep");
    const session = rig.headless();
    const request = await rig.nextRequest(30000);
    await waitUntil(() => seenBy.sse.has(request.id) && seenBy.long_poll.has(request.id) && seenBy.webhook.has(request.id), 5000, "all transports");
    await rig.tool("deny", { request_id: request.id });
    await session.done;
    if (rig.destroyed()) throw new Error("a denied request ran");
  }
  open = false;
  await reader.cancel().catch(() => {});
  hook.close();
  await rig.close();
  return Object.fromEntries(Object.entries(samples).map(([k, v]) => [k, summary(v)]));
}

// What the gate costs every ordinary tool call: tool emitted to its result coming back, with and without sayso. The two
// sides alternate so that drifting machine load falls on both.
async function overhead() {
  const side = async (withSayso) => {
    const rig = new Rig();
    if (withSayso) await rig.install();
    else fs.writeFileSync(path.join(rig.config, "settings.json"), JSON.stringify({ skipDangerousModePermissionPrompt: true }));
    const times = [];
    let t0 = 0;
    const steps = [];
    for (let i = 0; i < 3; i++) steps.push({ tool: "Bash", input: { command: "true", description: "noop" } });
    steps.push({ text: "done" });
    const model = await startScriptedModel(steps, {
      onToolEmitted: (_s, t) => (t0 = t),
      onRequest: (body) => {
        if (!body.tools?.length) return;
        const last = body.messages?.filter((m) => m.role === "user").at(-1);
        if (t0 && Array.isArray(last?.content) && last.content.some((c) => c.type === "tool_result")) times.push(performance.now() - t0);
      },
    });
    let failures = 0;
    const once = async () => {
      const child = spawn(CLAUDE, ["-p", "go", "--model", "claude-scripted", "--dangerously-skip-permissions"], { cwd: rig.cwd, env: apiKeyEnv(rig, model.url, rig.env()), stdio: "ignore" });
      const code = await new Promise((r) => child.on("exit", r));
      if (code !== 0) failures++;
    };
    const close = async () => {
      model.close();
      if (withSayso) await rig.close();
      else fs.rmSync(rig.root, { recursive: true, force: true });
      return { ...summary(times), failed_runs: failures };
    };
    return { once, close };
  };
  const without = await side(false);
  const withIt = await side(true);
  for (let i = 0; i < OVERHEAD_RUNS; i++) {
    await without.once();
    await withIt.once();
  }
  return { without_sayso: await without.close(), with_sayso: await withIt.close() };
}

function hookAlone() {
  const rig = new Rig();
  const samples = [];
  const input = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "bench", cwd: rig.cwd, tool_name: "Bash", tool_input: { command: "git status" } });
  const script = path.join(here, "..", "hooks", "run.sh");
  return (async () => {
    for (let i = 0; i < 50; i++) {
      const t = performance.now();
      const child = spawn("sh", [script, "gate"], { env: rig.env(), stdio: ["pipe", "ignore", "ignore"] });
      child.stdin.end(input);
      await new Promise((r) => child.on("exit", r));
      samples.push(performance.now() - t);
    }
    fs.rmSync(rig.root, { recursive: true, force: true });
    return summary(samples);
  })();
}

const started = Date.now();
const out = {
  machine: `${os.cpus()[0].model}, ${os.cpus().length} cores, ${os.platform()} ${os.release()}`,
  node: process.version,
  claude_code: (await new Promise((resolve) => {
    let v = "";
    const c = spawn(CLAUDE, ["--version"]);
    c.stdout.on("data", (d) => (v += d));
    c.on("exit", () => resolve(v.trim()));
  })),
  unit: "milliseconds",
  load_average_at_start: os.loadavg()[0],
  session_needs_input_to_agent_told: await told(),
  gate_on_an_ordinary_command_alone: await hookAlone(),
  tool_round_trip: await overhead(),
  load_average_at_end: os.loadavg()[0],
  wall_seconds: Math.round((Date.now() - started) / 1000),
};
fs.writeFileSync(path.join(here, "results.json"), `${JSON.stringify(out, null, 2)}\n`);
console.log(JSON.stringify(out, null, 2));
process.exit(0);
