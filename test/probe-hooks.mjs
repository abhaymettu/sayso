#!/usr/bin/env node
// What does the installed Claude Code really do? Runs the real binary against a scripted model, one permission mode and
// one hook behaviour at a time, and records whether `rm -rf victim` actually destroyed the directory.
// Usage: node test/probe-hooks.mjs [--json]
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startScriptedModel } from "./harness/scripted-model.mjs";

const CLAUDE = process.env.CLAUDE_BIN || "claude";
const MODES = ["default", "acceptEdits", "plan", "dontAsk", "bypassPermissions"];
const EVENTS = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "PostToolUseFailure", "Notification", "Stop", "StopFailure", "SessionEnd"];

function sandbox(hookForEvent, hookTimeout) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "probe-"));
  const config = path.join(root, "config");
  const cwd = path.join(root, "work");
  fs.mkdirSync(config);
  fs.mkdirSync(path.join(cwd, "victim"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "victim", "file.txt"), "keep me");
  const log = path.join(root, "events.jsonl");
  const logger = path.join(root, "log.sh");
  fs.writeFileSync(logger, `#!/bin/sh\ninput=$(cat)\nprintf '%s\\n' "$input" >> "${log}"\nexit 0\n`, { mode: 0o755 });
  const hooks = {};
  for (const event of EVENTS) hooks[event] = [{ hooks: [{ type: "command", command: logger }] }];
  if (hookForEvent) {
    for (const [event, script] of Object.entries(hookForEvent)) {
      const file = path.join(root, `${event}.sh`);
      fs.writeFileSync(file, `#!/bin/sh\n${script}\n`, { mode: 0o755 });
      hooks[event] = [...(hooks[event] || []), { hooks: [{ type: "command", command: file, ...(hookTimeout ? { timeout: hookTimeout } : {}) }] }];
    }
  }
  fs.writeFileSync(path.join(config, "settings.json"), JSON.stringify({ hooks }, null, 2));
  return { root, config, cwd, log, victim: path.join(cwd, "victim", "file.txt") };
}

function cleanEnv(box, baseUrl) {
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    TMPDIR: process.env.TMPDIR,
    CLAUDE_CONFIG_DIR: box.config,
    ANTHROPIC_API_KEY: "sk-ant-scripted-model-not-a-real-key",
    ANTHROPIC_BASE_URL: baseUrl,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    DISABLE_TELEMETRY: "1",
  };
}

async function run({ mode, hookForEvent, hookTimeout, plan, killHookAfterMs, deadlineMs = 90000 }) {
  const box = sandbox(hookForEvent, hookTimeout);
  const steps = plan?.(box) ?? [{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "finished" }];
  const model = await startScriptedModel(steps);
  const args = ["-p", "go", "--model", "claude-scripted", "--output-format", "json", "--permission-mode", mode];
  if (mode === "bypassPermissions") args.push("--dangerously-skip-permissions");
  const child = spawn(CLAUDE, args, { cwd: box.cwd, env: cleanEnv(box, model.url), stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const t0 = performance.now();
  if (killHookAfterMs) {
    setTimeout(() => {
      // SIGKILL the running hook script, simulating a crash mid-hold.
      spawnSync("pkill", ["-9", "-f", `${box.root}/PreToolUse.sh`]);
    }, killHookAfterMs);
  }
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve("timed-out");
    }, deadlineMs);
    child.on("exit", (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  model.close();
  const events = fs.existsSync(box.log) ? fs.readFileSync(box.log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  const toolResult = model.seen.toolResults[0] ?? null;
  const result = {
    mode,
    exit: code,
    seconds: +((performance.now() - t0) / 1000).toFixed(1),
    destroyed: !fs.existsSync(box.victim),
    fired: [...new Set(events.map((e) => e.hook_event_name))],
    hookPermissionMode: events.find((e) => e.hook_event_name === "PreToolUse")?.permission_mode,
    toolResult: toolResult?.slice(0, 200) ?? null,
    stderr: err.slice(0, 200),
    events,
  };
  fs.rmSync(box.root, { recursive: true, force: true });
  return result;
}

const scenarios = {
  "no gate hook": {},
  "PreToolUse: permissionDecision deny": { hookForEvent: { PreToolUse: `cat >/dev/null; echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"held by gate"}}'` } },
  "PreToolUse: permissionDecision ask": { hookForEvent: { PreToolUse: `cat >/dev/null; echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"ask"}}'` } },
  "PreToolUse: permissionDecision allow": { hookForEvent: { PreToolUse: `cat >/dev/null; echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'` } },
  "PreToolUse: exit 2": { hookForEvent: { PreToolUse: `cat >/dev/null; echo blocked >&2; exit 2` } },
  "PreToolUse: exit 1": { hookForEvent: { PreToolUse: `cat >/dev/null; exit 1` } },
  "PreToolUse: command not found": { hookForEvent: { PreToolUse: `cat >/dev/null; exec /nonexistent/runtime` } },
  "PreToolUse: garbage stdout": { hookForEvent: { PreToolUse: `cat >/dev/null; echo '{not json'; exit 0` } },
  "PreToolUse: killed with SIGKILL mid-hold": { hookForEvent: { PreToolUse: `cat >/dev/null; sleep 30` }, killHookAfterMs: 4000 },
  "PreToolUse: exceeds its timeout (3s)": { hookForEvent: { PreToolUse: `cat >/dev/null; sleep 30` }, hookTimeout: 3 },
  "PreToolUse: wrapper, exit 1 becomes exit 2": { hookForEvent: { PreToolUse: `cat >/dev/null; sh -c 'exit 1' || exit 2` } },
  "PreToolUse: wrapper, inner killed becomes exit 2": { hookForEvent: { PreToolUse: `cat >/dev/null; sleep 30 || exit 2` }, killInner: true },
};

const results = [];
const only = process.argv.find((a) => a.startsWith("--only="))?.slice(7);
for (const [name, spec] of Object.entries(scenarios)) {
  if (only && !name.includes(only)) continue;
  for (const mode of MODES) {
    if (name !== "no gate hook" && !name.includes("deny") && !name.includes("ask") && mode !== "bypassPermissions") continue;
    const r = await run({ mode, ...spec });
    results.push({ scenario: name, ...r, events: undefined });
    console.log(`${r.destroyed ? "DESTROYED" : "kept     "} ${mode.padEnd(18)} ${name.padEnd(46)} fired=${r.fired.join(",")} ${r.seconds}s exit=${r.exit}${r.toolResult ? ` result=${JSON.stringify(r.toolResult.slice(0, 80))}` : ""}`);
  }
}
if (process.argv.includes("--json")) console.log(JSON.stringify(results, null, 2));
