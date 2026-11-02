#!/usr/bin/env node
// Interactive behaviour of the real terminal UI: dialogs, holds, questions, and reaching an idle session.
import fs from "node:fs";
import path from "node:path";
import { startScriptedModel } from "./harness/scripted-model.mjs";
import { Tui, apiKeyEnv, newBox, sleep } from "./harness/tui.mjs";

function installHooks(box, hooks) {
  const log = path.join(box.root, "events.jsonl");
  const logger = path.join(box.root, "log.sh");
  fs.writeFileSync(logger, `#!/bin/sh\ninput=$(cat)\nprintf '%s\\n' "$input" >> "${log}"\nexit 0\n`, { mode: 0o755 });
  const settings = { skipDangerousModePermissionPrompt: true, hooks: {} };
  for (const e of ["SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PermissionDenied", "PostToolUse", "PostToolUseFailure", "Notification", "Stop", "SessionEnd", "Elicitation"])
    settings.hooks[e] = [{ hooks: [{ type: "command", command: logger }] }];
  for (const [event, spec] of Object.entries(hooks)) {
    const file = path.join(box.root, `${event}.sh`);
    fs.writeFileSync(file, `#!/bin/sh\n${spec.script}\n`, { mode: 0o755 });
    const entry = { type: "command", command: file, ...(spec.opts || {}) };
    settings.hooks[event] = [...(settings.hooks[event] || []), { ...(spec.matcher ? { matcher: spec.matcher } : {}), hooks: [entry] }];
  }
  fs.writeFileSync(path.join(box.config, "settings.json"), JSON.stringify(settings, null, 2));
  return () => (fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
}

const names = (evts) => evts.map((e) => e.hook_event_name + (e.notification_type ? `:${e.notification_type}` : "")).join(" ");
const tail = (s) => s.split("\n").filter((l) => l.trim()).slice(-14).join("\n");

const probes = {
  // Does the terminal stay usable during a hold, and does Esc cancel the command?
  async holdThenEsc() {
    const box = newBox();
    const events = installHooks(box, { PreToolUse: { script: `cat >/dev/null; sleep 60; exit 0`, opts: { timeout: 120 } } });
    const model = await startScriptedModel([{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "finished" }]);
    const t = new Tui(box, apiKeyEnv(box, model.url), ["--dangerously-skip-permissions", "--model", "claude-scripted"]);
    await sleep(2500);
    t.type("go");
    t.keys("Enter");
    await sleep(3500);
    console.log("--- during hold\n" + tail(t.screen()));
    t.keys("Escape");
    await sleep(2500);
    console.log("--- after Esc\n" + tail(t.screen()));
    console.log("destroyed:", !fs.existsSync(box.victim), "| events:", names(events()));
    t.kill();
    model.close();
  },
  // "ask" in bypass mode: does the terminal show a dialog?
  async askInBypass() {
    const box = newBox();
    const events = installHooks(box, { PreToolUse: { script: `cat >/dev/null; echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"gate wants a human"}}'` } });
    const model = await startScriptedModel([{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "finished" }]);
    const t = new Tui(box, apiKeyEnv(box, model.url), ["--dangerously-skip-permissions", "--model", "claude-scripted"]);
    await sleep(2500);
    t.type("go");
    t.keys("Enter");
    await sleep(3500);
    console.log("--- screen\n" + tail(t.screen()));
    console.log("destroyed:", !fs.existsSync(box.victim), "| events:", names(events()));
    t.kill();
    model.close();
  },
  // Default mode: does the dialog appear while a PermissionRequest hook holds, and does the hook's answer close it?
  async permissionRequestHold() {
    const box = newBox();
    const events = installHooks(box, { PermissionRequest: { script: `cat >/dev/null; sleep 6; echo '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}'`, opts: { timeout: 60 } } });
    const model = await startScriptedModel([{ tool: "Bash", input: { command: "rm -rf victim", description: "delete" } }, { text: "finished" }]);
    const t = new Tui(box, apiKeyEnv(box, model.url), ["--model", "claude-scripted", "--permission-mode", "default"]);
    await sleep(2500);
    t.type("go");
    t.keys("Enter");
    await sleep(3000);
    console.log("--- during PermissionRequest hook\n" + tail(t.screen()));
    await sleep(6000);
    console.log("--- after hook answered\n" + tail(t.screen()));
    console.log("destroyed:", !fs.existsSync(box.victim), "| events:", names(events()));
    t.kill();
    model.close();
  },
  // AskUserQuestion: can a PreToolUse hook answer it with updatedInput?
  async askUserQuestion() {
    const box = newBox();
    const answer = JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: { questions: [{ question: "Which colour?", header: "Colour", options: [{ label: "Red", description: "r" }, { label: "Blue", description: "b" }], multiSelect: false }], answers: { "Which colour?": "Blue" } } } });
    const events = installHooks(box, { PreToolUse: { matcher: "AskUserQuestion", script: `cat >/dev/null; echo '${answer}'` } });
    const model = await startScriptedModel([{ tool: "AskUserQuestion", input: { questions: [{ question: "Which colour?", header: "Colour", options: [{ label: "Red", description: "r" }, { label: "Blue", description: "b" }], multiSelect: false }] } }, { text: "finished" }]);
    const t = new Tui(box, apiKeyEnv(box, model.url), ["--dangerously-skip-permissions", "--model", "claude-scripted"]);
    await sleep(2500);
    t.type("go");
    t.keys("Enter");
    await sleep(3500);
    console.log("--- screen\n" + tail(t.screen()));
    console.log("tool result:", model.seen.toolResults[0]?.slice(0, 300));
    console.log("events:", names(events()));
    t.kill();
    model.close();
  },
  // AskUserQuestion with no hook answer: what the screen shows, which events fire.
  async askUserQuestionDialog() {
    const box = newBox();
    const events = installHooks(box, {});
    const model = await startScriptedModel([{ tool: "AskUserQuestion", input: { questions: [{ question: "Which colour?", header: "Colour", options: [{ label: "Red", description: "r" }, { label: "Blue", description: "b" }], multiSelect: false }] } }, { text: "finished" }]);
    const t = new Tui(box, apiKeyEnv(box, model.url), ["--dangerously-skip-permissions", "--model", "claude-scripted"]);
    await sleep(2500);
    t.type("go");
    t.keys("Enter");
    await sleep(8000);
    console.log("--- screen\n" + tail(t.screen()));
    console.log("events:", names(events()));
    t.kill();
    model.close();
  },
  // Reaching an idle session. An async rewake Stop hook waits on a file, then exits 2 with a message.
  async asyncRewake() {
    const box = newBox();
    const flag = path.join(box.root, "reply.txt");
    const events = installHooks(box, {
      Stop: {
        script: `cat >/dev/null; i=0; while [ $i -lt 200 ]; do if [ -f "${flag}" ]; then cat "${flag}" >&2; rm -f "${flag}"; exit 2; fi; sleep 0.1; i=$((i+1)); done; exit 0`,
        opts: { async: true, asyncRewake: true, rewakeMessage: "Your owner's agent says:", timeout: 300 },
      },
    });
    const seenTexts = [];
    const model = await startScriptedModel((messages) => {
      const last = messages[messages.length - 1];
      seenTexts.push(typeof last.content === "string" ? last.content : JSON.stringify(last.content));
      return { text: `reply ${seenTexts.length}` };
    });
    const t = new Tui(box, apiKeyEnv(box, model.url), ["--dangerously-skip-permissions", "--model", "claude-scripted"]);
    await sleep(2500);
    t.type("go");
    t.keys("Enter");
    await sleep(3000);
    console.log("--- idle\n" + tail(t.screen()));
    fs.writeFileSync(flag, "use option B please");
    await sleep(4000);
    console.log("--- after reply\n" + tail(t.screen()));
    console.log("model saw on wake:", JSON.stringify(seenTexts.at(-1)).slice(0, 400));
    console.log("events:", names(events()));
    t.kill();
    model.close();
  },
};

const pick = process.argv[2];
for (const [name, fn] of Object.entries(probes)) {
  if (pick && pick !== name) continue;
  console.log(`\n===== ${name}`);
  try {
    await fn();
  } catch (e) {
    console.log("ERROR", e.message.slice(0, 800));
  }
}
process.exit(0);
