#!/usr/bin/env node
// Runs inside every Claude Code hook. By default Claude Code treats a crash, a kill or a timeout here as "carry on" and runs
// the tool, so hooks/run.sh turns any non-zero exit into a block, and every path below must end in an explicit answer.
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { classifyToolCall, readToTheEnd } from "./classify.mjs";
import { MAX_HOLD_SECONDS, statePaths } from "./paths.mjs";

const paths = statePaths();
const mode = process.argv[2];
const READ_LIMIT_MS = 3000;
const ASK_LIMIT_MS = 2000;
const OPEN_LIMIT_MS = 10000;
const HOLD_GRACE_MS = 3000;

function writeAndExit(obj) {
  fs.writeSync(1, JSON.stringify(obj));
  process.exit(0);
}

const preToolUse = (permissionDecision, reason, extra = {}) =>
  writeAndExit({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason: reason, ...extra } });

const permissionRequest = (decision) => writeAndExit({ hookSpecificOutput: { hookEventName: "PermissionRequest", decision } });

function startDaemonDetached() {
  const server = path.join(path.dirname(fileURLToPath(import.meta.url)), "server.mjs");
  const child = spawn(process.execPath, ["--disable-sigusr1", server], { detached: true, stdio: "ignore", env: process.env });
  child.unref();
}

function connect(retryMs) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + retryMs;
    let started = false;
    const attempt = () => {
      const socket = net.connect(paths.sock);
      socket.once("connect", () => resolve(socket));
      socket.once("error", (error) => {
        socket.destroy();
        if (Date.now() >= deadline) return reject(error);
        if (!started) {
          started = true;
          startDaemonDetached();
        }
        setTimeout(attempt, 40);
      });
    };
    attempt();
  });
}

// True only for a person's terminal. A wrong guess either way stays safe: a false "attended" gets a dialog nobody can
// answer, which runs nothing, and a false "unattended" gets a hold without the dialog.
function isAttended() {
  if (process.env.CLAUDE_CODE_SESSION_ATTENDED === "0") return false;
  const pid = process.env.CLAUDE_PID;
  if (!pid) return false;
  const tty = spawnSync("ps", ["-o", "tty=", "-p", pid], { encoding: "utf8", timeout: ASK_LIMIT_MS }).stdout?.trim();
  return !!tty && tty !== "?" && tty !== "??";
}

function sessionFields(input) {
  return {
    session_id: input.session_id,
    cwd: input.cwd,
    permission_mode: input.permission_mode,
    pid: Number(process.env.CLAUDE_PID) || undefined,
  };
}

function holdAtDaemon(payload) {
  return new Promise((resolve) => {
    const started = Date.now();
    const absolute = started + MAX_HOLD_SECONDS * 1000 + 30000;
    // Until the daemon says `opened`, only this ends the wait. A stopped daemon still accepts connections.
    let deadline = started + OPEN_LIMIT_MS;
    let socket = null;
    const wrapper = process.ppid;
    // Wall clock, so a hold that spans a laptop sleep ends on wake rather than running on.
    setInterval(() => {
      // With the wrapper gone the session has moved on, and nobody should be asked to sign a call that can no longer run.
      if (process.ppid !== wrapper) process.exit(2);
      if (Date.now() <= deadline) return;
      resolve({ failure: "no answer from the sayso daemon in time" });
      socket?.destroy();
    }, 250);
    connect(2000)
      .then((connected) => {
        socket = connected;
        let buffer = "";
        socket.setEncoding("utf8");
        socket.on("data", (chunk) => {
          buffer += chunk;
          let end;
          while ((end = buffer.indexOf("\n")) >= 0) {
            const message = JSON.parse(buffer.slice(0, end));
            buffer = buffer.slice(end + 1);
            if (message.opened) {
              const until = Date.parse(message.expires_at) + HOLD_GRACE_MS;
              deadline = until < absolute ? until : absolute;
            } else {
              resolve(message);
            }
          }
        });
        socket.on("error", () => resolve({ failure: "the connection to the sayso daemon broke" }));
        socket.on("close", () => resolve({ failure: "the connection to the sayso daemon closed" }));
        socket.write(`${JSON.stringify({ op: "hold", ...payload })}\n`);
      })
      .catch(() => resolve({ failure: "the sayso daemon is not running" }));
  });
}

// One question and one answer. A stuck daemon counts as no answer.
function ask(message, retryMs = 0) {
  return new Promise((resolve) => {
    setTimeout(() => resolve(null), ASK_LIMIT_MS + retryMs);
    connect(retryMs)
      .then((socket) => {
        let buffer = "";
        socket.setEncoding("utf8");
        socket.on("data", (chunk) => (buffer += chunk));
        socket.on("error", () => resolve(null));
        socket.on("close", () => {
          try {
            resolve(JSON.parse(buffer));
          } catch {
            resolve(null);
          }
        });
        socket.write(`${JSON.stringify(message)}\n`);
      })
      .catch(() => resolve(null));
  });
}

// Most tool calls stop at the existsSync. The daemon hands over the text, so this works when the hook cannot write there.
async function takeMail(sessionId) {
  if (!fs.existsSync(path.join(paths.mail, encodeURIComponent(sessionId ?? "")))) return null;
  return (await ask({ op: "take_mail", session_id: sessionId }))?.text ?? null;
}

// A timer on this thread never fires while the classifier holds it, so the limit has to interrupt from outside. Anything
// that stops it finishing could be hiding what it would have found, which is why the warning sends it to the person.
function verdictFor(input) {
  const ctx = { home: homedir(), cwd: input.cwd ?? process.cwd(), stateDir: paths.dir, configDir: process.env.CLAUDE_CONFIG_DIR || undefined };
  try {
    const verdict = vm.runInNewContext("read()", { read: () => classifyToolCall(input.tool_name, input.tool_input ?? {}, ctx) }, { timeout: READ_LIMIT_MS });
    return readToTheEnd(verdict) ? verdict : { ...verdict, warnings: [...(verdict.warnings ?? []), "sayso could not finish reading this"] };
  } catch (error) {
    const unread = error.code === "ERR_SCRIPT_EXECUTION_TIMEOUT" ? "ran out of time" : `failed: ${error.message}`;
    return { risk: "opaque", why: [`sayso could not read this command: ${unread}`], warnings: ["sayso could not finish reading this"] };
  }
}

// The daemon holds the policy and the log, so a pass rule only counts once the daemon has checked it and written it down.
async function passedByRule(input, verdict) {
  if ((input.tool_name !== "Bash" && !verdict.nameOnly) || verdict.risk === "catastrophic" || verdict.risk === "self") return false;
  const reply = await ask({ op: "pass", session_id: input.session_id, risk: verdict.risk, name_only: verdict.nameOnly, tool: input.tool_name, input: input.tool_input, dialog: input.hook_event_name !== "PreToolUse" }, ASK_LIMIT_MS);
  return reply?.pass === true;
}

const failClosed = (why) => `sayso: blocked because ${why}. Nothing ran. The person can check with \`sayso doctor\`.`;

async function gate(input) {
  let verdict = verdictFor(input);
  if (verdict && (await passedByRule(input, verdict))) verdict = null;
  const tool = input.tool_name;

  if (input.hook_event_name === "PreToolUse") {
    const mail = await takeMail(input.session_id);
    const context = mail ? { additionalContext: mail } : {};
    if (!verdict) {
      if (mail) writeAndExit({ hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: mail } });
      process.exit(0);
    }
    const attended = isAttended();
    // At a terminal, "ask" puts the real dialog on screen and fires PermissionRequest, where the same hold races it.
    if (attended) preToolUse("ask", `sayso: ${verdict.why[0] ?? verdict.risk}. Answer here, or your agent can get your say-so.`, context);
    const answer = await holdAtDaemon({ ...sessionFields(input), attended, kind: "tool", risk: verdict.risk, why: verdict.why, warnings: verdict.warnings, tool, input: input.tool_input });
    if (answer.decision === "allow") preToolUse("allow", answer.reason ?? "sayso: approved", context);
    preToolUse("deny", answer.failure ? failClosed(answer.failure) : (answer.reason ?? "sayso: denied"), context);
  }

  // PermissionRequest: the dialog is on screen while this waits, and whichever answer comes first wins.
  const kind = tool === "AskUserQuestion" ? "question" : tool === "ExitPlanMode" ? "plan" : verdict ? "tool" : "prompt";
  const risk = kind === "question" ? "question" : kind === "plan" ? "plan" : (verdict?.risk ?? "prompt");
  const answer = await holdAtDaemon({ ...sessionFields(input), attended: isAttended(), dialog: true, kind, risk, why: verdict?.why ?? [], warnings: verdict?.warnings, tool, input: input.tool_input });
  if (answer.decision === "closed") process.exit(0);
  if (answer.decision === "allow") permissionRequest({ behavior: "allow" });
  if (answer.decision === "answer") permissionRequest({ behavior: "allow", updatedInput: answer.updatedInput });
  if (answer.decision === "deny" && !answer.failure) permissionRequest({ behavior: "deny", message: answer.reason ?? "sayso: denied" });
  // A flagged call with no answer is a no. An ordinary prompt can stay on screen, since the dialog itself runs nothing.
  if (verdict) permissionRequest({ behavior: "deny", message: answer.failure ? failClosed(answer.failure) : (answer.reason ?? "sayso: no answer") });
  process.exit(0);
}

async function reportEvent(input) {
  setTimeout(() => process.exit(0), 5000);
  const socket = await connect(input.hook_event_name === "SessionStart" ? 1500 : 300);
  socket.on("error", () => process.exit(0));
  socket.end(
    `${JSON.stringify({
      op: "event",
      t: Date.now(),
      ...sessionFields(input),
      attended: input.hook_event_name === "SessionStart" ? isAttended() : undefined,
      hook_event_name: input.hook_event_name,
      notification_type: input.notification_type,
      last_assistant_message: input.last_assistant_message,
      error_message: input.error_message ?? input.error,
      tool_name: input.tool_name,
      input_sha256: input.tool_input === undefined ? undefined : crypto.createHash("sha256").update(JSON.stringify(input.tool_input)).digest("hex"),
    })}\n`,
    () => process.exit(0),
  );
}

// Claude Code keeps this running beside an idle session. Exit 2 with text on stderr wakes the session with that text.
async function waitForMessage(input) {
  const socket = await connect(300);
  let buffer = "";
  socket.setEncoding("utf8");
  socket.on("data", (chunk) => (buffer += chunk));
  socket.on("error", () => process.exit(0));
  socket.on("close", () => {
    try {
      const { message } = JSON.parse(buffer.trim() || "{}");
      if (message) {
        fs.writeSync(2, message);
        process.exit(2);
      }
    } catch {}
    process.exit(0);
  });
  socket.write(`${JSON.stringify({ op: "wait_message", session_id: input.session_id })}\n`);
}

let input;
try {
  input = JSON.parse(fs.readFileSync(0, "utf8"));
} catch {
  if (mode === "gate") {
    process.stderr.write("sayso: could not read the hook input, so this tool call was blocked.\n");
    process.exit(2);
  }
  process.exit(0);
}

if (mode === "gate") {
  await gate(input);
} else if (mode === "wake") {
  await waitForMessage(input).catch(() => process.exit(0));
} else {
  await reportEvent(input).catch(() => process.exit(0));
}
