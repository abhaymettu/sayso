#!/usr/bin/env node
// Runs inside every Claude Code hook. Claude Code treats a crash, a kill or a timeout here as "carry on" and runs the
// tool, so hooks/run.sh turns any non-zero exit into a block, and every path below must end in an explicit answer.
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyToolCall } from "./classify.mjs";
import { statePaths } from "./paths.mjs";
import { loadPolicy, matchesPassRule } from "./policy.mjs";

const paths = statePaths();
const mode = process.argv[2];

function writeAndExit(obj) {
  fs.writeSync(1, JSON.stringify(obj));
  process.exit(0);
}

const preToolUse = (permissionDecision, reason, extra = {}) =>
  writeAndExit({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason: reason, ...extra } });

const permissionRequest = (decision) => writeAndExit({ hookSpecificOutput: { hookEventName: "PermissionRequest", decision } });

function startDaemonDetached() {
  const server = path.join(path.dirname(fileURLToPath(import.meta.url)), "server.mjs");
  const child = spawn(process.execPath, [server], { detached: true, stdio: "ignore", env: process.env });
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
  const tty = spawnSync("ps", ["-o", "tty=", "-p", pid], { encoding: "utf8" }).stdout?.trim();
  return !!tty && tty !== "?" && tty !== "??";
}

function sessionFields(input) {
  return {
    session_id: input.session_id,
    cwd: input.cwd,
    permission_mode: input.permission_mode,
    pid: Number(process.env.CLAUDE_PID) || undefined,
    entrypoint: process.env.CLAUDE_CODE_ENTRYPOINT,
  };
}

function holdAtDaemon(payload, onOpened) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    connect(2000)
      .then((socket) => {
        let buffer = "";
        let deadline = null;
        const watchdog = setInterval(() => {
          // Wall clock, so a hold that spans a laptop sleep ends on wake rather than running on.
          if (deadline && Date.now() > deadline + 3000) {
            socket.destroy();
            finish({ failure: "no answer from the sayso daemon in time" });
          }
        }, 1000);
        watchdog.unref();
        socket.setEncoding("utf8");
        socket.on("data", (chunk) => {
          buffer += chunk;
          let end;
          while ((end = buffer.indexOf("\n")) >= 0) {
            const message = JSON.parse(buffer.slice(0, end));
            buffer = buffer.slice(end + 1);
            if (message.opened) {
              deadline = Date.parse(message.expires_at);
              onOpened?.(message);
            } else {
              finish(message);
            }
          }
        });
        socket.on("error", () => finish({ failure: "the connection to the sayso daemon broke" }));
        socket.on("close", () => finish({ failure: "the connection to the sayso daemon closed" }));
        socket.write(`${JSON.stringify({ op: "hold", ...payload })}\n`);
      })
      .catch(() => finish({ failure: "the sayso daemon is not running" }));
  });
}

// Most tool calls stop at the existsSync. The daemon hands over the text, so this works when the hook cannot write there.
function takeMail(sessionId) {
  if (!fs.existsSync(path.join(paths.mail, encodeURIComponent(sessionId ?? "")))) return Promise.resolve(null);
  return connect(0)
    .then(
      (socket) =>
        new Promise((resolve) => {
          let buffer = "";
          socket.setEncoding("utf8");
          socket.on("data", (chunk) => (buffer += chunk));
          socket.on("error", () => resolve(null));
          socket.on("close", () => {
            try {
              resolve(JSON.parse(buffer).text ?? null);
            } catch {
              resolve(null);
            }
          });
          socket.write(`${JSON.stringify({ op: "take_mail", session_id: sessionId })}\n`);
        }),
    )
    .catch(() => null);
}

function verdictFor(input) {
  const ctx = { home: homedir(), cwd: input.cwd ?? process.cwd(), stateDir: paths.dir };
  let verdict;
  try {
    verdict = classifyToolCall(input.tool_name, input.tool_input ?? {}, ctx);
  } catch (error) {
    verdict = { risk: "opaque", why: [`could not read this command: ${error.message}`] };
  }
  if (verdict && input.tool_name === "Bash") {
    if (verdict.risk !== "catastrophic" && verdict.risk !== "self" && matchesPassRule(input.tool_input?.command, loadPolicy(paths.policy).pass)) return null;
  }
  return verdict;
}

const failClosed = (why) => `sayso: blocked because ${why}. Nothing ran. The person can check with \`sayso doctor\`.`;

async function gate(input) {
  const verdict = verdictFor(input);
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
    const answer = await holdAtDaemon({ ...sessionFields(input), attended, kind: "tool", risk: verdict.risk, why: verdict.why, tool, input: input.tool_input });
    if (answer.decision === "allow") preToolUse("allow", answer.reason ?? "sayso: approved", context);
    preToolUse("deny", answer.failure ? failClosed(answer.failure) : (answer.reason ?? "sayso: denied"), context);
  }

  // PermissionRequest: the dialog is on screen while this waits, and whichever answer comes first wins.
  const kind = tool === "AskUserQuestion" ? "question" : tool === "ExitPlanMode" ? "plan" : verdict ? "tool" : "prompt";
  const risk = kind === "question" ? "question" : kind === "plan" ? "plan" : (verdict?.risk ?? "prompt");
  const answer = await holdAtDaemon({ ...sessionFields(input), attended: isAttended(), dialog: true, kind, risk, why: verdict?.why ?? [], tool, input: input.tool_input });
  if (answer.decision === "closed") process.exit(0);
  if (answer.decision === "allow") permissionRequest({ behavior: "allow" });
  if (answer.decision === "answer") permissionRequest({ behavior: "allow", updatedInput: answer.updatedInput });
  if (answer.decision === "deny" && !answer.failure) permissionRequest({ behavior: "deny", message: answer.reason ?? "sayso: denied" });
  // A flagged call with no answer is a no. An ordinary prompt can stay on screen, since the dialog itself runs nothing.
  if (verdict) permissionRequest({ behavior: "deny", message: answer.failure ? failClosed(answer.failure) : (answer.reason ?? "sayso: no answer") });
  process.exit(0);
}

async function reportEvent(input) {
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
