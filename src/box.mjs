// The daemon's state and every rule about who may decide what. No sockets here, so each rule is testable directly.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { openAudit } from "./audit.mjs";
import { RISKS, matchesPassRule, matchesToolRule } from "./policy.mjs";
import { faithful, forDisplay, redact } from "./redact.mjs";
import { encodeDoc, verifyApproval } from "./sign.mjs";

/** @typedef {"pending"|"approved"|"denied"|"answered"|"expired"|"cancelled"} RequestStatus */
/** @typedef {{type: "agent"|"human"|"owner"|"system", name: string, key_id?: string, via?: string}} Actor */

const MAX_BAD_SIGNATURES = 3;
const MAX_EVENTS = 2000;
const MAX_PENDING_PER_SESSION = 8;
const MAX_PENDING = 64;
const TEXT_LIMIT_MS = 2000;
const REDACTED = "part of this is hidden as a possible secret, and the hidden part could be a command or a path";
// A key's or token's own shape can't hold a command. What these markers replaced could, so nobody can sign over one.
const HIDES_ANYTHING = /\[redacted(?: blob| hex| encoded)?\]/;
// A session writes these fields itself, and they reach the agent outside `untrusted`, so only known values get that far.
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;
const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,128}$/;
const KINDS = new Set(["tool", "question", "plan", "prompt"]);
const REQUEST_RISKS = new Set([...RISKS, "question"]);
const PERMISSION_MODES = new Set(["default", "acceptEdits", "bypassPermissions", "plan", "dontAsk", "auto"]);

const SESSION_STATE = {
  SessionStart: "idle",
  UserPromptSubmit: "working",
  PostToolUse: "working",
  PostToolUseFailure: "working",
  Stop: "waiting",
  StopFailure: "failed",
  SessionEnd: "ended",
};

const NOTIFICATION_STATE = {
  permission_prompt: "needs_input",
  elicitation_dialog: "needs_input",
  idle_prompt: "waiting",
};

const ATTENTION = new Set(["request.opened", "session.waiting", "session.failed"]);

const shortId = () => crypto.randomBytes(6).toString("base64url").replace(/[-_]/g, "x");

const within = (run, ms = TEXT_LIMIT_MS) => vm.runInNewContext("run()", { run }, { timeout: ms });

function look(text, limit) {
  const display = forDisplay(text, limit);
  return redact(text) === String(text ?? "") ? display : { ...display, warnings: [...display.warnings, REDACTED] };
}

// One thread serves every session, so text a session chose must not be able to stall it. Too slow to check for secrets
// means it is not shown at all, never that it is shown raw.
function shown(text, limit = 2000) {
  if (String(text ?? "").length < 1024) return look(text, limit);
  try {
    return within(() => look(text, limit));
  } catch {
    return { text: "⟦not shown: it took too long to check for secrets⟧", warnings: ["could not be shown"], truncated: true };
  }
}

const clip = (text, limit = 2000) => shown(text, limit).text;

// What a person reads before signing. Only an input with nothing but these fields gets the readable form. Anything else is
// JSON, so a session can't pick a harmless field to show and keep the real one out of sight. A Bash description and timeout
// change nothing that runs.
function summarizeInput(tool, input) {
  if (!input || typeof input !== "object") return "";
  const only = (...names) => Object.keys(input).every((field) => names.includes(field));
  if (tool === "Bash" && typeof input.command === "string" && only("command", "description", "timeout")) return input.command;
  if (tool === "Write" && typeof input.file_path === "string" && typeof input.content === "string" && only("file_path", "content")) return `${input.file_path}\n\n${input.content}`;
  if (tool === "ExitPlanMode" && typeof input.plan === "string" && only("plan")) return input.plan;
  return JSON.stringify(input, null, 1);
}

// JSON escapes control characters into plain text, so hidden characters are looked for in the values themselves.
function hiddenInFields(input) {
  const warnings = new Set();
  JSON.stringify(input ?? null, (key, value) => {
    for (const text of [key, value]) if (typeof text === "string") for (const warning of faithful(text).warnings) warnings.add(warning);
    return value;
  });
  return warnings;
}

// Keys the hashes in the audit log. A plain hash of a redacted input cracks with a wordlist.
function auditKey(file) {
  try {
    return fs.readFileSync(file);
  } catch {
    const key = crypto.randomBytes(32);
    fs.writeFileSync(file, key, { mode: 0o600 });
    return key;
  }
}

export function createBox({ paths, policy, agents = [], keys = [], pageUrl, onEvent = () => {}, now = () => Date.now() }) {
  const state = { policy, agents, keys };
  const sessions = new Map();
  const requests = new Map();
  const events = [];
  const audit = openAudit(paths.audit);
  const hashKey = auditKey(`${paths.audit}.key`);
  const inputHmac = (input) => crypto.createHmac("sha256", hashKey).update(JSON.stringify(input ?? null)).digest("hex");
  let seq = 0;

  function emit(type, fields) {
    const event = { seq: ++seq, at: new Date(now()).toISOString(), type, attention: ATTENTION.has(type), ...fields };
    events.push(event);
    if (events.length > MAX_EVENTS) events.shift();
    onEvent(event);
    return event;
  }

  const sessionName = (s) => (s?.cwd ? clip(path.basename(s.cwd), 120) : "unknown");

  function touchSession(id, fields) {
    fields.permission_mode = PERMISSION_MODES.has(fields.permission_mode) ? fields.permission_mode : undefined;
    fields.attended = typeof fields.attended === "boolean" ? fields.attended : undefined;
    fields.pid = Number.isInteger(fields.pid) ? fields.pid : undefined;
    let s = sessions.get(id);
    if (!s) {
      s = { session_id: id, state: "idle", started_at: new Date(now()).toISOString(), last_message: null };
      sessions.set(id, s);
      emit("session.started", { session_id: id, untrusted: { session: sessionName(fields) } });
    }
    Object.assign(s, fields);
    return s;
  }

  function setState(s, next, extra = {}) {
    if (s.state === next) return;
    s.state = next;
    const untrusted = { session: sessionName(s) };
    if (next === "waiting") emit("session.waiting", { session_id: s.session_id, untrusted: { ...untrusted, last_message: s.last_message }, ...extra });
    else if (next === "failed") emit("session.failed", { session_id: s.session_id, untrusted, ...extra });
    else if (next === "ended") emit("session.ended", { session_id: s.session_id, untrusted });
    else emit("session.state", { session_id: s.session_id, untrusted, state: next });
  }

  // Hook reports run as separate processes and can arrive out of order, so each carries the time it started.
  function report(input) {
    if (!SESSION_ID.test(input?.session_id ?? "")) return;
    const t = Number(input.t) || now();
    const s = touchSession(input.session_id, {
      cwd: input.cwd,
      permission_mode: input.permission_mode ?? sessions.get(input.session_id)?.permission_mode,
      pid: input.pid ?? sessions.get(input.session_id)?.pid,
      attended: input.attended ?? sessions.get(input.session_id)?.attended,
    });
    if (s.last_t && t < s.last_t) return;
    s.last_t = t;
    s.last_event_at = new Date(t).toISOString();
    const event = input.hook_event_name;
    if (event === "Stop" && input.last_assistant_message) s.last_message = clip(input.last_assistant_message);
    const next = event === "Notification" ? NOTIFICATION_STATE[input.notification_type] : SESSION_STATE[event];
    if (next) setState(s, next, event === "StopFailure" ? { error: clip(input.error_message ?? input.error ?? "", 300) } : {});
    if (event === "PostToolUse" || event === "PostToolUseFailure") closeAnsweredDialog(input);
  }

  // Claude Code leaves a PermissionRequest hook running after a keyboard yes, so the tool finishing is the only sign the
  // dialog is gone. This comes from the session, so it can only let go of a hold, leaving any dialog to the keyboard. An
  // answered question comes back with its answers added to the input, so a question matches on the tool alone.
  function closeAnsweredDialog({ session_id, tool_name, input_sha256 }) {
    const held = [...requests.values()].find((r) => r.dialog && r.status === "pending" && r.session_id === session_id && r.tool === tool_name && (r.kind === "question" || r.input_sha256 === input_sha256));
    if (held) settle(held, "cancelled", { type: "session", name: "the session reports it finished" }, { decision: "closed" });
  }

  function checkLiveness(isAlive) {
    for (const s of sessions.values()) if (s.state !== "ended" && s.pid && !isAlive(s.pid)) setState(s, "ended");
  }

  function questionsOf(input) {
    return (input?.questions ?? []).map((q) => ({
      question: clip(q.question, 500),
      header: clip(q.header, 60),
      multi_select: !!q.multiSelect,
      options: (q.options ?? []).map((o) => ({ label: clip(o.label, 120), description: clip(o.description, 300) })),
    }));
  }

  function refuseRequest({ session_id, tool, risk, input, onDecision }, name, reason) {
    audit.append({ session: session_id, tool, risk, input_hmac: inputHmac(input), decision: "denied", actor: { type: "system", name } });
    return onDecision({ decision: "deny", reason });
  }

  // A pass rule lets a flagged call run with nobody asked, so this is the only record that it did. A dialog that comes
  // after a passed call runs nothing by itself, so it asks without logging.
  function passRule({ session_id, tool, risk, name_only, input, dialog }) {
    if (risk === "catastrophic" || risk === "self") return { pass: false };
    let pass = false;
    if (tool !== "Bash") pass = name_only === true && matchesToolRule(tool, state.policy.trust_tools);
    else {
      try {
        pass = within(() => matchesPassRule(input?.command, state.policy.pass));
      } catch {}
    }
    if (pass && !dialog) audit.append({ session: session_id, tool, risk, input_hmac: inputHmac(input), decision: "passed", actor: { type: "hook", name: "a hook reported this, and it matched a pass rule" } });
    return { pass };
  }

  function openRequest({ session_id, cwd, kind, risk, why, warnings, tool, input, permission_mode, attended, dialog, pid, onDecision }) {
    if (!SESSION_ID.test(session_id ?? "") || !KINDS.has(kind) || !REQUEST_RISKS.has(risk) || !TOOL_NAME.test(tool ?? "")) return refuseRequest({ input, onDecision }, "a malformed request", "sayso: refused a malformed request, so it was not run.");
    const pending = [...requests.values()].filter((r) => r.status === "pending");
    const refused = { session_id, tool, risk, input, onDecision };
    if (pending.length >= MAX_PENDING) return refuseRequest(refused, "too many requests pending", "too many requests pending");
    if (pending.filter((r) => r.session_id === session_id).length >= MAX_PENDING_PER_SESSION) return refuseRequest(refused, "too many requests pending for this session", "too many requests pending for this session");
    const s = touchSession(session_id, { cwd, permission_mode, attended, pid });

    const hold = state.policy.hold_seconds;
    const created = now();
    const display = shown(summarizeInput(tool, input));
    const raised = Array.isArray(warnings) ? warnings.map((w) => clip(w, 200)) : [];
    display.warnings = [...new Set([...display.warnings, ...hiddenInFields(input), ...raised])];
    const request = {
      id: `r_${shortId()}`,
      nonce: crypto.randomBytes(9).toString("base64url"),
      session_id,
      session: sessionName(s),
      cwd,
      kind,
      dialog: !!dialog,
      risk,
      why: Array.isArray(why) ? why.map((w) => clip(w, 300)) : [],
      tool,
      display,
      questions: kind === "question" ? questionsOf(input) : undefined,
      raw_input: input,
      // Only to match the session's own report of this call. It never leaves the daemon, so it needs no key.
      input_sha256: crypto.createHash("sha256").update(JSON.stringify(input ?? null)).digest("hex"),
      input_hmac: inputHmac(input),
      approver: kind === "question" ? "agent" : (state.policy.approver[risk] ?? "human"),
      status: "pending",
      created_at: new Date(created).toISOString(),
      expires_at: new Date(created + hold * 1000).toISOString(),
      expires_ms: created + hold * 1000,
      bad_signatures: 0,
      onDecision,
    };
    if (display.truncated || (kind !== "question" && display.warnings.length)) request.approver = "human";
    // A signature says the person read this. Past these two they could not have, and a signature would release the full input.
    request.unread = kind !== "question" && (display.truncated || HIDES_ANYTHING.test(display.text));

    // Nobody registered, nobody to ask. A headless run should find out now, not after the full hold.
    if (!state.agents.length && !attended) {
      return refuseRequest(refused, "no agent registered", "sayso: this needs an answer and no agent is connected, so it was not run.");
    }

    request.doc = encodeDoc({
      v: 1,
      id: request.id,
      nonce: request.nonce,
      session: request.session,
      cwd: clip(cwd ?? "", 300),
      tool,
      kind,
      risk,
      why: request.why,
      display: display.text,
      warnings: display.warnings,
      expires_at: request.expires_at,
      ...(request.unread ? { unread: true } : {}),
    });
    requests.set(request.id, request);
    if (s.state !== "ended") setState(s, "needs_input");
    audit.append({ request: request.id, session: session_id, tool, risk, approver: request.approver, input_hmac: request.input_hmac, decision: "opened" });
    emit("request.opened", { session_id, request_id: request.id, kind, risk, approver: request.approver, tool, untrusted: untrustedOf(request) });
    return request;
  }

  const untrustedOf = (r) => ({ session: r.session, action: r.display.text, questions: r.questions, why: r.why, warnings: r.display.warnings });

  function approvalUrl(r) {
    return `${pageUrl}#r=${r.doc}`;
  }

  function view(r) {
    return {
      id: r.id,
      session_id: r.session_id,
      kind: r.kind,
      risk: r.risk,
      tool: r.tool,
      approver: r.approver,
      status: r.status,
      created_at: r.created_at,
      expires_at: r.expires_at,
      decided_by: r.decided_by,
      untrusted: untrustedOf(r),
      ...(r.status === "pending" && r.approver === "human" && !r.unread ? { approval_url: approvalUrl(r) } : {}),
    };
  }

  function settle(r, status, actor, decision, extra = {}) {
    r.status = status;
    r.decided_by = actor;
    r.decided_at = new Date(now()).toISOString();
    audit.append({ request: r.id, session: r.session_id, tool: r.tool, risk: r.risk, input_hmac: r.input_hmac, decision: status, actor, ...extra });
    r.onDecision?.(decision);
    delete r.raw_input;
    const s = sessions.get(r.session_id);
    if (s && s.state === "needs_input" && ![...requests.values()].some((o) => o.session_id === r.session_id && o.status === "pending")) setState(s, "working");
    emit("request.resolved", { session_id: r.session_id, untrusted: { session: r.session }, request_id: r.id, status, decided_by: actor });
  }

  function pendingRequest(id) {
    const r = requests.get(id);
    if (!r) return { error: { status: "not_found", message: "no such request" } };
    if (r.status !== "pending") return { error: { status: "already_decided", message: `already ${r.status}`, request: view(r) } };
    if (now() >= r.expires_ms) {
      settle(r, "expired", { type: "system", name: "timeout" }, { decision: "deny", reason: "sayso: no answer in time, so it was not run." });
      return { error: { status: "expired", message: "this request expired and was denied" } };
    }
    return { request: r };
  }

  function deny(id, actor, reason) {
    const { request: r, error } = pendingRequest(id);
    if (error) return error;
    // The session's model reads this. Under a policy with messages off, an injected agent must not be able to speak to it here.
    const said = reason && state.policy.messages ? ` (${clip(reason, 200)})` : "";
    settle(r, "denied", actor, { decision: "deny", reason: `sayso: denied by ${actor.name}${said}. Do not try an equivalent command. Tell the user what you wanted to do.` }, reason ? { reason: clip(reason, 200) } : {});
    return { status: "denied", request: view(r) };
  }

  function approve(id, actor, signature) {
    const { request: r, error } = pendingRequest(id);
    if (error) return error;
    if (r.kind === "question") return { status: "refused", message: "this is a question: use answer_question" };
    if (r.unread) return { status: "refused", message: "Part of this can't be shown to the person, so it can't be approved from their device. Deny it, or they can answer at the session's terminal. A shorter command with no secret written in it can be approved." };

    if (signature) {
      const check = verifyApproval(r.doc, signature, state.keys);
      if (!check.ok) {
        r.bad_signatures++;
        audit.append({ request: r.id, session: r.session_id, decision: "bad_signature", actor, why: check.why });
        if (r.bad_signatures >= MAX_BAD_SIGNATURES) {
          settle(r, "denied", { type: "system", name: "too many bad signatures" }, { decision: "deny", reason: "sayso: too many invalid approvals, so it was not run." });
          return { status: "denied", message: "too many invalid signatures: the request was denied" };
        }
        return { status: "refused", message: `signature rejected: ${check.why}`, attempts_left: MAX_BAD_SIGNATURES - r.bad_signatures };
      }
      const human = { type: "human", name: check.key_name ?? "paired device", key_id: check.key_id, via: actor.name };
      settle(r, "approved", human, { decision: "allow", reason: `sayso: approved on ${human.name}.` });
      return { status: "approved", approved_by: human, request: view(r) };
    }

    if (r.approver === "agent") {
      settle(r, "approved", actor, { decision: "allow", reason: `sayso: approved by agent ${actor.name}.` });
      return { status: "approved", approved_by: actor, request: view(r) };
    }

    audit.append({ request: r.id, session: r.session_id, decision: "agent_cannot_approve", actor });
    if (!state.keys.length)
      return { status: "needs_human", message: "Only the person can approve this and no device is paired. They should run `sayso pair` in their own terminal. Until then it stays held and then is denied." };
    return {
      status: "needs_human",
      approval_url: approvalUrl(r),
      expires_at: r.expires_at,
      message:
        "Only the person can approve this. Send them approval_url unchanged. They read the exact request on their own device, and if they approve it gives them a code. Pass that code back to approve as signature. Changing the link makes the code useless.",
    };
  }

  function answerQuestion(id, actor, answers) {
    const { request: r, error } = pendingRequest(id);
    if (error) return error;
    if (r.kind !== "question") return { status: "refused", message: "this is not a question" };
    if (state.policy.questions === "off") return { status: "refused", message: "the policy does not let agents answer questions" };
    if (!answers || typeof answers !== "object") return { status: "refused", message: "answers must map each question to an answer" };
    const original = r.raw_input?.questions ?? [];
    const out = {};
    for (const q of original) {
      const given = answers[q.question];
      if (typeof given !== "string" || !given) return { status: "refused", message: `missing an answer for: ${clip(q.question, 120)}` };
      const labels = (q.options ?? []).map((o) => o.label);
      const picks = q.multiSelect ? given.split(",").map((x) => x.trim()) : [given];
      const allOffered = picks.every((p) => labels.includes(p));
      if (!allOffered && state.policy.questions !== "free_text")
        return { status: "refused", message: `the policy allows only the offered options: ${labels.join(", ")}` };
      out[q.question] = given.slice(0, 1000);
    }
    settle(r, "answered", actor, { decision: "answer", updatedInput: { ...r.raw_input, answers: out } }, { answers_sha256: crypto.createHash("sha256").update(JSON.stringify(out)).digest("hex") });
    return { status: "answered", request: view(r) };
  }

  function expire(id) {
    const r = requests.get(id);
    if (r?.status === "pending") settle(r, "expired", { type: "system", name: "timeout" }, { decision: "deny", reason: "sayso: no answer in time, so it was not run. Tell the user what you wanted to do." });
  }

  // The hook's connection died: the session was interrupted, exited or crashed. Nothing is waiting for an answer now.
  function cancel(id) {
    const r = requests.get(id);
    if (r?.status === "pending") {
      r.onDecision = null;
      settle(r, "cancelled", { type: "system", name: "the hook's connection closed with no answer" }, null);
    }
  }

  function sweep() {
    const t = now();
    for (const r of requests.values()) if (r.status === "pending" && t >= r.expires_ms) expire(r.id);
    if (requests.size > 500) for (const [id, r] of requests) if (r.status !== "pending" && requests.size > 500) requests.delete(id);
  }

  return {
    report,
    passRule,
    openRequest,
    deny,
    approve,
    answerQuestion,
    expire,
    cancel,
    sweep,
    checkLiveness,
    audit,
    emit,
    setConfig(next) {
      Object.assign(state, next);
    },
    get policy() {
      return state.policy;
    },
    get keys() {
      return state.keys;
    },
    get agents() {
      return state.agents;
    },
    get seq() {
      return seq;
    },
    session: (id) => sessions.get(id),
    listSessions: (includeEnded = false) =>
      [...sessions.values()]
        .filter((s) => includeEnded || s.state !== "ended")
        .map((s) => ({
          session_id: s.session_id,
          state: s.state,
          permission_mode: s.permission_mode,
          attended: s.attended,
          started_at: s.started_at,
          last_event_at: s.last_event_at,
          pending_requests: [...requests.values()].filter((r) => r.session_id === s.session_id && r.status === "pending").map((r) => r.id),
          untrusted: { name: sessionName(s), cwd: clip(s.cwd ?? "", 300), last_message: s.last_message },
        })),
    listRequests: (status = "pending") => [...requests.values()].filter((r) => status === "all" || r.status === status).map(view),
    getRequest: (id) => {
      const r = requests.get(id);
      return r ? view(r) : null;
    },
    eventsSince: (cursor, onlyAttention = true) => events.filter((e) => e.seq > cursor && (!onlyAttention || e.attention || e.type === "request.resolved")),
  };
}
