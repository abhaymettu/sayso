// The daemon's state and every rule about who may decide what. No sockets here, so each rule is testable directly.
import crypto from "node:crypto";
import path from "node:path";
import { openAudit } from "./audit.mjs";
import { forDisplay, redact } from "./redact.mjs";
import { encodeDoc, verifyApproval } from "./sign.mjs";

/** @typedef {"pending"|"approved"|"denied"|"answered"|"expired"|"cancelled"} RequestStatus */
/** @typedef {{type: "agent"|"human"|"owner"|"system", name: string, key_id?: string, via?: string}} Actor */

const MAX_BAD_SIGNATURES = 3;
const MAX_EVENTS = 2000;
const MAX_PENDING_PER_SESSION = 8;

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
const clip = (text, limit = 2000) => forDisplay(text, limit).text;

// Which simple field of a tool call a person should read to know what it does.
function summarizeInput(tool, input) {
  if (!input || typeof input !== "object") return "";
  if (typeof input.command === "string") return input.command;
  if (typeof input.file_path === "string") {
    if (typeof input.content === "string") return `${input.file_path}\n\n${input.content}`;
    if (typeof input.new_string === "string") return `${input.file_path}\n\nreplace:\n${input.old_string}\n\nwith:\n${input.new_string}`;
    return input.edits ? `${input.file_path}\n\n${JSON.stringify(input.edits)}` : input.file_path;
  }
  if (typeof input.notebook_path === "string") return `${input.notebook_path}\n\n${input.new_source ?? ""}`.trimEnd();
  if (typeof input.plan === "string") return input.plan;
  if (typeof input.url === "string") return input.url;
  return JSON.stringify(input);
}

export function createBox({ paths, policy, agents = [], keys = [], pageUrl, onEvent = () => {}, now = () => Date.now() }) {
  const state = { policy, agents, keys };
  const sessions = new Map();
  const requests = new Map();
  const events = [];
  const audit = openAudit(paths.audit);
  let seq = 0;

  function emit(type, fields) {
    const event = { seq: ++seq, at: new Date(now()).toISOString(), type, attention: ATTENTION.has(type), ...fields };
    events.push(event);
    if (events.length > MAX_EVENTS) events.shift();
    onEvent(event);
    return event;
  }

  const sessionName = (s) => (s?.cwd ? path.basename(s.cwd) : "unknown");

  function touchSession(id, fields) {
    let s = sessions.get(id);
    if (!s) {
      s = { session_id: id, state: "idle", started_at: new Date(now()).toISOString(), last_message: null };
      sessions.set(id, s);
      emit("session.started", { session_id: id, session: sessionName(fields) });
    }
    Object.assign(s, fields);
    return s;
  }

  function setState(s, next, extra = {}) {
    if (s.state === next) return;
    s.state = next;
    if (next === "waiting") emit("session.waiting", { session_id: s.session_id, session: sessionName(s), untrusted: { last_message: s.last_message }, ...extra });
    else if (next === "failed") emit("session.failed", { session_id: s.session_id, session: sessionName(s), ...extra });
    else if (next === "ended") emit("session.ended", { session_id: s.session_id, session: sessionName(s) });
    else emit("session.state", { session_id: s.session_id, session: sessionName(s), state: next });
  }

  // Hook reports run as separate processes and can arrive out of order, so each carries the time it started.
  function report(input) {
    if (!input?.session_id) return;
    const t = Number(input.t) || now();
    const s = touchSession(input.session_id, {
      cwd: input.cwd,
      permission_mode: input.permission_mode ?? sessions.get(input.session_id)?.permission_mode,
      pid: input.pid ?? sessions.get(input.session_id)?.pid,
      attended: input.attended ?? sessions.get(input.session_id)?.attended,
      entrypoint: input.entrypoint ?? sessions.get(input.session_id)?.entrypoint,
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
    if (held) settle(held, "cancelled", { type: "session", name: "answered at the terminal" }, { decision: "closed" });
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

  function openRequest({ session_id, cwd, kind, risk, why, tool, input, permission_mode, attended, dialog, pid, entrypoint, onDecision }) {
    const s = touchSession(session_id, { cwd, permission_mode, attended, pid, entrypoint });
    const pendingHere = [...requests.values()].filter((r) => r.session_id === session_id && r.status === "pending").length;
    if (pendingHere >= MAX_PENDING_PER_SESSION) return onDecision({ decision: "deny", reason: "too many requests pending for this session" });

    const hold = state.policy.hold_seconds;
    const created = now();
    const display = forDisplay(summarizeInput(tool, input));
    const request = {
      id: `r_${shortId()}`,
      nonce: crypto.randomBytes(9).toString("base64url"),
      session_id,
      session: sessionName(s),
      cwd,
      kind,
      dialog: !!dialog,
      risk,
      why: why ?? [],
      tool,
      display,
      questions: kind === "question" ? questionsOf(input) : undefined,
      raw_input: input,
      input_sha256: crypto.createHash("sha256").update(JSON.stringify(input ?? null)).digest("hex"),
      approver: kind === "question" ? "agent" : (state.policy.approver[risk] ?? "human"),
      status: "pending",
      created_at: new Date(created).toISOString(),
      expires_at: new Date(created + hold * 1000).toISOString(),
      expires_ms: created + hold * 1000,
      bad_signatures: 0,
      onDecision,
    };
    if (display.truncated || (request.risk !== "prompt" && kind !== "question" && display.warnings.length)) request.approver = "human";

    // Nobody registered, nobody to ask. A headless run should find out now, not after the full hold.
    if (!state.agents.length && !attended) {
      audit.append({ request: request.id, session: session_id, tool, risk, input_sha256: request.input_sha256, decision: "denied", actor: { type: "system", name: "no agent registered" } });
      return onDecision({ decision: "deny", reason: "sayso: this needs an answer and no agent is connected, so it was not run." });
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
      input_sha256: request.input_sha256,
    });
    requests.set(request.id, request);
    if (s.state !== "ended") setState(s, "needs_input");
    audit.append({ request: request.id, session: session_id, tool, risk, approver: request.approver, input_sha256: request.input_sha256, decision: "opened" });
    emit("request.opened", { session_id, session: request.session, request_id: request.id, kind, risk, approver: request.approver, tool, untrusted: untrustedOf(request) });
    return request;
  }

  const untrustedOf = (r) => ({ action: r.display.text, questions: r.questions, why: r.why, warnings: r.display.warnings });

  function approvalUrl(r) {
    return `${pageUrl}#r=${r.doc}`;
  }

  function view(r) {
    return {
      id: r.id,
      session_id: r.session_id,
      session: r.session,
      kind: r.kind,
      risk: r.risk,
      tool: r.tool,
      approver: r.approver,
      status: r.status,
      created_at: r.created_at,
      expires_at: r.expires_at,
      decided_by: r.decided_by,
      untrusted: untrustedOf(r),
      ...(r.status === "pending" && r.approver === "human" ? { approval_url: approvalUrl(r) } : {}),
    };
  }

  function settle(r, status, actor, decision, extra = {}) {
    r.status = status;
    r.decided_by = actor;
    r.decided_at = new Date(now()).toISOString();
    audit.append({ request: r.id, session: r.session_id, tool: r.tool, risk: r.risk, input_sha256: r.input_sha256, decision: status, actor, ...extra });
    r.onDecision?.(decision);
    delete r.raw_input;
    const s = sessions.get(r.session_id);
    if (s && s.state === "needs_input" && ![...requests.values()].some((o) => o.session_id === r.session_id && o.status === "pending")) setState(s, "working");
    emit("request.resolved", { session_id: r.session_id, session: r.session, request_id: r.id, status, decided_by: actor });
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
    settle(r, "denied", actor, { decision: "deny", reason: `sayso: denied by ${actor.name}${said}. Do not try an equivalent command. Tell the user what you wanted to do.` }, reason ? { reason: redact(reason).slice(0, 200) } : {});
    return { status: "denied", request: view(r) };
  }

  function approve(id, actor, signature) {
    const { request: r, error } = pendingRequest(id);
    if (error) return error;
    if (r.kind === "question") return { status: "refused", message: "this is a question: use answer_question" };

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
      settle(r, "cancelled", { type: "system", name: "session stopped waiting" }, null);
    }
  }

  function sweep() {
    const t = now();
    for (const r of requests.values()) if (r.status === "pending" && t >= r.expires_ms) expire(r.id);
    if (requests.size > 500) for (const [id, r] of requests) if (r.status !== "pending" && requests.size > 500) requests.delete(id);
  }

  return {
    report,
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
          name: sessionName(s),
          cwd: s.cwd,
          state: s.state,
          permission_mode: s.permission_mode,
          attended: s.attended,
          started_at: s.started_at,
          last_event_at: s.last_event_at,
          pending_requests: [...requests.values()].filter((r) => r.session_id === s.session_id && r.status === "pending").map((r) => r.id),
          untrusted: { last_message: s.last_message },
        })),
    listRequests: (status = "pending") => [...requests.values()].filter((r) => status === "all" || r.status === status).map(view),
    getRequest: (id) => {
      const r = requests.get(id);
      return r ? view(r) : null;
    },
    eventsSince: (cursor, onlyAttention = true) => events.filter((e) => e.seq > cursor && (!onlyAttention || e.attention || e.type === "request.resolved")),
  };
}
