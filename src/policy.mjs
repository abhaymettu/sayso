import fs from "node:fs";
import { MAX_HOLD_SECONDS } from "./paths.mjs";

export const RISKS = ["catastrophic", "self", "credentials", "destructive", "outward", "opaque", "prompt", "plan"];

// Who may say yes to each kind of request. "human" means a signature from the person's own device, which the agent
// can carry but cannot make. Saying no is always open to any authenticated agent.
export const PRESETS = {
  strict: {
    approver: { catastrophic: "human", self: "human", credentials: "human", destructive: "human", outward: "human", opaque: "human", prompt: "human", plan: "human" },
    questions: "options",
    messages: false,
    hold_seconds: 900,
    pass: [],
    trust_tools: [],
  },
  "trusted-agent": {
    approver: { catastrophic: "human", self: "human", credentials: "human", destructive: "agent", outward: "agent", opaque: "agent", prompt: "agent", plan: "agent" },
    questions: "free_text",
    messages: true,
    hold_seconds: 900,
    pass: [],
    trust_tools: [],
  },
};

// These stay with the human whatever the file says. Wiping a disk or disarming the gate is never an agent's call.
const FLOORS = ["catastrophic", "self"];

export function normalizePolicy(raw) {
  const base = PRESETS[raw?.preset] ?? PRESETS.strict;
  const notes = [];
  const approver = { ...base.approver };
  for (const risk of RISKS) {
    const wanted = raw?.approver?.[risk];
    if (wanted === undefined) continue;
    if (wanted !== "human" && wanted !== "agent") notes.push(`approver.${risk}: "${wanted}" is not valid, kept ${approver[risk]}`);
    else if (wanted === "agent" && FLOORS.includes(risk)) notes.push(`approver.${risk}: stays human, it cannot be lowered`);
    else approver[risk] = wanted;
  }
  const questions = ["options", "free_text", "off"].includes(raw?.questions) ? raw.questions : base.questions;
  const hold = Number.isFinite(raw?.hold_seconds) ? raw.hold_seconds : base.hold_seconds;
  const hold_seconds = Math.max(5, Math.min(hold, MAX_HOLD_SECONDS));
  if (hold !== hold_seconds) notes.push(`hold_seconds: clamped to ${hold_seconds}`);
  return {
    preset: PRESETS[raw?.preset] ? raw.preset : "strict",
    approver,
    questions,
    messages: raw?.messages === undefined ? base.messages : raw.messages === true,
    hold_seconds,
    pass: Array.isArray(raw?.pass) ? raw.pass.filter((p) => typeof p === "string") : base.pass,
    trust_tools: Array.isArray(raw?.trust_tools) ? raw.trust_tools.filter((t) => typeof t === "string" && t.startsWith("mcp__") && t.length > 5) : base.trust_tools,
    notes,
  };
}

// A malformed file falls back to strict and says so; it never loosens anything.
export function loadPolicy(file) {
  try {
    return normalizePolicy(JSON.parse(fs.readFileSync(file, "utf8")));
  } catch (error) {
    const policy = normalizePolicy({});
    if (error.code !== "ENOENT") policy.notes.push(`policy file unreadable, using strict: ${error.message}`);
    return policy;
  }
}

// A pass rule applies only to a command with no shell control characters, so `rm -rf cache; rm -rf ~` can never
// ride in on a rule written for `rm -rf cache`.
// Drops only what a tool's name alone raised. Sayso's own send_message is always trusted, since the policy already decides it.
export function matchesToolRule(tool, rules) {
  if (tool === "mcp__sayso__send_message") return true;
  return rules.some((rule) => (rule.endsWith("*") ? tool.startsWith(rule.slice(0, -1)) : tool === rule));
}

export function matchesPassRule(command, rules) {
  if (typeof command !== "string" || /[;&|`$()<>\n\\]/.test(command)) return false;
  return rules.some((rule) => {
    try {
      return new RegExp(`^(?:${rule})$`).test(command);
    } catch {
      return false;
    }
  });
}
