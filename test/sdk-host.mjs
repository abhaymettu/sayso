#!/usr/bin/env node
// A session hosted through the Claude Agent SDK, the way a desktop app or an orchestrator runs Claude Code. An SDK host's
// canUseTool can say yes to everything, so these check that the gate does not leave the decision to the host.
// Run: npm run test:sdk
import assert from "node:assert/strict";
import { Rig, CLAUDE, sleep, waitUntil } from "./harness/rig.mjs";
import { apiKeyEnv } from "./harness/tui.mjs";

const { query } = await import("@anthropic-ai/claude-agent-sdk");
const RM = { tool: "Bash", input: { command: "rm -rf victim", description: "delete" } };
const QUESTION = { question: "Which colour?", header: "Colour", options: [{ label: "Red", description: "warm" }, { label: "Blue", description: "cool" }], multiSelect: false };
const say = (line) => console.log(line);

async function host(rig, { permissionMode, seen = [], hostAnswersAfter = 0 }) {
  const stream = query({
    prompt: "go",
    options: {
      cwd: rig.cwd,
      model: "claude-scripted",
      pathToClaudeCodeExecutable: CLAUDE,
      env: apiKeyEnv(rig, rig.scripted.url, rig.env()),
      settingSources: ["user"],
      permissionMode,
      allowDangerouslySkipPermissions: permissionMode === "bypassPermissions",
      canUseTool: async (name, input, options) => {
        seen.push(name);
        if (name === "AskUserQuestion") {
          await new Promise((resolve) => {
            const timer = setTimeout(resolve, hostAnswersAfter);
            options?.signal?.addEventListener("abort", () => {
              clearTimeout(timer);
              resolve();
            });
          });
          return { behavior: "allow", updatedInput: { ...input, answers: { [QUESTION.question]: "Red" } } };
        }
        return { behavior: "allow", updatedInput: input };
      },
    },
  });
  for await (const _ of stream);
  return seen;
}

async function scenario(name, plan, body) {
  const rig = new Rig("sdk");
  try {
    await rig.install();
    await rig.model(plan);
    await body(rig);
    say(`ok  ${name}`);
  } finally {
    await rig.close();
  }
}

await scenario("bypass mode: an rm -rf is held, a plain yes is refused, a signature runs it", [RM, { text: "finished" }], async (rig) => {
  const session = host(rig, { permissionMode: "bypassPermissions" });
  const request = await rig.nextRequest(30000);
  assert.equal(rig.destroyed(), false);
  const plain = await rig.tool("approve", { request_id: request.id });
  assert.equal(plain.status, "needs_human");
  await sleep(300);
  assert.equal(rig.destroyed(), false);
  await rig.tool("approve", { request_id: request.id, signature: rig.signFor(plain) });
  await session;
  assert.equal(rig.destroyed(), true);
});

await scenario("default mode: a host that allows everything does not get to allow this", [RM, { text: "finished" }], async (rig) => {
  const seen = [];
  const session = host(rig, { permissionMode: "default", seen });
  const request = await rig.nextRequest(30000);
  await sleep(1500);
  assert.equal(rig.destroyed(), false, "the host's canUseTool ran the command while the gate held it");
  await rig.tool("deny", { request_id: request.id });
  await session;
  assert.equal(rig.destroyed(), false);
  say(`    the host's canUseTool saw: ${seen.join(", ") || "nothing"}`);
});

const ASK = [{ tool: "AskUserQuestion", input: { questions: [QUESTION] } }, { text: "finished" }];

await scenario("a question, with the host waiting on its person: the agent's answer wins", ASK, async (rig) => {
  const session = host(rig, { permissionMode: "default", hostAnswersAfter: 60000 });
  const request = await rig.nextRequest(20000);
  assert.equal(request.kind, "question");
  await rig.tool("answer_question", { request_id: request.id, answers: { [QUESTION.question]: "Blue" } });
  await session;
  assert.match(rig.scripted.seen.toolResults[0], /"Which colour\?"="Blue"/);
});

await scenario("a question the host's person answers first: the request closes, and the agent is not left holding it", ASK, async (rig) => {
  const session = host(rig, { permissionMode: "default", hostAnswersAfter: 0 });
  await session;
  assert.match(rig.scripted.seen.toolResults[0], /"Which colour\?"="Red"/);
  await waitUntil(async () => (await rig.tool("list_requests")).requests.length === 0, 10000, "the question to close");
});
process.exit(0);
