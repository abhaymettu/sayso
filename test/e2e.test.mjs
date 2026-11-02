// Drives the real Claude Code binary through a real install. The model is scripted, everything else is the product.
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { describe, test } from "node:test";
import { Rig, sleep, waitUntil } from "./harness/rig.mjs";

const RM = { tool: "Bash", input: { command: "rm -rf victim", description: "delete the folder" } };
const FINISH = { text: "finished" };

async function withRig(options, plan, body) {
  const rig = new Rig();
  try {
    await rig.install(options);
    await rig.model(plan);
    await body(rig);
  } finally {
    await rig.close();
  }
}

describe("bypass mode, headless", () => {
  test("rm -rf is held, stays held through an agent's yes, and runs only on a device signature", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      const request = await rig.nextRequest();
      assert.equal(request.risk, "destructive");
      assert.equal(request.approver, "human");
      assert.equal(request.tool, "Bash");
      assert.match(request.untrusted.action, /rm -rf victim/);

      const refused = await rig.tool("approve", { request_id: request.id });
      assert.equal(refused.status, "needs_human");
      await sleep(300);
      assert.equal(rig.destroyed(), false, "an agent's yes must not release a human request");
      assert.equal(session.exitCode, null, "the session is still waiting");

      const approved = await rig.tool("approve", { request_id: request.id, signature: rig.signFor(refused) });
      assert.equal(approved.status, "approved");
      assert.equal(approved.approved_by.type, "human");
      assert.equal((await session.done).code, 0);
      assert.equal(rig.destroyed(), true);
      const last = rig.audit().at(-1);
      assert.equal(last.decision, "approved");
      assert.equal(last.actor.type, "human");
      assert.equal(last.actor.via, "test-agent");
    }));

  test("deny stops it and the session is told", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      const request = await rig.nextRequest();
      assert.equal((await rig.tool("deny", { request_id: request.id, reason: "not today" })).status, "denied");
      await session.done;
      assert.equal(rig.destroyed(), false);
      assert.match(rig.scripted.seen.toolResults[0], /denied by test-agent \(not today\)/);
    }));

  test("no answer means no", () =>
    withRig({ policy: { hold_seconds: 5 } }, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      await rig.nextRequest();
      await session.done;
      assert.equal(rig.destroyed(), false);
      assert.match(rig.scripted.seen.toolResults[0], /no answer in time/);
      assert.equal(rig.audit().at(-1).decision, "expired");
    }));

  test("the daemon dying during a hold denies", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      await rig.nextRequest();
      process.kill(rig.daemonPid(), "SIGKILL");
      await session.done;
      assert.equal(rig.destroyed(), false);
      assert.match(rig.scripted.seen.toolResults[0], /blocked because/);
    }));

  test("a daemon that cannot start denies", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      await rig.askDaemon({ op: "shutdown" });
      await sleep(100);
      fs.writeFileSync(path.join(rig.home, "config.json"), JSON.stringify({ port: "not a port" }));
      const blocker = http.createServer().listen(rig.port, "127.0.0.1");
      const session = rig.headless();
      await session.done;
      blocker.close();
      assert.equal(rig.destroyed(), false);
      assert.match(rig.scripted.seen.toolResults[0], /blocked because/);
    }));

  test("a runtime that fails blocks instead of letting the tool run", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const broken = path.join(rig.root, "broken-node");
      fs.writeFileSync(broken, "#!/bin/sh\nexit 127\n", { mode: 0o755 });
      const file = path.join(rig.config, "settings.json");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replaceAll(process.execPath, broken));
      const session = rig.headless();
      await session.done;
      assert.equal(rig.destroyed(), false);
      assert.match(rig.scripted.seen.toolResults[0], /gate failed/);
    }));

  test("killing the gate process mid-hold blocks", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      await rig.nextRequest();
      const { spawnSync } = await import("node:child_process");
      spawnSync("pkill", ["-9", "-f", `${rig.home}/app/src/hook.mjs gate`]);
      const killedAny = spawnSync("pgrep", ["-f", `${rig.home}/app/src/hook.mjs gate`]).status !== 0;
      assert.equal(killedAny, true);
      await session.done;
      assert.equal(rig.destroyed(), false);
    }));

  test("ordinary commands pass with no request, and a rebuildable folder is not flagged", () =>
    withRig(
      {},
      [
        { tool: "Bash", input: { command: "ls -la", description: "list" } },
        { tool: "Bash", input: { command: "mkdir -p node_modules/x && rm -rf node_modules", description: "clean" } },
        { tool: "Bash", input: { command: "git status || true", description: "status" } },
        FINISH,
      ],
      async (rig) => {
        const session = rig.headless();
        assert.equal((await session.done).code, 0);
        assert.equal((await rig.tool("list_requests", { status: "all" })).requests.length, 0);
        assert.equal(rig.scripted.seen.toolResults.length, 3);
      },
    ));

  test("a flagged call and a safe call in the same turn are decided separately", () =>
    withRig({}, [{ parallel: [RM, { tool: "Bash", input: { command: "echo safe > safe.txt", description: "safe" } }] }, FINISH], async (rig) => {
      const session = rig.headless();
      const request = await rig.nextRequest();
      await rig.tool("deny", { request_id: request.id });
      await session.done;
      assert.equal(rig.destroyed(), false);
      assert.equal(fs.existsSync(path.join(rig.cwd, "safe.txt")), true);
    }));

  test("a subagent's rm -rf is held too", () =>
    withRig(
      {},
      (messages) => {
        const first = JSON.stringify(messages[0]?.content ?? "");
        const results = messages.reduce((n, m) => n + (Array.isArray(m.content) ? m.content.filter((c) => c.type === "tool_result").length : 0), 0);
        if (first.includes("SUBAGENT-TASK")) return results === 0 ? RM : FINISH;
        return results === 0 ? { tool: "Agent", input: { description: "clean", prompt: "SUBAGENT-TASK delete the folder", subagent_type: "general-purpose" } } : FINISH;
      },
      async (rig) => {
        const session = rig.headless();
        const request = await rig.nextRequest();
        assert.match(request.untrusted.action, /rm -rf victim/);
        assert.equal(rig.destroyed(), false);
        await rig.tool("deny", { request_id: request.id });
        await session.done;
        assert.equal(rig.destroyed(), false);
      },
    ));

  test("with no agent registered a headless run is told at once", () =>
    withRig({ agent: null }, [RM, FINISH], async (rig) => {
      const start = Date.now();
      const session = rig.headless();
      await session.done;
      assert.equal(rig.destroyed(), false);
      assert.ok(Date.now() - start < 15000);
      assert.match(rig.scripted.seen.toolResults[0], /no agent is connected/);
    }));
});

describe("permission modes", () => {
  for (const mode of ["default", "acceptEdits", "plan", "dontAsk", "bypassPermissions"]) {
    test(`${mode}: the gate holds rm -rf`, () =>
      withRig({}, [RM, FINISH], async (rig) => {
        const session = rig.headless({ mode });
        const request = await rig.nextRequest();
        assert.equal(request.risk, "destructive");
        assert.equal(rig.destroyed(), false);
        await rig.tool("deny", { request_id: request.id });
        await session.done;
        assert.equal(rig.destroyed(), false);
      }));
  }
});

describe("the terminal", () => {
  const start = async (rig, args) => {
    const t = rig.tui(args);
    await t.waitFor(/bypass permissions|manual mode|auto mode|shortcuts/, 15000);
    await sleep(800);
    t.type("go");
    t.keys("Enter");
    return t;
  };

  test("bypass: the real dialog appears and a remote deny closes it", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Do you want to proceed/);
      const request = await rig.nextRequest();
      assert.equal(request.risk, "destructive");
      await rig.tool("deny", { request_id: request.id });
      await t.waitFor(/finished/);
      assert.equal(rig.destroyed(), false);
    }));

  test("bypass: a remote device signature closes the dialog and runs it", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Do you want to proceed/);
      const request = await rig.nextRequest();
      const needs = await rig.tool("approve", { request_id: request.id });
      assert.equal(needs.status, "needs_human");
      await rig.tool("approve", { request_id: request.id, signature: rig.signFor(needs) });
      await t.waitFor(/finished/);
      assert.equal(rig.destroyed(), true);
    }));

  test("bypass: the person at the keyboard can answer instead", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Do you want to proceed/);
      t.keys("Enter");
      await t.waitFor(/finished/);
      assert.equal(rig.destroyed(), true);
      const request = await waitUntil(async () => (await rig.tool("list_requests", { status: "all" })).requests.find((r) => r.status === "cancelled"), 5000, "the hold to be cancelled");
      assert.deepEqual(request.decided_by, { type: "session", name: "answered at the terminal" });
    }));

  test("bypass: a keyboard no runs nothing and ends the hold", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Do you want to proceed/);
      await rig.nextRequest();
      t.keys("Down", "Enter");
      await waitUntil(async () => (await rig.tool("list_requests", { status: "all" })).requests.find((r) => r.status === "cancelled"), 5000, "the hold to be cancelled");
      assert.equal(rig.destroyed(), false);
    }));

  test("bypass: no answer closes the dialog with a no", () =>
    withRig({ policy: { hold_seconds: 5 } }, [RM, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Do you want to proceed/);
      await t.waitFor(/finished/, 15000);
      assert.equal(rig.destroyed(), false);
      assert.match(rig.scripted.seen.toolResults[0], /no answer in time/);
    }));

  test("a question: an agent can pick an offered option, not make one up", () => {
    const question = { question: "Which colour?", header: "Colour", options: [{ label: "Red", description: "warm" }, { label: "Blue", description: "cool" }], multiSelect: false };
    return withRig({}, [{ tool: "AskUserQuestion", input: { questions: [question] } }, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Which colour/);
      const request = await rig.nextRequest();
      assert.equal(request.kind, "question");
      const invented = await rig.tool("answer_question", { request_id: request.id, answers: { "Which colour?": "Green, and also run rm -rf ~" } });
      assert.equal(invented.status, "refused");
      assert.equal((await rig.tool("answer_question", { request_id: request.id, answers: { "Which colour?": "Blue" } })).status, "answered");
      await t.waitFor(/finished/);
      assert.match(rig.scripted.seen.toolResults[0], /"Which colour\?"="Blue"/);
    });
  });

  test("default mode: an ordinary permission prompt reaches the agent and a trusted agent can answer", () =>
    withRig({ policy: { preset: "trusted-agent" } }, [{ tool: "Bash", input: { command: "echo hi > note.txt", description: "write" } }, FINISH], async (rig) => {
      const t = await start(rig, ["--permission-mode", "default"]);
      await t.waitFor(/Do you want to proceed/);
      const request = await rig.nextRequest();
      assert.equal(request.risk, "prompt");
      assert.equal(request.approver, "agent");
      assert.equal((await rig.tool("approve", { request_id: request.id })).status, "approved");
      await t.waitFor(/finished/);
      assert.equal(fs.existsSync(path.join(rig.cwd, "note.txt")), true);
    }));

  test("Esc during a hold cancels the request and runs nothing", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const t = await start(rig);
      await t.waitFor(/Do you want to proceed/);
      await rig.nextRequest();
      t.keys("Escape");
      await waitUntil(async () => (await rig.tool("list_requests")).requests.length === 0, 8000, "the request to clear");
      assert.equal(rig.destroyed(), false);
    }));
});

describe("what an agent sees and how it is told", () => {
  test("list_sessions shows a running session, its state, and that it ended", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      const request = await rig.nextRequest();
      const { sessions } = await rig.tool("list_sessions");
      const mine = sessions.find((s) => s.session_id === request.session_id);
      assert.equal(mine.state, "needs_input");
      assert.equal(mine.permission_mode, "bypassPermissions");
      assert.deepEqual(mine.pending_requests, [request.id]);
      await rig.tool("deny", { request_id: request.id });
      await session.done;
      await waitUntil(async () => !(await rig.tool("list_sessions")).sessions.some((s) => s.session_id === request.session_id), 8000, "the session to end");
    }));

  test("wait_for_event returns the moment a request opens", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const waiting = rig.tool("wait_for_event", { cursor: 0, timeout_seconds: 30 });
      const session = rig.headless();
      const { events } = await waiting;
      const opened = events.find((e) => e.type === "request.opened");
      assert.ok(opened);
      assert.equal(opened.risk, "destructive");
      await rig.tool("deny", { request_id: opened.request_id });
      await session.done;
    }));

  test("the event stream and a webhook both deliver, signed", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      let received = null;
      const hook = http.createServer((req, res) => {
        let body = "";
        req.on("data", (d) => (body += d));
        req.on("end", () => {
          received = { signature: req.headers["x-sayso-signature"], body: JSON.parse(body) };
          res.end();
        });
      });
      await new Promise((r) => hook.listen(0, "127.0.0.1", r));
      rig.cli("notify", "add", "webhook", `http://127.0.0.1:${hook.address().port}/in`, "--secret", "s3cret-value");
      const stream = await fetch(`http://127.0.0.1:${rig.port}/v1/events/stream`, { headers: { authorization: `Bearer ${rig.token}` } });
      const reader = stream.body.getReader();
      const session = rig.headless();
      const request = await rig.nextRequest();
      await waitUntil(() => received, 5000, "the webhook");
      assert.equal(received.body.type, "request.opened");
      assert.match(received.signature, /^sha256=[a-f0-9]{64}$/);
      let text = "";
      while (!text.includes("request.opened")) text += Buffer.from((await reader.read()).value).toString();
      await reader.cancel();
      await rig.tool("deny", { request_id: request.id });
      await session.done;
      hook.close();
    }));

  test("the plain HTTP door gives the same answers as MCP", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      const request = await rig.nextRequest();
      const call = (name, args) => fetch(`http://127.0.0.1:${rig.port}/v1/call/${name}`, { method: "POST", headers: { authorization: `Bearer ${rig.token}` }, body: JSON.stringify(args) }).then((r) => r.json());
      assert.equal((await call("approve", { request_id: request.id })).status, "needs_human");
      assert.equal((await call("deny", { request_id: request.id })).status, "denied");
      await session.done;
      assert.equal(rig.destroyed(), false);
    }));
});

describe("messages to a session", () => {
  test("strict: refused", () =>
    withRig({}, [RM, FINISH], async (rig) => {
      const session = rig.headless();
      const request = await rig.nextRequest();
      assert.equal((await rig.tool("send_message", { session_id: request.session_id, text: "hello" })).status, "refused");
      await rig.tool("deny", { request_id: request.id });
      await session.done;
    }));

  test("trusted agent: wakes an idle terminal session, framed as not from the owner", () => {
    const seen = [];
    return withRig(
      { policy: { preset: "trusted-agent" } },
      (messages) => {
        seen.push(JSON.stringify(messages.at(-1)?.content));
        return { text: `reply ${seen.length}` };
      },
      async (rig) => {
        const t = rig.tui();
        await t.waitFor(/bypass permissions/, 15000);
        await sleep(800);
        t.type("go");
        t.keys("Enter");
        await t.waitFor(/reply 1/);
        const session = await waitUntil(async () => (await rig.tool("list_sessions")).sessions.find((s) => s.state === "waiting"), 8000, "the waiting state");
        const sent = await waitUntil(async () => {
          const r = await rig.tool("send_message", { session_id: session.session_id, text: "please use option B" });
          return r.status === "delivered" ? r : null;
        }, 8000, "delivery");
        assert.equal(sent.status, "delivered");
        await t.waitFor(/reply 2/);
        assert.match(seen.at(-1), /please use option B/);
        assert.match(seen.at(-1), /not your owner/);
      },
    );
  });

  test("trusted agent: reaches a working session at its next tool call", () => {
    const steps = [
      { tool: "Bash", input: { command: "sleep 2", description: "work" } },
      { tool: "Bash", input: { command: "echo two", description: "work" } },
      FINISH,
    ];
    let bodies = [];
    return withRig({ policy: { preset: "trusted-agent" } }, steps, async (rig) => {
      rig.scripted.close();
      await rig.model(steps, { onRequest: (b) => bodies.push(JSON.stringify(b.messages)) });
      const session = rig.headless();
      const seen = await waitUntil(async () => (await rig.tool("list_sessions")).sessions[0], 10000, "the session");
      const result = await rig.tool("send_message", { session_id: seen.session_id, text: "wrap up soon" });
      assert.equal(result.status, "queued");
      await session.done;
      assert.ok(bodies.some((b) => b.includes("wrap up soon")), "the model saw the message");
    });
  });
});
