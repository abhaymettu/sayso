// A stand-in for the Anthropic Messages API. Real Claude Code talks to it through ANTHROPIC_BASE_URL, so the tests
// exercise the real binary, real hooks and real tool execution, with no account, no cost and no model nondeterminism.
import http from "node:http";

const sse = (res, event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

function streamReply(res, blocks, stopReason) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  sse(res, "message_start", {
    type: "message_start",
    message: {
      id: `msg_${Math.random().toString(36).slice(2)}`,
      type: "message",
      role: "assistant",
      content: [],
      model: "claude-scripted",
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 1 },
    },
  });
  blocks.forEach((block, index) => {
    if (block.type === "text") {
      sse(res, "content_block_start", { type: "content_block_start", index, content_block: { type: "text", text: "" } });
      sse(res, "content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text: block.text } });
    } else {
      sse(res, "content_block_start", {
        type: "content_block_start",
        index,
        content_block: { type: "tool_use", id: block.id, name: block.name, input: {} },
      });
      sse(res, "content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) },
      });
    }
    sse(res, "content_block_stop", { type: "content_block_stop", index });
  });
  sse(res, "message_delta", { type: "message_delta", delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 1 } });
  sse(res, "message_stop", { type: "message_stop" });
  res.end();
}

const hasToolResult = (messages) =>
  messages.some((m) => Array.isArray(m.content) && m.content.some((c) => c.type === "tool_result"));

const countToolResults = (messages) =>
  messages.reduce((n, m) => n + (Array.isArray(m.content) ? m.content.filter((c) => c.type === "tool_result").length : 0), 0);

const lastToolResultText = (messages) => {
  for (let i = messages.length - 1; i >= 0; i--) {
    const c = Array.isArray(messages[i].content) ? messages[i].content.find((x) => x.type === "tool_result") : null;
    if (c) return typeof c.content === "string" ? c.content : JSON.stringify(c.content);
  }
  return "";
};

// `plan` is a list of steps: { tool, input } or { text }. The step comes from how many tool results the request carries,
// so the server holds no per-conversation state and a resumed session lands on the right step.
export function startScriptedModel(plan, { onToolEmitted, onRequest } = {}) {
  const seen = { requests: 0, toolResults: [] };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      let parsed = {};
      try {
        parsed = JSON.parse(body || "{}");
      } catch {}
      if (!req.url.startsWith("/v1/messages") || req.url.includes("count_tokens")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 1 }));
        return;
      }
      const messages = parsed.messages || [];
      seen.requests++;
      onRequest?.(parsed);
      // Claude Code's side calls (titles, summaries, classifiers) carry no tools.
      if (!parsed.tools?.length) return streamReply(res, [{ type: "text", text: "ok" }], "end_turn");
      if (hasToolResult(messages)) seen.toolResults.push(lastToolResultText(messages));
      const step = typeof plan === "function" ? plan(messages) : plan[countToolResults(messages)];
      if (!step || step.text !== undefined) return streamReply(res, [{ type: "text", text: step?.text ?? "done" }], "end_turn");
      onToolEmitted?.(step, performance.now());
      const calls = step.parallel ?? [step];
      return streamReply(res, calls.map((c) => ({ type: "tool_use", id: `toolu_${Math.random().toString(36).slice(2)}`, name: c.tool, input: c.input })), "tool_use");
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}`, seen, close: () => server.close() });
    });
  });
}
