#!/usr/bin/env node
// The daemon. Two doors with different powers: a Unix socket for hooks, which can open requests but never answer them,
// and an authenticated loopback HTTP port for agents, which can answer but never open them.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { createBox } from "./box.mjs";
import { DEFAULT_PAGE, DEFAULT_PORT, statePaths } from "./paths.mjs";
import { loadPolicy } from "./policy.mjs";
import { redact } from "./redact.mjs";
import { INSTRUCTIONS, TOOLS, TOOL_BY_NAME } from "./tools.mjs";

const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BODY = 256 * 1024;
const SWEEP_MS = 1000;
const LIVENESS_MS = 5000;

const readJson = (file, fallback) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
};

export function loadConfig(paths) {
  const config = readJson(paths.config, {});
  return {
    port: Number(process.env.SAYSO_PORT ?? config.port ?? DEFAULT_PORT),
    page_url: config.page_url ?? DEFAULT_PAGE,
    allowed_hosts: config.allowed_hosts ?? [],
    notify: config.notify ?? [],
  };
}

const sha256 = (text) => crypto.createHash("sha256").update(text).digest("hex");

function authenticate(req, agents) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;
  const digest = Buffer.from(sha256(token));
  for (const agent of agents) {
    const known = Buffer.from(agent.token_sha256);
    if (known.length === digest.length && crypto.timingSafeEqual(known, digest) && !agent.revoked) return { type: "agent", name: agent.name };
  }
  return null;
}

// A browser page can reach loopback. Rejecting foreign Host values stops DNS rebinding, and rejecting Origin stops
// cross-site requests, so only programs with a token get past this point.
function hostAllowed(req, port, allowedHosts) {
  const host = (req.headers.host ?? "").toLowerCase();
  if (host === `127.0.0.1:${port}` || host === `localhost:${port}` || host === `[::1]:${port}`) return true;
  return allowedHosts.includes(host);
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error("body too large"), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

function pushToSinks(event, sinks, log) {
  if (event.type !== "request.opened" && event.type !== "session.waiting" && event.type !== "session.failed") return;
  const body = JSON.stringify(event);
  for (const sink of sinks) {
    if (sink.type === "webhook") {
      const signature = sink.secret ? `sha256=${crypto.createHmac("sha256", sink.secret).update(body).digest("hex")}` : undefined;
      fetch(sink.url, {
        method: "POST",
        headers: { "content-type": "application/json", ...(signature ? { "x-sayso-signature": signature } : {}), ...(sink.headers ?? {}) },
        body,
        signal: AbortSignal.timeout(5000),
      }).catch((error) => log(`webhook failed: ${error.message}`));
    } else if (sink.type === "command") {
      const child = spawn(sink.argv[0], sink.argv.slice(1), { stdio: ["pipe", "ignore", "ignore"] });
      child.on("error", (error) => log(`notify command failed: ${error.message}`));
      child.stdin.on("error", () => {});
      child.stdin.end(body);
    }
  }
}

export async function startDaemon(paths = statePaths()) {
  fs.mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(paths.mail, { recursive: true, mode: 0o700 });
  fs.chmodSync(paths.dir, 0o700);

  const log = (line) => fs.appendFileSync(paths.log, `${new Date().toISOString()} ${line}\n`, { mode: 0o600 });
  let config = loadConfig(paths);
  const waiters = new Set();
  const streams = new Set();
  const wakers = new Map();

  const box = createBox({
    paths,
    policy: loadPolicy(paths.policy),
    agents: readJson(paths.agents, []),
    keys: readJson(paths.keys, []),
    pageUrl: config.page_url,
    onEvent(event) {
      pushToSinks(event, config.notify, log);
      for (const wake of [...waiters]) wake();
      const line = `id: ${event.seq}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
      for (const res of streams) res.write(line);
    },
  });

  const reload = () => {
    config = loadConfig(paths);
    box.setConfig({ policy: loadPolicy(paths.policy), agents: readJson(paths.agents, []), keys: readJson(paths.keys, []) });
  };

  function waitForEvents({ cursor, timeout_seconds = 30, all = false }) {
    const fresh = cursor === undefined;
    const since = cursor ?? 0;
    const collect = () => {
      const events = box.eventsSince(since, !all);
      // A first call asks "what needs me now", so resolved history is dropped and only open requests come back.
      return fresh ? events.filter((e) => e.type === "request.opened" && box.getRequest(e.request_id)?.status === "pending") : events;
    };
    const ready = collect();
    if (ready.length || timeout_seconds <= 0) return Promise.resolve({ events: ready, cursor: box.seq });
    return new Promise((resolve) => {
      const finish = () => {
        const events = collect();
        waiters.delete(check);
        clearTimeout(timer);
        resolve({ events, cursor: box.seq });
      };
      const check = () => {
        if (collect().length) finish();
      };
      const timer = setTimeout(finish, Math.min(timeout_seconds, 300) * 1000);
      waiters.add(check);
    });
  }

  function sendMessage(actor, sessionId, text) {
    if (!box.policy.messages) return { status: "refused", message: "the policy does not let agents send messages. The person can turn this on with `sayso policy trusted-agent`." };
    const session = box.session(sessionId);
    if (!session || session.state === "ended") return { status: "not_found", message: "no running session with that id" };
    const clean = redact(String(text ?? "")).slice(0, 4000);
    if (!clean.trim()) return { status: "refused", message: "empty message" };
    const framed = `Message from ${actor.name}, your owner's agent (not your owner): ${clean}`;
    box.audit.append({ session: sessionId, decision: "message", actor, text_sha256: sha256(clean) });
    const waker = wakers.get(sessionId);
    if (waker) {
      wakers.delete(sessionId);
      waker.end(`${JSON.stringify({ message: framed })}\n`);
      return { status: "delivered", via: "woke the idle session" };
    }
    if (session.state === "waiting") return { status: "not_deliverable", message: "that session is idle and has no listener; it cannot be woken right now" };
    fs.appendFileSync(path.join(paths.mail, encodeURIComponent(sessionId)), `${framed}\n`, { mode: 0o600 });
    return { status: "queued", via: "next tool call" };
  }

  const toolContext = { waitForEvents, sendMessage };

  // ---- hook door ----
  function handleHook(conn, message) {
    switch (message.op) {
      case "event":
        box.report(message);
        conn.end();
        return;
      case "hold": {
        const request = box.openRequest({
          ...message,
          onDecision(decision) {
            if (decision && !conn.destroyed) conn.end(`${JSON.stringify(decision)}\n`);
          },
        });
        if (!request) return;
        const timer = setTimeout(() => box.expire(request.id), Math.max(0, request.expires_ms - Date.now()));
        conn.on("close", () => {
          clearTimeout(timer);
          box.cancel(request.id);
        });
        conn.write(`${JSON.stringify({ opened: request.id, expires_at: request.expires_at })}\n`);
        return;
      }
      case "wait_message": {
        if (!box.policy.messages) return void conn.end(`${JSON.stringify({ none: true })}\n`);
        wakers.get(message.session_id)?.end(`${JSON.stringify({ none: true })}\n`);
        wakers.set(message.session_id, conn);
        conn.on("close", () => {
          if (wakers.get(message.session_id) === conn) wakers.delete(message.session_id);
        });
        return;
      }
      case "status":
        conn.end(`${JSON.stringify({ pid: process.pid, port: config.port, sessions: box.listSessions(), requests: box.listRequests(), policy: box.policy, agents: box.agents.map((a) => a.name), keys: box.keys.map((k) => ({ id: k.id, name: k.name })) })}\n`);
        return;
      case "reload":
        reload();
        conn.end(`${JSON.stringify({ ok: true })}\n`);
        return;
      case "deny":
        conn.end(`${JSON.stringify(box.deny(message.request_id, { type: "owner", name: "local terminal" }, message.reason))}\n`);
        return;
      case "shutdown":
        conn.end(`${JSON.stringify({ ok: true })}\n`);
        setTimeout(() => process.exit(0), 20);
        return;
      default:
        conn.end(`${JSON.stringify({ error: "unknown op" })}\n`);
    }
  }

  const hookServer = net.createServer((conn) => {
    let buffer = "";
    let handled = false;
    conn.setEncoding("utf8");
    conn.on("error", () => {});
    conn.on("data", (chunk) => {
      if (handled) return;
      buffer += chunk;
      if (buffer.length > 2 * 1024 * 1024) return conn.destroy();
      const end = buffer.indexOf("\n");
      if (end < 0) return;
      handled = true;
      try {
        handleHook(conn, JSON.parse(buffer.slice(0, end)));
      } catch (error) {
        log(`hook door: ${error.message}`);
        conn.destroy();
      }
    });
  });

  // ---- agent door ----
  async function handleMcp(req, res, actor) {
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return sendJson(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    }
    const respond = async (msg) => {
      const reply = (result) => ({ jsonrpc: "2.0", id: msg.id, result });
      const fail = (code, message) => ({ jsonrpc: "2.0", id: msg.id, error: { code, message } });
      switch (msg.method) {
        case "initialize": {
          const asked = msg.params?.protocolVersion;
          return reply({
            protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
            capabilities: { tools: {} },
            serverInfo: { name: "sayso", version: "0.1.0" },
            instructions: INSTRUCTIONS,
          });
        }
        case "ping":
          return reply({});
        case "tools/list":
          return reply({ tools: TOOLS.map(({ name, description, inputSchema, readOnly }) => ({ name, description, inputSchema, annotations: { readOnlyHint: !!readOnly } })) });
        case "tools/call": {
          const tool = TOOL_BY_NAME.get(msg.params?.name);
          if (!tool) return fail(-32602, `unknown tool ${msg.params?.name}`);
          const result = await tool.run(box, actor, msg.params?.arguments ?? {}, toolContext);
          return reply({ content: [{ type: "text", text: JSON.stringify(result, null, 1) }], structuredContent: result, isError: result?.status === "not_found" });
        }
        default:
          return msg.method?.startsWith("notifications/") ? null : fail(-32601, `unknown method ${msg.method}`);
      }
    };
    if (Array.isArray(body)) {
      const out = (await Promise.all(body.map(respond))).filter(Boolean);
      return out.length ? sendJson(res, 200, out) : void res.writeHead(202).end();
    }
    const out = await respond(body);
    return out ? sendJson(res, 200, out) : void res.writeHead(202).end();
  }

  function handleStream(req, res) {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
    const from = Number(req.headers["last-event-id"] ?? new URL(req.url, "http://x").searchParams.get("since") ?? box.seq);
    for (const event of box.eventsSince(from, false)) res.write(`id: ${event.seq}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
    res.write(": connected\n\n");
    streams.add(res);
    const heartbeat = setInterval(() => res.write(": ping\n\n"), 15000);
    req.on("close", () => {
      clearInterval(heartbeat);
      streams.delete(res);
    });
  }

  const httpServer = http.createServer(async (req, res) => {
    try {
      if (!hostAllowed(req, config.port, config.allowed_hosts)) return sendJson(res, 403, { error: "host not allowed" });
      if (req.headers.origin) return sendJson(res, 403, { error: "browser requests are not allowed" });
      const url = new URL(req.url, "http://x");
      if (url.pathname === "/health") return sendJson(res, 200, { ok: true, name: "sayso" });
      const actor = authenticate(req, box.agents);
      if (!actor) return sendJson(res, 401, { error: "missing or invalid token" }, { "www-authenticate": "Bearer" });

      if (url.pathname === "/mcp") {
        if (req.method === "POST") return await handleMcp(req, res, actor);
        return sendJson(res, 405, { error: "this server does not open a server-sent stream on /mcp" }, { allow: "POST" });
      }
      if (url.pathname === "/v1/events/stream" && req.method === "GET") return handleStream(req, res);
      const call = /^\/v1\/call\/([a-z_]+)$/.exec(url.pathname);
      if (call && req.method === "POST") {
        const tool = TOOL_BY_NAME.get(call[1]);
        if (!tool) return sendJson(res, 404, { error: "unknown tool" });
        const raw = await readBody(req);
        return sendJson(res, 200, await tool.run(box, actor, raw ? JSON.parse(raw) : {}, toolContext));
      }
      if (url.pathname === "/v1/tools" && req.method === "GET") return sendJson(res, 200, { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })), instructions: INSTRUCTIONS });
      return sendJson(res, 404, { error: "not found" });
    } catch (error) {
      log(`agent door: ${error.message}`);
      if (!res.headersSent) sendJson(res, error.statusCode ?? 500, { error: error.statusCode ? error.message : "internal error" });
      else res.end();
    }
  });

  await new Promise((resolve, reject) => {
    hookServer.once("error", reject);
    const bind = () => hookServer.listen(paths.sock, () => {
      fs.chmodSync(paths.sock, 0o600);
      resolve();
    });
    if (!fs.existsSync(paths.sock)) return bind();
    // A socket file with nobody behind it is left over from a crash. One that answers means a daemon is already up.
    const probe = net.connect(paths.sock);
    probe.once("connect", () => {
      probe.destroy();
      reject(Object.assign(new Error("already running"), { code: "ALREADY_RUNNING" }));
    });
    probe.once("error", () => {
      fs.rmSync(paths.sock, { force: true });
      bind();
    });
  });

  await new Promise((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(config.port, "127.0.0.1", resolve);
  });
  fs.writeFileSync(paths.pid, String(process.pid), { mode: 0o600 });
  log(`started pid ${process.pid} port ${httpServer.address().port}`);

  const sweeper = setInterval(() => box.sweep(), SWEEP_MS);
  const liveness = setInterval(() => box.checkLiveness(isAlive), LIVENESS_MS);
  sweeper.unref();
  liveness.unref();

  const shutdown = () => {
    fs.rmSync(paths.sock, { force: true });
    fs.rmSync(paths.pid, { force: true });
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  return { box, port: httpServer.address().port };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("server.mjs")) {
  startDaemon().catch((error) => {
    if (error.code === "ALREADY_RUNNING") process.exit(0);
    console.error(`sayso daemon: ${error.message}`);
    process.exit(1);
  });
}
