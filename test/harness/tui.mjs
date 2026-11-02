// Runs the real Claude Code terminal UI inside a private tmux server, so tests can read the screen and press keys.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const CLAUDE = process.env.CLAUDE_BIN || "claude";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function newBox(name = "tui") {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), `${name}-`));
  const config = path.join(root, "config");
  const cwd = path.join(root, "work");
  fs.mkdirSync(config);
  fs.mkdirSync(path.join(cwd, "victim"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "victim", "file.txt"), "keep me");
  return { root, config, cwd, victim: path.join(cwd, "victim", "file.txt") };
}

export function apiKeyEnv(box, baseUrl, extra = {}) {
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    TMPDIR: process.env.TMPDIR,
    TERM: "xterm-256color",
    CLAUDE_CONFIG_DIR: box.config,
    ANTHROPIC_API_KEY: "sk-ant-scripted-model-not-a-real-key",
    ANTHROPIC_BASE_URL: baseUrl,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    DISABLE_TELEMETRY: "1",
    ...extra,
  };
}

export function acceptFirstRun(box, env) {
  const key = env.ANTHROPIC_API_KEY;
  fs.writeFileSync(
    path.join(box.config, ".claude.json"),
    JSON.stringify({
      hasCompletedOnboarding: true,
      lastOnboardingVersion: "2.1.303",
      theme: "dark",
      customApiKeyResponses: { approved: [key.slice(-20)], rejected: [] },
      projects: { [box.cwd]: { hasTrustDialogAccepted: true, hasCompletedProjectOnboarding: true, allowedTools: [] } },
    }),
  );
}

export class Tui {
  constructor(box, env, args = []) {
    this.socket = `probe-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
    this.box = box;
    acceptFirstRun(box, env);
    const script = path.join(box.root, "start.sh");
    const exports = Object.entries(env)
      .map(([k, v]) => `export ${k}=${JSON.stringify(v)}`)
      .join("\n");
    fs.writeFileSync(script, `#!/bin/sh\n${exports}\ncd ${JSON.stringify(box.cwd)}\nexec ${JSON.stringify(CLAUDE)} ${args.map((a) => JSON.stringify(a)).join(" ")}\n`, { mode: 0o755 });
    execFileSync("tmux", ["-L", this.socket, "-f", "/dev/null", "new-session", "-d", "-s", "t", "-x", "120", "-y", "40", script], { env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, TERM: "xterm-256color" } });
  }
  screen() {
    const r = spawnSync("tmux", ["-L", this.socket, "capture-pane", "-p", "-t", "t"], { encoding: "utf8" });
    return r.stdout ?? "";
  }
  keys(...keys) {
    spawnSync("tmux", ["-L", this.socket, "send-keys", "-t", "t", ...keys]);
  }
  type(text) {
    spawnSync("tmux", ["-L", this.socket, "send-keys", "-t", "t", "-l", text]);
  }
  async waitFor(pattern, ms = 20000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const s = this.screen();
      if (pattern.test(s)) return s;
      await sleep(150);
    }
    throw new Error(`timed out waiting for ${pattern}; screen:\n${this.screen()}`);
  }
  alive() {
    return spawnSync("tmux", ["-L", this.socket, "has-session", "-t", "t"]).status === 0;
  }
  kill() {
    spawnSync("tmux", ["-L", this.socket, "kill-server"]);
  }
}
