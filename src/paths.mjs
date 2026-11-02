import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_PORT = 7428;
export const DEFAULT_PAGE = "https://abhaymettu.github.io/sayso/";

// Hooks are registered with a 3600 s timeout, and Claude Code lets the tool run if that timeout fires.
// A hold therefore has to end well before it, whatever the policy file says.
export const MAX_HOLD_SECONDS = 3000;

export const HARDENED_HOME = "/var/lib/sayso";
export const HARDENED_SOCK = "/run/sayso/sayso.sock";
export const isHardened = () => existsSync("/etc/sayso/hardened");

export function statePaths(dir = process.env.SAYSO_HOME || (isHardened() ? HARDENED_HOME : join(homedir(), ".sayso"))) {
  return {
    dir,
    sock: process.env.SAYSO_SOCK || (dir === HARDENED_HOME ? HARDENED_SOCK : join(dir, "sayso.sock")),
    config: join(dir, "config.json"),
    policy: join(dir, "policy.json"),
    agents: join(dir, "agents.json"),
    keys: join(dir, "keys.json"),
    audit: join(dir, "audit.jsonl"),
    log: join(dir, "daemon.log"),
    pid: join(dir, "daemon.pid"),
    mail: join(dir, "mail"),
  };
}
