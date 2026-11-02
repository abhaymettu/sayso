# What Claude Code hooks actually do

Everything in sayso rests on these facts, so they are measured rather than assumed. Each comes from the real binary
(version 2.1.303) with a scripted model, in a throwaway config, trying to run `rm -rf victim`.

Rerun on your version: `node test/probe-hooks.mjs` and `node test/probe-tui.mjs`.

## Which events fire

| Permission mode | PreToolUse | PermissionRequest | `rm -rf` with no gate |
|---|---|---|---|
| bypassPermissions | yes | no | runs |
| acceptEdits | yes | no | runs |
| default, headless | yes | yes | refused by Claude Code |
| plan | yes | no | refused by Claude Code |
| dontAsk | yes | no | refused by Claude Code |

So in bypass mode there is no prompt to answer. PreToolUse is the only place a call can be stopped.

## What blocks, and what does not

By default a hook blocks only by saying so, and a failure of the hook itself lets the tool run. Setting
[`"onFailure": "block"`](https://code.claude.com/docs/en/hooks) on the hook changes most of that.

| What the PreToolUse hook does | Result in bypass mode, default | With `onFailure: "block"` |
|---|---|---|
| Returns `permissionDecision: "deny"` | blocked, in all five modes | not rerun |
| Exits 2 | blocked | not rerun |
| Exits 1 | **`rm -rf` ran** | blocked |
| Its command is not found | **`rm -rf` ran** | blocked |
| Prints something that isn't JSON and exits 0 | **`rm -rf` ran** | **`rm -rf` ran** |
| Killed with SIGKILL while holding | **`rm -rf` ran** | blocked |
| Passes its `timeout` | **`rm -rf` ran** | blocked |
| No `timeout` set, runs past 600 s | **`rm -rf` ran**, at 601 s | not rerun |
| `timeout: 3600`, holds 700 s, then answers | its answer is honoured at 701 s | not rerun |

`node test/probe-hooks.mjs --only=onFailure` reruns the last column. Claude Code's docs count invalid output as a failure,
but plain text on stdout isn't one, so that row stays open.

This is the trap for anything built on hooks. A guard that crashes, runs out of memory or loses its runtime turns off
without a sound, and the thing it was guarding happens anyway.

sayso's answer has five parts:

- The gate's hook entries set `onFailure: "block"`, so a kill or a timeout blocks the call on a Claude Code that knows the
  field.
- `hooks/run.sh` wraps the gate in the one layer that needs no runtime, and turns every failure into exit 2. This covers
  older versions, and says what happened and how to fix it.
- The hook timeout is 3600 s and holds are capped at 3000 s, so an open hold ends with an answer first.
- The gate has clocks of its own that need nothing from the daemon: 3 s to read the command, 10 s for the daemon to open the
  hold, and the hold's end after that. A `vm` timeout interrupts the read, since a timer can't fire on a thread the
  classifier is holding.
- `hooks/run.sh` kills a gate that is stopped or stuck in a system call at 3300 s, past the longest hold and before the hook
  timeout, and the kill becomes a block.
- Holds live on a connection. If the daemon dies, the connection closes and the hook denies.

Claude Code also refuses a few things on its own. `rmdir /` in bypass mode comes back with "Dangerous rmdir operation
detected" and can't be auto-allowed, with no hook involved, and its docs name `rm -rf ~` as another case. So this table is
about ordinary commands, and "a prompt never appears in bypass" has that small exception.

## What a person at a terminal sees

- During a PreToolUse hold the terminal stays alive and shows that a hook is running. Esc interrupts, and the tool does
  not run.
- `permissionDecision: "ask"` puts the real dialog on screen **even in bypass mode**, and then fires PermissionRequest.
- The dialog stays up while a PermissionRequest hook holds, and the hook's answer closes it. So the keyboard and a
  remote answer can race, and whichever comes first wins. sayso uses exactly this at a terminal.
- In headless mode `ask` runs nothing and fires no PermissionRequest, which is why sayso holds at PreToolUse there.
- A keyboard no or Esc kills the PermissionRequest hook. A keyboard yes does not: the hook keeps running until it finishes
  on its own. Its input has no `tool_use_id`, so sayso matches the PostToolUse that follows by session, tool and input hash,
  and lets go of the hold.
- Claude Code refuses a Bash command holding terminal control characters before any hook sees it.

## Questions and idle sessions

- AskUserQuestion is answered by returning `allow` with `updatedInput.answers`, from PreToolUse or PermissionRequest. The
  screen shows "User answered" and the dialog closes.
- In headless mode AskUserQuestion is not available at all.
- An idle session can be reached by a Stop hook with `async: true` and `asyncRewake: true`. When it exits 2, its stderr
  wakes the model. Claude Code wraps that text as "SYSTEM NOTIFICATION - NOT USER INPUT", so the model is told it did
  not come from the user, which is what sayso wants.

## What a repository's settings reach

A checkout's `.claude/settings.json` applies to any session started in it, and its `env` reaches hook processes. Measured
with `-p`, where no trust dialog appears:

| In the project's `env` | What the hook process sees |
|---|---|
| `PATH`, `NODE_OPTIONS`, `SAYSO_*` | the repository's value, so the hook command clears its environment and uses absolute paths |
| `HOME` | Claude Code's own value, not the repository's |
| `SHELL`, `BASH_ENV`, `ENV` | the repository's value, with no effect on how the command runs |
| `CLAUDE_CODE_SHELL_PREFIX` | **the hook command never runs**, and the prefix runs in its place |

Nothing in a hook's command can stop that last row, or `disableAllHooks`. Managed settings can: their `env` beats a
project's, and `sudo sayso harden` uses that.

## What skips hooks

Hooks in user settings do not run under `--bare`, `--safe-mode`, `disableAllHooks`, or the Agent SDK with
`settingSources: []`, per Claude Code's documentation, and `disableAllHooks` and `CLAUDE_CODE_SHELL_PREFIX` work from a
project's settings too. `sudo sayso harden` uses managed hooks, and `test/harden.mjs` shows them still holding the call under
`--bare`, `--safe-mode`, `--setting-sources project`, and `disableAllHooks` or a project `env` from user or project settings.
