#!/bin/sh -p
# Claude Code starts this file directly, with no shell in front of it, because a repository's `env` setting reaches any
# shell it starts. SHELLOPTS=noexec makes a shell read a command and run nothing, then exit 0, and no command can object.
# -p is what makes this shell ignore SHELLOPTS, BASHOPTS, BASH_ENV, ENV and exported functions in turn. Only absolute paths
# until the environment is clean, since PATH is the repository's too.
if [ "$1" != clean ]; then
  case $1 in
    gate | report | wake) ;;
    *)
      echo "sayso: this version of Claude Code did not pass the hook its arguments, so this tool call was blocked. Update Claude Code." >&2
      exit 2 ;;
  esac
  mode=$1
  shift
  exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$HOME" CLAUDE_PID="$CLAUDE_PID" CLAUDE_CODE_SESSION_ATTENDED="$CLAUDE_CODE_SESSION_ATTENDED" CLAUDE_CONFIG_DIR="$CLAUDE_CONFIG_DIR" "$@" /bin/sh -p "$0" clean "$mode"
fi
# Hardened, the gate reads the real home from the password database rather than one a session started with.
if [ -e /etc/sayso/hardened ]; then unset HOME; fi

# Claude Code runs the tool if a hook exits with anything but 2, including a crash, a missing runtime or a kill.
# So a failure of the gate itself is turned into a block here, in the one layer that needs no runtime.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=$2
node_bin=${SAYSO_NODE:-node}
if ! command -v "$node_bin" >/dev/null 2>&1; then
  # The environment is clean by now, so a plugin install has no PATH of the person's own to search. A system install comes
  # first and is never replaced by a folder in the home, which any process of this user can write to.
  for candidate in /usr/local/bin/node /opt/homebrew/bin/node "$HOME/.local/bin/node" "$HOME/.volta/bin/node" "$HOME"/.nvm/versions/node/*/bin/node "$HOME"/.local/share/fnm/aliases/default/bin/node "$HOME"/.fnm/aliases/default/bin/node "$HOME"/.asdf/shims/node "$HOME"/.local/share/mise/shims/node; do
    if [ -x "$candidate" ]; then
      node_bin=$candidate
      break
    fi
  done
fi
# Without this flag SIGUSR1 opens an inspector on the gate, and any local process could then run code inside it and print
# an allow. It needs Node 22.14. An older Node refuses the flag, and that exit is a block.
if [ "$mode" != gate ]; then
  "$node_bin" --disable-sigusr1 "$root/src/hook.mjs" "$mode"
  exit $?
fi
if ! command -v "$node_bin" >/dev/null 2>&1; then
  echo "sayso: could not find Node, so this tool call was blocked. Install with: npx github:abhaymettu/sayso setup, which records where Node is." >&2
  exit 2
fi

# The gate keeps its own clocks, but a process that is stopped or stuck in a system call can't run them. This one needs
# nothing from it. It fires past the longest hold (3000 s) and before the hook timeout (3600 s), and the kill becomes a
# block below. A shell gives a background job /dev/null for stdin unless told otherwise, so the hook input goes by fd 3.
limit=${SAYSO_GATE_LIMIT:-3300}
exec 3<&0
"$node_bin" --disable-sigusr1 "$root/src/hook.mjs" gate <&3 3<&- &
gate=$!
exec 3<&- </dev/null
(
  trap 'kill "$!" 2>/dev/null; exit 0' TERM
  while [ "$limit" -gt 0 ] && kill -0 "$gate" 2>/dev/null; do
    sleep 1 &
    wait "$!"
    limit=$((limit - 1))
  done
  kill -KILL "$gate"
) >/dev/null 2>&1 &
watchdog=$!
trap 'kill -KILL "$gate" "$watchdog" 2>/dev/null; exit 2' HUP INT TERM
wait "$gate"
code=$?
kill "$watchdog" 2>/dev/null
case "$code" in
  0) exit 0 ;;
  *)
    echo "sayso: the gate failed (exit $code), so this tool call was blocked. Run: sayso doctor. To remove sayso: sayso uninstall" >&2
    exit 2 ;;
esac
