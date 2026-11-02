#!/bin/sh
# Claude Code runs the tool if a hook exits with anything but 2, including a crash, a missing runtime or a kill.
# So a failure of the gate itself is turned into a block here, in the one layer that needs no runtime.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=$1
node_bin=${SAYSO_NODE:-node}
if ! command -v "$node_bin" >/dev/null 2>&1; then
  # The hook commands clear the environment, so a plugin install has no PATH of the person's own to search. Later wins.
  for candidate in "$HOME"/.nvm/versions/node/*/bin/node "$HOME"/.local/share/fnm/aliases/default/bin/node "$HOME"/.fnm/aliases/default/bin/node "$HOME"/.asdf/shims/node "$HOME"/.local/share/mise/shims/node "$HOME/.local/bin/node" "$HOME/.volta/bin/node" /usr/local/bin/node /opt/homebrew/bin/node; do
    if [ -x "$candidate" ]; then node_bin=$candidate; fi
  done
fi
if [ "$mode" != gate ]; then
  "$node_bin" "$root/src/hook.mjs" "$mode"
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
"$node_bin" "$root/src/hook.mjs" gate <&3 3<&- &
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
