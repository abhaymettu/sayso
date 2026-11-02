#!/bin/sh
# Claude Code runs the tool if a hook exits with anything but 2, including a crash, a missing runtime or a kill.
# So a failure of the gate itself is turned into a block here, in the one layer that needs no runtime.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=$1
node_bin=${SAYSO_NODE:-node}
if ! command -v "$node_bin" >/dev/null 2>&1; then
  for candidate in /opt/homebrew/bin/node /usr/local/bin/node "$HOME/.volta/bin/node" "$HOME/.local/bin/node"; do
    if [ -x "$candidate" ]; then node_bin=$candidate; break; fi
  done
fi
"$node_bin" "$root/src/hook.mjs" "$mode"
code=$?
case "$mode:$code" in
  gate:0) exit 0 ;;
  gate:*)
    echo "sayso: the gate failed (exit $code), so this tool call was blocked. Run: sayso doctor. To remove sayso: sayso uninstall" >&2
    exit 2 ;;
  *) exit "$code" ;;
esac
