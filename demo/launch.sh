#!/usr/bin/env bash
#
# launch.sh — bootstrap demo-agent.sh against a fresh hark daemon + agent.
#
# Idempotent: if the hark daemon is already running, this reuses it; if not,
# it starts it. Then creates a cbcl-cli agent handle and execs demo-agent.sh
# with sensible defaults.
#
# Designed to be run as a single command from tmux:
#
#   tmux new -d -s demo-agent "bash $HOME/Code/hark/demo/launch.sh"
#
# Override defaults via env before invocation:
#
#   CLI_DEMO_ALLOWED_PREFIX=/path/to/scope
#   CLI_DEMO_REPOS=name=path:name=path
#
# Defaults assume the agent host has both repos at $HOME/Code/{cbcl-rs,hark}
# and is willing to expose paths under $HOME/Code.

set -e

# Start the per-user hark daemon if it isn't already up.
if ! hark daemon status >/dev/null 2>&1; then
    echo "launch: starting hark daemon" >&2
    hark daemon start
    sleep 2
fi

# Create the cbcl-cli agent handle (or reuse if one is already advertised).
echo "launch: creating cbcl-cli agent handle" >&2
eval "$(hark init --dialect cbcl-cli)"
echo "launch: agent handle = $CBCL_AGENT_HANDLE" >&2

# Script-side configuration: bounded path + repo allowlists.
export CLI_DEMO_ALLOWED_PREFIX="${CLI_DEMO_ALLOWED_PREFIX:-$HOME/Code}"
export CLI_DEMO_REPOS="${CLI_DEMO_REPOS:-cbcl-rs=$HOME/Code/cbcl-rs:hark=$HOME/Code/hark}"

echo "launch: ALLOWED_PREFIX=$CLI_DEMO_ALLOWED_PREFIX" >&2
echo "launch: REPOS=$CLI_DEMO_REPOS" >&2

# Replace this process with the agent loop so signals propagate cleanly.
exec bash "$(dirname "$0")/demo-agent.sh"
