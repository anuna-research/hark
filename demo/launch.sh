#!/usr/bin/env bash
#
# launch.sh — bootstrap demo-agent.sh against a fresh hark daemon + agent.
#
# Idempotent: if the hark daemon is already running, this reuses it; if not,
# it starts it. Then creates a cbcl-cli agent handle and supervises
# demo-agent.sh, re-initialising a fresh handle if the agent's handle or the
# daemon goes away (see the supervise loop below).
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

# tmux on macOS spawns non-login shells whose PATH doesn't include
# ~/.cargo/bin or other common cargo-install locations. Prepend the
# usual suspects so `hark` and `cbcl-cli` resolve regardless of how
# this script is invoked.
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

# Script-side configuration: bounded path + repo allowlists. Set once and
# inherited by every demo-agent.sh run in the supervise loop below.
export CLI_DEMO_ALLOWED_PREFIX="${CLI_DEMO_ALLOWED_PREFIX:-$HOME/Code}"
export CLI_DEMO_REPOS="${CLI_DEMO_REPOS:-cbcl-rs=$HOME/Code/cbcl-rs:hark=$HOME/Code/hark}"

echo "launch: ALLOWED_PREFIX=$CLI_DEMO_ALLOWED_PREFIX" >&2
echo "launch: REPOS=$CLI_DEMO_REPOS" >&2

agent_dir="$(cd "$(dirname "$0")" && pwd)"

# Close whatever handle we currently hold when the supervisor exits, so we
# don't leave a stale entry in the daemon.
cleanup() {
    if [[ -n ${CBCL_AGENT_HANDLE:-} ]]; then
        hark close >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Supervise loop.
#
# hark deliberately never reconnects a dropped router WebSocket: a silent
# reconnect could miss frames and break the causal ordering it enforces.
# Instead it marks the handle unhealthy, demo-agent.sh exits rc 7 (or rc 3 if
# the daemon itself went away), and we recover here by minting a *fresh*
# handle — a new router connection with a clean causal store — and restarting
# the agent. Backoff grows only across rapid repeated failures (e.g. the
# router is genuinely down) and resets once the agent has run for a while.
backoff=1
while true; do
    # Ensure the per-user hark daemon is up (it may have died).
    if ! hark daemon status >/dev/null 2>&1; then
        echo "launch: (re)starting hark daemon" >&2
        hark daemon start
        sleep 2
    fi

    # Drop any stale/unhealthy handle before minting a new one.
    if [[ -n ${CBCL_AGENT_HANDLE:-} ]]; then
        hark close >/dev/null 2>&1 || true
        unset CBCL_AGENT_HANDLE
    fi

    echo "launch: creating cbcl-cli agent handle" >&2
    eval "$(hark init --dialect cbcl-cli)" || true
    if [[ -z ${CBCL_AGENT_HANDLE:-} ]]; then
        echo "launch: hark init failed; retrying in ${backoff}s" >&2
        sleep "$backoff"
        backoff=$(( backoff < 30 ? backoff * 2 : 30 ))
        continue
    fi
    echo "launch: agent handle = $CBCL_AGENT_HANDLE" >&2

    # Run the agent loop. It returns when its handle/daemon goes away.
    started=$SECONDS
    rc=0
    bash "$agent_dir/demo-agent.sh" || rc=$?
    ran=$(( SECONDS - started ))

    case $rc in
        7|3)
            # Handle unhealthy / daemon gone — recoverable via re-init.
            if (( ran > 60 )); then
                backoff=1
            fi
            echo "launch: agent exited rc=$rc after ${ran}s; re-initialising in ${backoff}s" >&2
            sleep "$backoff"
            backoff=$(( backoff < 30 ? backoff * 2 : 30 ))
            ;;
        *)
            # Clean stop (0), interrupt (130/143), or an unrecognised error —
            # stop the supervisor and let cleanup close the handle.
            echo "launch: agent exited rc=$rc after ${ran}s; stopping" >&2
            exit "$rc"
            ;;
    esac
done
