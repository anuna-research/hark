#!/bin/sh
# Exercises the tmux + withdone + publish machinery with no hub.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export HERD_STATE="${TMPDIR:-/tmp}/herd-spike-test.$$"
export HERD_SESSION="herd-test-$$"
export HERD_PUBLISH=stub
export HERD_AGENT_CMD="$HERE/fake-agent"
export HERD_GRACE=1
export HERD_PASS_ENV="FAKE_CODE FAKE_MUTE FAKE_SLEEP"
export FAKE_SLEEP=1

fail=0
ok()  { echo "  PASS $*"; }
bad() { echo "  FAIL $*"; fail=1; }
cleanup() { "$HERE/herd" down >/dev/null 2>&1 || true; rm -rf "$HERD_STATE"; }
trap cleanup EXIT

# Wait on the condition, not on a guessed duration.
wait_for() {
    limit=$1; shift
    n=0
    while [ "$n" -lt "$limit" ]; do
        if eval "$*"; then return 0; fi
        n=$((n + 1)); sleep 1
    done
    return 1
}

echo "== up =="
"$HERE/herd" up
tmux has-session -t "$HERD_SESSION" && ok "tmux session exists"

echo "== success path: agent declares 0 =="
HERD_SILENCE=60 "$HERE/herd" spawn rcp-001 'say hello'
wait_for 20 '[ -f "$HERD_STATE/jobs/rcp-001/code" ]' || bad "no code file after 20s"
[ "$(cat "$HERD_STATE/jobs/rcp-001/code" 2>/dev/null)" = 0 ] \
    && ok "exit code 0 propagated from sentinel" \
    || bad "code was '$(cat "$HERD_STATE/jobs/rcp-001/code" 2>/dev/null)'"
grep -q '^reply.*:thread "rcp-001"' "$HERD_STATE/published.log" \
    && ok "reply published on the ask's thread" || bad "no reply frame"

echo "== failure path: agent declares 2 =="
FAKE_CODE=2 HERD_SILENCE=60 "$HERE/herd" spawn rcp-002 'do a thing badly'
wait_for 20 '[ -f "$HERD_STATE/jobs/rcp-002/code" ]' || bad "no code file after 20s"
[ "$(cat "$HERD_STATE/jobs/rcp-002/code" 2>/dev/null)" = 2 ] \
    && ok "semantic exit code 2 propagated" \
    || bad "code was '$(cat "$HERD_STATE/jobs/rcp-002/code" 2>/dev/null)'"
grep -q '^error.*:thread "rcp-002"' "$HERD_STATE/published.log" \
    && ok "error frame published" || bad "no error frame"

echo "== non-compliant agent: never declares =="
FAKE_MUTE=1 FAKE_SLEEP=30 HERD_SILENCE=3 "$HERE/herd" spawn rcp-003 'forget to signal'
wait_for 20 'grep -q "rcp-003 silent" "$HERD_STATE/published.log"' \
    && ok "silence poll surfaced the stall" \
    || bad "no silence alert"

echo "== quiet after done: no spurious alerts =="
sleep 2
[ "$(grep -c 'rcp-001' "$HERD_STATE/published.log")" -le 2 ] \
    && ok "completed job stayed quiet (no silent/pane-died noise)" \
    || bad "completed job emitted extra frames: $(grep 'rcp-001' "$HERD_STATE/published.log" | tr '\n' '|')"

echo "== herd view =="
"$HERE/herd" ls

echo
[ "$fail" = 0 ] && echo "ALL PASS" || echo "FAILURES"
exit "$fail"
