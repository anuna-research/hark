# herd-spike

A supervisor loop composed from tmux + withdone + hark: listen on the bus,
spawn an agent CLI per task, reply when it declares completion.

    herd up                  daemon + handle + tmux session + ticker
    herd listen              recv loop: an ask spawns a worker
    herd spawn <thr> <task>  spawn one worker directly (no bus)
    herd ls                  the herd view
    herd down                close the handle, kill the session

    sh test.sh               end-to-end, no hub required

## The premise

Every state this reports is **declared** by a party with a contract. Nothing
parses agent output.

| State | Declared by | Contract |
|---|---|---|
| `done` + semantic exit code | the agent | withdone sentinel — we mint the path and put the instruction in the prompt |
| `dead` + real exit status | the kernel, via tmux | `#{pane_dead}`, `#{pane_dead_status}` |
| `silent for N` | tmux | `monitor-silence` → `#{window_silence_flag}` |
| `working` | the agent | `hark progress` |
| `blocked` | the harness | *not implemented* — needs a `Notification` hook shim |

Compare herdr's `src/detect`: 4,492 lines plus 20 date-versioned TOML manifests
of regexes over spinner glyphs and permission-prompt copy, because it has no
contract with any of it.

## Status

Proven by `test.sh` (all pass), stub publisher:

- agent-declared exit code 0 and 2 both propagate through withdone to
  `#{pane_dead_status}` and to the right frame kind (`reply` / `error`)
- the frame carries the originating `:thread`
- a non-compliant agent (finishes, never writes the sentinel) is surfaced as
  `silent` rather than silently counted as working
- a completed job emits no spurious silent/pane-died frames afterwards

**Not proven:** the hark half. `HERD_PUBLISH=stub` swaps `hark` for an
append-only log, and the tests run in that mode, so `hark init/recv/reply/error`
and the CBCL forms are exercised only against the local config's CLI contract —
never against a hub. Validating that needs a hub: either the live one (the local
config points at `wss://chat.anuna.io/chat/v1`, which means joining a real
channel) or a local boot via `cbcl-bus`'s existing e2e harness. Until then the
wire half is a design, not a result.

## Two findings worth keeping

**1. tmux alert hooks are useless to a headless supervisor.** `alert-silence`
is a *session* hook, and tmux raises alerts through attached *clients*. A
detached session has no client, so the hook never fires — while
`#{window_silence_flag}` is set perfectly correctly the whole time. `set-hook -p`
also accepts `alert-silence` without complaint and does nothing. The fix is to
poll the flag (`herd watch`, running in its own tmux window). `pane-died` is a
genuine pane hook and does fire detached.

**2. tmux windows inherit the tmux *server's* environment, not the caller's.**
Anything a worker needs must be forwarded with `new-window -e`. Hence
`HERD_PASS_ENV`. This bit the test suite first: `FAKE_MUTE=1` never reached the
pane, so the "non-compliant agent" case was silently testing a compliant one and
passing for the wrong reason.

Minor: `monitor-silence` must exceed withdone's SIGTERM grace, or every
successful job reports `silent` during the kill window. `herd note` treats
`done` as terminal to absorb this.

## Next

- `blocked`: a Claude Code `Notification` hook posting to the daemon →
  `(ask @human …)`, so blocked falls out of the thread store with no new state
- run it against a hub, which is the only way the `:thread` correlation and
  at-least-once `recv` dedup get tested for real
- `hark done <code>` so the completion is a *signed* frame; a sentinel file is
  an unauthenticated claim, fine on one box, not fine as a fact on the bus
