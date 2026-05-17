#!/usr/bin/env bash
#
# demo-agent.sh — LangSec 2026 demo agent for the cbcl-cli dialect.
#
# Loops:  hark recv  ->  cbcl-cli parse | jq  ->  bounded shell  ->  hark reply.
#
# The dialect (cbcl-rs/dialects/cli.cbcl) enumerates the eight read-only
# performatives this agent will respond to. Out-of-dialect performatives
# are rejected by the recogniser upstream of this script; the case
# statement below is a defence-in-depth safety net, not the primary gate.
#
# Prerequisites:
#   - hark daemon running, agent initialised with --dialect cbcl-cli
#   - cbcl-cli and jq on PATH
#   - CLI_DEMO_REPOS set to a colon-separated allowlist of git-log paths
#     (e.g. CLI_DEMO_REPOS=cbcl-rs=/home/hugo/Code/cbcl-rs:hark=/home/hugo/Code/hark)
#   - CLI_DEMO_ALLOWED_PREFIX overrides the path allowlist used by ls/cat.
#     Defaults to /home/hugo/Code. On macOS the host path is typically
#     /Users/<user>/Code, so export accordingly.

set -euo pipefail

# --- bounded path allowlist for ls/cat -------------------------------------
#
# Anything outside this prefix gets rejected with exit 1 in the reply.
# The recogniser will not let an out-of-dialect performative through;
# this is the second wall, against in-dialect requests that name paths
# outside the demo's intended scope.

readonly ALLOWED_PREFIX="${CLI_DEMO_ALLOWED_PREFIX:-/home/hugo/Code}"
readonly CAT_MAX_BYTES=8192
readonly GIT_LOG_MAX_N=20

# --- helpers ---------------------------------------------------------------

# Normalise a path and verify it falls inside ALLOWED_PREFIX. Returns the
# resolved path on stdout; returns non-zero if the path is empty, escapes
# the allowlist via `..` segments, or is a sibling whose name happens to
# start with the prefix string (e.g. "/foo/Codeextra" against "/foo/Code").
#
# realpath -m resolves relative segments without requiring the target to
# exist, so we can reject path-traversal attempts even when the resolved
# path doesn't name a real file.
resolve_under_prefix() {
    local raw=$1
    [[ -z $raw ]] && return 1

    # Only absolute paths are accepted. Relative paths would otherwise
    # be resolved against the agent's cwd, which is implementation
    # detail and not part of the dialect's contract.
    [[ $raw == /* ]] || return 1

    local resolved
    if ! resolved=$(realpath -m -- "$raw" 2>/dev/null); then
        return 1
    fi

    # Match either the prefix exactly or anything strictly beneath it.
    # The trailing "/" anchor stops "Codeextra" matching "Code".
    if [[ $resolved == "$ALLOWED_PREFIX" || $resolved == "$ALLOWED_PREFIX"/* ]]; then
        printf '%s' "$resolved"
        return 0
    fi
    return 1
}

# CBCL string escape: backslash and double-quote.
escape_cbcl_string() {
    local s=${1//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

# Build a core CBCL (reply ...) carrying structured content. The dialect
# describes only requests; replies use CBCL core so they pass hark's
# kind validation (MessageKind::Reply -> CorePerformative::Reply).
# The inbound :thread is echoed back so the router correlates the
# response with the originating receipt.
build_reply() {
    local stdout=$1 stderr=$2 exit_code=$3 thread=$4
    local host_time
    host_time=$(date -Iseconds)

    local thread_clause=""
    if [[ -n $thread && $thread != "null" ]]; then
        thread_clause=" :thread \"$(escape_cbcl_string "$thread")\""
    fi

    cat <<EOF
(reply (list :stdout "$(escape_cbcl_string "$stdout")"
             :stderr "$(escape_cbcl_string "$stderr")"
             :exit-code $exit_code
             :host-time "$host_time")$thread_clause)
EOF
}

# Reject in-dialect requests that escape the bounded scope. Returns an
# exit-1 cli-result rather than crashing the loop.
reject() {
    local reason=$1 thread=$2
    build_reply "" "$reason" 1 "$thread"
}

# Resolve a logical repo name to an absolute path via CLI_DEMO_REPOS.
resolve_repo() {
    local name=$1
    local entry
    IFS=':' read -r -a entries <<< "${CLI_DEMO_REPOS:-}"
    for entry in "${entries[@]}"; do
        if [[ $entry == "${name}="* ]]; then
            printf '%s' "${entry#*=}"
            return 0
        fi
    done
    return 1
}

# --- performative dispatch -------------------------------------------------
#
# Each branch shells out to a strictly bounded command, captures stdout +
# exit code, and emits a reply via build_reply. No branch shells out via
# `eval` or composes a string into a shell command — every external call
# uses array argv form so user-supplied strings cannot inject flags.

dispatch() {
    local parsed=$1
    local perf content params thread
    perf=$(jq -r '.Dialect.inner.Simple.performative.Custom // empty' <<< "$parsed")
    thread=$(jq -r '.Dialect.inner.Simple.thread // empty' <<< "$parsed")
    content=$(jq -r '.Dialect.inner.Simple.content.Atom.Str // empty' <<< "$parsed")
    params=$(jq -c '.Dialect.inner.Simple.params // []' <<< "$parsed")

    local stdout stderr=""
    local exit_code=0

    case "$perf" in
        ls)
            local path
            if ! path=$(resolve_under_prefix "$content"); then
                reject "path outside allowlist: ${content}" "$thread"
                return
            fi
            stdout=$(ls -1 -- "$path" 2>&1) || exit_code=$?
            ;;

        cat)
            local path bytes_max
            bytes_max=$(jq -r '.[0].Atom.Num // 0' <<< "$params")
            if ! path=$(resolve_under_prefix "$content"); then
                reject "path outside allowlist: ${content}" "$thread"
                return
            fi
            if (( bytes_max <= 0 || bytes_max > CAT_MAX_BYTES )); then
                bytes_max=$CAT_MAX_BYTES
            fi
            stdout=$(head -c "$bytes_max" -- "$path" 2>&1) || exit_code=$?
            ;;

        localtime)
            # The visual punchline: ISO 8601 with offset (e.g. +10:00 for
            # AEST) plus the resolved IANA tz name. The audience sees the
            # timezone in the reply and knows the message reached Sydney.
            # The :format keyword arg is accepted but the only supported
            # format is "iso8601" — extra space for future formats without
            # breaking the dialect.
            local iso tz
            iso=$(date -Iseconds 2>/dev/null || date "+%Y-%m-%dT%H:%M:%S%z")
            tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*zoneinfo/||')
            stdout="${iso} ${tz}"
            ;;

        git-log)
            local repo_name=$content
            local n
            n=$(jq -r '.[0].Atom.Num // 0' <<< "$params")
            local repo_path
            if ! repo_path=$(resolve_repo "$repo_name"); then
                reject "unknown repo: ${repo_name}" "$thread"
                return
            fi
            if (( n <= 0 || n > GIT_LOG_MAX_N )); then
                n=$GIT_LOG_MAX_N
            fi
            stdout=$(git -C "$repo_path" log --oneline -n "$n" 2>&1) || exit_code=$?
            ;;

        *)
            # Defence in depth. In a fully R5-enforcing pipeline the
            # recogniser at the router rejects out-of-dialect performatives
            # before they reach the agent. Today's deployed router has
            # R5 stubbed (see cbcl-router/docs/status.md), so this branch
            # is the rejection point in practice.
            stderr="performative not in cbcl-cli dialect: ${perf}"
            exit_code=2
            stdout=""
            ;;
    esac

    build_reply "$stdout" "$stderr" "$exit_code" "$thread"
}

# --- main loop -------------------------------------------------------------

main() {
    echo "demo-agent: ready; waiting for cbcl-cli messages" >&2
    while true; do
        local msg
        if ! msg=$(hark recv --timeout 60s 2>/dev/null); then
            # Recv timeout or daemon hiccup. systemd Restart=always handles
            # daemon death; transient recv failures just loop.
            continue
        fi
        if [[ -z $msg ]]; then
            continue
        fi

        local parsed
        if ! parsed=$(printf '%s' "$msg" | cbcl-cli parse 2>/dev/null); then
            echo "demo-agent: parse failed for inbound message" >&2
            continue
        fi

        local perf
        perf=$(jq -r '.Dialect.inner.Simple.performative.Custom // "?"' <<< "$parsed")
        echo "demo-agent: handling ${perf}" >&2

        local reply
        reply=$(dispatch "$parsed")

        if ! printf '%s' "$reply" | hark reply 2>/dev/null; then
            echo "demo-agent: hark reply failed" >&2
        else
            echo "demo-agent: replied (${perf})" >&2
        fi
    done
}

main "$@"
