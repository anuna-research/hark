# elf:ticket Agent Contract

You are handling CBCL asks routed through `cbcl-lfe-router` for capability
`elf:ticket`.

The caller starts `hark` before launching you. Assume the daemon is already
running and `CBCL_AGENT_HANDLE` is already set, for example by:

```bash
eval "$(hark init --dialect elf --capability elf:ticket)"
```

Do not run `hark init` yourself. Use the existing agent handle with `hark recv`,
`hark progress`, `hark reply`, and `hark error`.

## Input

Wait for work with:

```bash
hark recv
```

Expected ask shape:

```lisp
(lang elf
  (ask @router "ticket"
    :text "BGOV-123"
    :user "@slack:U123"
    :thread "rcp-ABCDEF"))
```

Interpret the `:text` value as the JIRA ticket id. The router-provided
`:thread` value is the receipt id for all progress and terminal messages.

If the ask is malformed, missing `:text`, missing `:thread`, or the ticket id is
not a `BGOV-<number>` id, send a terminal error rather than guessing.

## Workflow

1. Extract the ticket id and thread id from the CBCL ask.
2. Fetch the ticket details:

   ```bash
   bgov issues show BGOV-123
   ```

3. Treat the current working directory as the workspace root. Relevant
   repositories are available somewhere beneath this directory.
4. Identify the target repository from the ticket details and local workspace.
   If the repository is ambiguous or unavailable, stop with a useful terminal
   error.
5. In the target repository, inspect the current branch and worktree before
   making changes. Do not overwrite or discard unrelated local changes.
6. Create a new branch with a clear ticket-derived name, for example:

   ```bash
   git checkout -b bgov-123-short-description
   ```

7. Implement the requested work.
8. Run the relevant tests, linters, or checks for the changed project.
9. Push the branch.
10. Create a GitLab merge request with `glab`.
11. Complete with a reply containing the merge request URL, or complete with an
    error explaining what blocked completion.

## Merge Request Creation

When creating the GitLab merge request, take care to pass the description as
real multiline Markdown. Do not pass a description containing literal `\n`
escape sequences, JSON-escaped text, or a single long shell-escaped string.

Prefer writing the body to a temporary Markdown file with a quoted heredoc, then
passing the file contents to `glab`:

```bash
mr_description="$(mktemp)"
cat > "$mr_description" <<'EOF'
## Summary

- Describe the user-visible change.
- Mention any important implementation detail.

## Tests

- `cargo test`
EOF

glab mr create \
  --title "BGOV-123: short description" \
  --description "$(cat "$mr_description")" \
  --yes
```

Before running `glab mr create`, verify that the rendered description source
contains actual blank lines, Markdown headings, and bullet lines. If the preview
shows backslash-n text such as `\n## Tests`, rebuild the description before
creating the merge request.

## Progress

Send progress at major milestones using the original thread id:

```bash
hark progress --thread "$THREAD" --text "Fetched BGOV-123"
hark progress --thread "$THREAD" --text "Identified repository anuna/example"
hark progress --thread "$THREAD" --text "Created branch bgov-123-short-description"
hark progress --thread "$THREAD" --text "Running tests"
```

Progress messages are useful for Slack forwarding, but they do not complete the
router receipt. Always finish with exactly one terminal `hark reply` or
`hark error`.

## Success

On success, send a terminal reply with the original thread id. Include both a
human-readable `:text` field and a machine-readable `:pr-url` field.

```bash
hark reply '(lang elf (reply @router "ok" :thread "'"$THREAD"'" :text "Completed BGOV-123: https://gitlab.com/anuna/example/-/merge_requests/123" :pr-url "https://gitlab.com/anuna/example/-/merge_requests/123"))'
```

## Failure

If you cannot complete the task, send a terminal error with a specific reason
and any useful next action.

```bash
hark error '(lang elf (error @router "failed" :thread "'"$THREAD"'" :text "Could not identify the target repository for BGOV-123 from the ticket details"))'
```

Use a terminal error for blockers such as missing repository access, missing
ticket access, ambiguous requirements, failing required checks that you cannot
resolve, inability to push, or inability to create a merge request.

## Operating Rules

- Do not start or initialize `hark`; use the existing `CBCL_AGENT_HANDLE`.
- Do not invent a new thread id.
- Preserve the router-provided `:thread` value on every progress, reply, and
  error message.
- Do not silently stop after partial work.
- Prefer small, focused changes that address the ticket directly.
- Use the local project's existing build, test, formatting, and contribution
  conventions.
- Do not discard unrelated local changes.
- If completion is blocked, report the blocker with `hark error`.
