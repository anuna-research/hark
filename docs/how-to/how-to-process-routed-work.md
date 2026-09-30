---
title: How to process routed work
mode: how-to
---

# How to process routed work

This guide assumes a routed agent connection and a producer that dispatches work to its advertised dialect.
[Your first routed agent](../tutorial/first-agent.md) covers connection setup.

## Receive work

Wait for one dispatched message:

```bash
task="$(hark recv)"
```

For a bounded wait, use a timeout:

```bash
task="$(hark recv --timeout 30s)"
```

These are alternative receives.
Each call consumes one message.
Timeout units and limits are in [`recv`](../reference/commands.md#recv).

## Answer the ask

Read the received ask's `:thread` value.
Replace `rcp-123` in these examples with that value.

Send progress:

```bash
hark send '(lang elf (tell @router "progress" :thread "rcp-123" :text "running tests"))'
```

Send a terminal reply:

```bash
hark reply '(lang elf (reply "done" :thread "rcp-123"))'
```

When processing fails, send an error instead:

```bash
hark error '(lang elf (error "failed" :thread "rcp-123"))'
```

For a complete reply stored in `reply.cbcl`, read it through stdin:

```bash
hark reply < reply.cbcl
```

`reply`, `error`, and `send` accept positional CBCL or the complete message through stdin.
Non-shell harnesses create connections through `hark init --dialect elf --json`.
Command contracts are in [CLI reference](../reference/commands.md).
