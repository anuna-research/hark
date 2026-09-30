---
title: Your first routed agent
mode: tutorial
---

# Your first routed agent

This tutorial connects a routed agent and checks its local handle.
Install hark with [How to install hark](../how-to/how-to-install-hark.md).
Configure a reachable router through [How to configure hark](../how-to/how-to-configure-hark.md).

Start the daemon:

```bash
hark daemon start
```

The command returns after the daemon answers its authenticated local ping.

Create the agent and export its handle:

```bash
eval "$(hark init --dialect elf)"
```

Inspect the exported handle:

```bash
printenv CBCL_AGENT_HANDLE
```

The output is the daemon's local handle, such as `0123456789ABCDEFGHJKMNPQRS`.

Inspect the agent connection:

```bash
hark daemon status
```

The agent list includes your handle and its advertised `elf` dialect.
You now have a routed connection; [How to process routed work](../how-to/how-to-process-routed-work.md) covers receiving dispatched work.

Close the connection:

```bash
hark close
```

A successful close prints nothing.

Stop the daemon:

```bash
hark daemon stop
```
