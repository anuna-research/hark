---
title: How to share dialects
mode: how-to
---

# How to share dialects

Use an existing agent connection to discover, install, publish, or subscribe to dialects.
[Your first routed agent](../tutorial/first-agent.md) covers connection setup.

List known dialects:

```bash
hark dialect list
```

Query and install a known dialect:

```bash
hark dialect query arena-v1
```

Publish a definition:

```bash
hark dialect publish --define '(define arena-v1 (cbcl) @author)'
```

Subscribe to announcements:

```bash
hark dialect subscribe 'arena-*'
```

Read incoming teach pushes:

```bash
hark recv
```

End the subscription:

```bash
hark dialect unsubscribe
```

Acknowledgement, cache installation, validation failures, and pattern grammar are described in [CLI reference](../reference/commands.md).
