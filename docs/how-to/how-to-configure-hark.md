---
title: How to configure hark
mode: how-to
---

# How to configure hark

This guide sets the router URL and daemon configuration.

Locate the platform config file:

```bash
hark config path
```

Print a sample config:

```bash
hark config show-example
```

Create the config file if it does not already exist:

```bash
hark config init
$EDITOR "$(hark config path)"
```

Set the router URL in the config file.
The keys, precedence, and environment overrides are listed in [Configuration](../reference/configuration.md).

After changing configuration, restart the daemon:

```bash
hark daemon stop
hark daemon start
```

For a supervised daemon, follow [How to run hark with launchd](how-to-run-hark-with-launchd.md).
