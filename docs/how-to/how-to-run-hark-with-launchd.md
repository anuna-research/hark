---
title: How to run hark with launchd
mode: how-to
---

# How to run hark with launchd

To keep the daemon running across logins, supervise `hark daemon run` with a per-user LaunchAgent.
Put router settings in the config file through [How to configure hark](how-to-configure-hark.md).
[Daemon supervision](../explanation/about-hark.md#daemon-supervision) explains foreground operation, runtime paths, and environment inheritance.

If you started the daemon by hand, run `hark daemon stop` before loading the LaunchAgent.

Write the agent (the substitutions fill in your real binary path and home):

```bash
mkdir -p ~/Library/LaunchAgents ~/Library/Logs/hark
cat > ~/Library/LaunchAgents/io.anuna.hark.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.anuna.hark</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(command -v hark)</string>
    <string>daemon</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$HOME/Library/Logs/hark/daemon.out.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/Library/Logs/hark/daemon.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>hark=info</string>
  </dict>
</dict>
</plist>
EOF
```

Load and start it (macOS 11+):

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.anuna.hark.plist
launchctl kickstart gui/$(id -u)/io.anuna.hark
hark daemon status        # confirm it is up
```

`init`, `join`, `recv`, and the rest then discover the launchd-started daemon
normally. Manage the daemon through launchd.
To stop it, use `launchctl bootout`; `KeepAlive` restarts a daemon stopped through `hark daemon stop`:

```bash
launchctl print gui/$(id -u)/io.anuna.hark            # status + last exit code
launchctl kickstart -k gui/$(id -u)/io.anuna.hark     # restart (e.g. after a config change)
launchctl bootout gui/$(id -u)/io.anuna.hark          # stop and unload
tail -f ~/Library/Logs/hark/daemon.err.log            # logs (tracing writes to stderr)
```

On macOS 10 the equivalents are `launchctl load -w
~/Library/LaunchAgents/io.anuna.hark.plist` and `launchctl unload -w …`.

> Linux: run the same `hark daemon run` under a systemd **user** service
> (`systemctl --user`). There the runtime dir follows `XDG_RUNTIME_DIR`, which
> systemd already sets to match your interactive shell.
