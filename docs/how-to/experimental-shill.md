# Experimental CBCL capability executor

`hark shill` is a Shill-inspired experiment in deriving local authority from admitted
CBCL requests. It runs in its own CLI process beside the Hark daemon. It uses native
cbcl-rs admission, immutable read snapshots and a closed Rust effect type. It is not
a port of Harvard Shill, a new CBCL language primitive, or a formally verified host
security boundary.

## Try it

Build this checkout (`cargo build`). `definition` and `check` require no daemon:

```sh
target/debug/hark shill definition > /tmp/shill-definition.json
target/debug/hark shill check --manifest examples/shill/manifest.json
```

The generated definition is a real version-3 object contract, compiled and verified
by the same cbcl-rs revision as Hark's object runtime. Its fields use existing string
and number shapes; the host resolves resource/program IDs into private typed values.
No hypothetical `(capability ...)` or `(enum ...)` grammar is introduced.

Edit the manifest's controller, worker, room, hub and provenance to match dedicated
Hark agents joined with `--objects`. Resource paths are local configuration, relative
to the manifest. The worker loads at most 32 regular UTF-8 files, each at most 32 KiB,
into memory at startup. A later pathname or symlink change cannot redirect a remote
read. These files and all fixed program code must be trusted at startup.

For an existing MLS room, pair the two agents, then start the worker:

```sh
target/debug/hark --agent @shill-worker shill serve \
  --manifest examples/shill/manifest.json --journal /tmp/shill-private-journal
```

On macOS, `manifest-macos.json` supplies a fixed `/bin/echo` operation and public-room
configuration. Start from dedicated public agents:

```sh
target/debug/hark join @shill-demo --as @shill-controller --objects
target/debug/hark join @shill-demo --as @shill-worker --objects
target/debug/hark --agent @shill-worker shill serve \
  --manifest examples/shill/manifest-macos.json \
  --journal /tmp/shill-private-journal --allow-public
```

`serve` validates the selected worker and opens a worker-authored announcement object
(`shill-offer-...`). This publishes the exact dialect through Hark's control path,
including in MLS rooms. The announcement grants no effect. The worker prints one JSON
readiness record; copy its fresh `session` value. The same epoch marker is visible in
the announcement object's `session` state. In another terminal:

```sh
target/debug/hark --agent @shill-controller object open \
  --define /tmp/shill-definition.json --thread shill-read-1 \
  --field session=PASTE_THE_LIVE_SESSION_VALUE
target/debug/hark --agent @shill-controller object act shill-read-1 read '{"resource":"readme"}'
target/debug/hark --agent @shill-controller recv --follow
```

Each effect needs a fresh thread and opener. For the macOS program example:

```sh
target/debug/hark --agent @shill-controller object open \
  --define /tmp/shill-definition.json --thread shill-run-1 \
  --field session=PASTE_THE_LIVE_SESSION_VALUE
target/debug/hark --agent @shill-controller object act shill-run-1 run '{"program":"hello"}'
```

To expose the existing count demo, build its native binary and add this local
binding under `programs`, replacing the absolute path:

```json
"count": {
  "executable": "/absolute/path/to/cbcl-rs/target/release/examples/count-to-one-hundred",
  "arguments": ["--messages", "--direct"],
  "timeout_ms": 3000,
  "max_output_bytes": 32768,
  "memory_mb": 256
}
```

Restart the worker and open a fresh thread using its new session marker. The
request is `run {"program":"count"}`. Arguments come exclusively from the local
binding. Generic output currently concatenates stdout followed by stderr; it does
not preserve their original interleaving or expose a PTY.

`read {"resource":"../../secret"}`, undeclared `exec`, extra `path` fields,
wrong senders and historical records cannot authorize effects. Refusals are
logged to stderr; the experiment does not send a diagnostic to an untrusted request.
The old browser demo uses a different dialect and is not automatically migrated.

## Constrained caller arguments

`run` retains fixed argv. A separate `invoke` action carries an `arguments` list,
whose positions must match the local program's parameter schema exactly. The macOS
example now includes `/bin/ls`, with these grants:

```json
"directories": { "docs": "demo-docs" },
"programs": {
  "ls": {
    "executable": "/bin/ls",
    "arguments": [],
    "parameters": [
      { "kind": "enum", "values": { "-1": ["-1"], "-l": ["-l"] } },
      { "kind": "directory", "allow": ["docs"] }
    ],
    "timeout_ms": 1000,
    "max_output_bytes": 4096,
    "memory_mb": 256
  }
}
```

After opening a fresh thread with the current session:

```sh
target/debug/hark --agent @shill-controller object act shill-ls-1 invoke \
  '{"program":"ls","arguments":["-l","docs"]}'
```

The host resolves `-l` to its fixed argv fragment and `docs` to an immutable
directory snapshot. It copies that snapshot to a private `grants/arg-1` directory
inside the child cwd. The child can read it, but the sandbox denies writes to the
grants subtree. Unselected grants never enter the child. `/etc`, `../secret`, shell
substitutions, unlisted flags and extra/missing/non-string arguments are rejected
before execution. No shell is used for argv construction.

A terminal facade can therefore translate `ls -l docs` directly into that request,
and supply `-1` as the default for `ls docs`. The existing slide terminal has not
been wired to this dialect. The prototype supports enum choices and directory IDs;
it does not yet support unrestricted strings, integer ranges or relative paths
within a grant. Directories are snapshots, not live mounts: at most eight grants,
256 total entries, depth four, 32 KiB per file and 1 MiB total. Symlinks and special
files are refused. File contents and names are copied; listing timestamps and
permissions describe the materialized copy, not a faithful host metadata snapshot.

## Enforcement path

```
dedicated Hark recv queue (trusted local daemon)
  -> exact signer + room + provenance + fresh-record checks
  -> native CBCL parse/admit of the generated fixed dialect
  -> live-session opener and local resource/program allowlist
  -> private Effect::Read(snapshot) / Effect::Run(fixed program) / Effect::Invoke(bound arguments)
  -> atomic durable one-effect-per-thread claim
  -> snapshot copy / sandboxed child
  -> native CBCL intend -> Hark signed send of output/done
```

Missing causal evidence is buffered as Unknown (up to 32 requests, 8 KiB each), then
retried when its opener arrives. Invalid or unauthorized acts never yield an effect.
Each run accepts at most 1024 opens/commands, expires within one hour (15 minutes in
the examples), and enforces at least 100 ms between newly issued effects. There is
one serial worker and one locked private journal. Duplicate or competing commands on
the same thread cannot bypass the claim. The claim is flushed before the effect;
completion is flushed before network output. A crash leaves an uncertain claim and
never causes automatic re-execution. Results are not cached or retransmitted, so
delivery can be lost despite successful execution. This is at-most-once claiming,
not exactly-once distributed effects. Journal claims are bounded by the configured
command quota across restarts; stop and explicitly rotate the journal to reset it.

## Child sandbox

External programs currently work only on macOS with `/usr/bin/sandbox-exec`; all
other platforms reject manifests containing programs. Snapshot reads work on Unix.
There is no unsandboxed fallback. A locally configured program has a canonical
absolute executable and fixed argv prefix. `invoke` appends only fragments selected
from the declared parameter schema and materialized directory grants. The executor
clears the environment, uses an empty temporary home/cwd and null stdin, captures
UTF-8 stdout/stderr with a combined byte bound, and applies CPU, file-size,
descriptor, process-count and core-dump limits. A parent-side macOS physical-memory
watcher samples every 10 ms and kills the child when its budget is exceeded. This
is a sampled budget, not a hard allocation ceiling: a brief spike can overshoot it.

The generated Seatbelt profile denies access by default. It allows the selected
executable, OS runtime libraries, the root directory itself (required by dyld),
a few system metadata/random-device paths and its
private scratch directory. Network, user files, unrelated execution and writes
outside scratch are denied. Forking additional processes is denied in this first
version; this prevents descendants from escaping the supervised process group.
The profile grants specific library subtrees, never all of `/System`: that would
also cover `/System/Volumes/Data`, an alternate path to writable host files.
Executables with
additional dylib or service requirements fail closed; there is no configurable raw
profile escape hatch. Shell scripts are not a supported executable binding.

The wall-clock deadline covers process exit and pipe EOF, and kills the whole child
process group with SIGKILL on timeout/output overflow/cancellation. Surviving children
are killed even after a normally exiting parent. Ctrl-C cancels the worker and its
active child group; SIGTERM does the same. The durable claim remains spent/uncertain.
An uncatchable parent SIGKILL or host crash cannot run that cleanup; any surviving
child remains sandboxed, but its parent-side wall-clock and memory watchers are lost.
Use external process supervision or a disposable VM for stronger crash containment.

`sandbox-exec`/Seatbelt is a platform-specific experimental backend. The parent Hark
CLI retains its user's authority, and the local daemon/token, admission code,
manifest, executor, journal and OS remain trusted. This does not isolate bugs in the
parent native parser. Local processes able to modify executables or private state
are outside this threat model. The program binary can change on disk between
configuration and exec; use immutable, trusted binaries. For stronger separation,
run the worker under a dedicated user or disposable VM.

Public rooms require `--allow-public`, trust the hub for identity and expose all
output. The fresh session value prevents cross-run reuse; it is an epoch marker,
not a bearer secret, and does not replace sender authentication. Files remain local
unless a granted read is exercised. Stop the worker after a presentation.

## Relationship to Harvard Shill

The reference is [HarvardPL/shill](https://github.com/HarvardPL/shill), especially
`examples/grading/grade.cap`, `rt/sandbox.c`, `sandbox/yacc.y` and the FreeBSD
`kmod/*_checks.c` policies. Shill separates ambient acquisition from capability-safe
execution and extends rights to legacy programs through kernel enforcement. This
experiment applies that separation to authenticated causal requests and uses a
small closed executor with a macOS sandbox. In Shill's `racket/private/filesystem.rkt`,
`exec` accepts strings, file capabilities and directory capabilities. It converts
resource arguments to paths and includes their rights in the child's sandbox; a
string alone grants no filesystem rights. Our enum and snapshot parameters are a
deliberately smaller analogue. No upstream code is copied. It does not
implement Shill's general scripting language, capability wallets, directory rights,
delegation, revocation, arbitrary pipelines or FreeBSD MAC module.

An accepted message is only part of authorization: the local manifest pins the
subject, operations and resources. Content hashes identify evidence; public hashes
are not unforgeable bearer capabilities. One-use enforcement is local and durable;
multiple hosts executing the same thread need a separate ownership/coordination
policy. No claim is made that replicas enforce a global use count without it.

Tests: `cargo test --lib shill::`. The local API integration test exercises actual
native admission, snapshot execution, response binding and duplicate refusal. macOS
tests run real sandboxed programs, probe denied reads/writes, environment inheritance,
output bounds and a program that ignores TERM. These tests do not establish a proof
of confinement or deployed transport security.
