# eTraceReplay

A per-PID syscall/socket tracer built on eBPF (CO-RE via `cilium/ebpf` + `bpf2go`), with a
`bubbletea` TUI, that can record a traced HTTP request and its Redis dependencies as a
replayable YAML test case. This is Milestones 1–4 of a larger eBPF traffic-recording
project — see [Roadmap](#roadmap) for what's deliberately not built yet.

Build notes, bugs, and gotchas encountered along the way (kept for a future write-up, not
part of this reference doc) are in [`NOTES.md`](NOTES.md).

## What this does

Given a PID, `etrace trace` attaches BPF tracepoints on `connect`, `write`, `read`, and
`close`, scoped **in-kernel** to that one process (a `target_pid` rodata constant checked
at the top of every probe — tracing is never system-wide), and streams the decoded events
either to a live terminal UI or as plain text.

```
sudo ./etrace trace --pid <pid>            # interactive TUI (default)
sudo ./etrace trace --pid <pid> --no-tui   # plain-text stream
sudo ./etrace record --pid <pid> -o test.yaml   # record one HTTP request + Redis deps as YAML
```

The TUI has three tabs (`Tab` to cycle, `q` to quit): **Events** is the flat, timestamped
syscall log; **Connections** groups them by `(pid, fd)` into one row per socket lifecycle —
remote endpoint, cumulative bytes out/in, and open/closed state, updating in place rather
than appending as new activity arrives on that socket; **HTTP** shows one row per decoded
HTTP request/response pair — method, path, status, a body preview, and whether the capture
was truncated (Redis traffic doesn't get a TUI tab — see Architecture).

`etrace record` runs until `Ctrl-C`, then writes a YAML test case built from what it saw
during that window — matching the guide's schema:

```yaml
test:
    name: recorded-test
request:
    method: POST
    path: /users
    body:
        name: Alice
dependencies:
    - type: redis
      request: set user:42 Alice
      response: OK
response:
    status: 201
    body:
        id: 42
        name: Alice
```

Root (or `CAP_BPF`+`CAP_PERFMON`) is required to load BPF programs.

## Building

Requires: Go 1.21+, clang/llvm, `libbpf-dev`, `bpftool`, and kernel BTF
(`/sys/kernel/btf/vmlinux` must exist). `etrace record`'s Redis decoding only needs a Redis
instance at trace time (e.g. `redis-server --save "" --appendonly no`, stopped again after
— this project doesn't install or run Redis as a standing service), not to build or test.

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
make build     # regenerates BPF bindings (bpf2go) and builds ./etrace
make test      # unit + headless TUI tests, no root required
```

`bpf/vmlinux.h` is machine-generated and gitignored — regenerate it on whatever box you're
building on.

## Architecture

Library-core, thin-consumer: `internal/collector` loads the BPF program, attaches the
tracepoints, and publishes decoded `Event`s on a Go channel. It never touches a terminal.
`internal/printer` (`--no-tui`) consumes that channel directly. In TUI mode, events flow
through a chain of stages, each the *sole* consumer of the previous stage's channel — Go
channels deliver each value to exactly one receiver, so fanning one channel out to multiple
independent consumers isn't an option — and each owning further output channels of its own:

```
collector.Event  --->  correlator.Run  --->  streamer.Run  --->  tui.Run
                        (raw passthrough,      (raw passthrough,
                         Connection stream)      Exchange stream)
```

`internal/correlator` groups events into `Connection` snapshots (feeding the Connections
tab). `internal/streamer` buffers each `(pid, fd)`'s read/write bytes and, on close (or when
the trace ends — see below), content-sniffs both directions, trying each protocol
`internal/decoder` supports in turn and keeping whichever parses. Every stage still forwards
the raw event stream unchanged, which is what keeps the Events tab working all the way
through the chain. This layering is also what makes the TUI testable headlessly with
`teatest` (`internal/tui/tui_test.go`): every tab consumes a plain channel, so tests inject
synthetic values instead of driving a live trace.

`internal/decoder` owns protocol semantics as pure functions over byte slices — no
channels, no lifecycle — so streamer stays responsible only for buffering. `TryHTTP` tries
**both** role assignments (read=request/write=response for a traced HTTP server; the
inverse for a traced client) and keeps whichever parses; `TryRESP` decodes a RESP2 command
stream, pairs each command with its reply positionally, and filters out connection-setup
commands (`HELLO`, `CLIENT`, `AUTH`, `SELECT`, `PING`) so a recorded dependency reflects the
application's actual Redis usage, not the client library's handshake chatter. Neither
decoder needs `accept()` tracking to identify a traced server's inbound sockets: streamer
buffers every fd's bytes regardless of how the socket was established, and content alone
determines what protocol (if any) it's carrying.

`etrace record` chains `collector → streamer` directly (it needs the `Exchange` stream, not
the TUI's `Connection` view) and calls `internal/recorder.Build` on everything the streamer
decoded during the trace: the first HTTP exchange observed becomes the recorded
request/response, every Redis call across every Redis exchange becomes a dependency, in
order. No time-window matching is needed to tell "the request" from "its dependencies" —
protocol type alone separates them, which is enough at this project's single-request-at-a-
time scope (see Known limitations). `internal/storage` is a deliberately generic YAML
read/write helper with no knowledge of the `TestCase` shape.

Streamer decodes on `close()`, or on whatever's still buffered when the trace ends —
added for `etrace record`, since connection-pooling clients like `go-redis` never call
`close()` on a connection they intend to reuse. Without this, Redis traffic would be
captured perfectly on the wire and then silently produce nothing.

`read()` is captured as an entry+exit pair: the buffer isn't populated until the syscall
returns, so `sys_enter_read` stashes `{buf, fd}` in a BPF hash map keyed by `pid_tgid`, and
`sys_exit_read` reads the buffer using the real return length. `write()`, `connect()`, and
`close()` are single-probe (`sys_enter_*` only).

The correlator identifies a connection by a monotonic `Seq` assigned at `connect()` time,
not just `(pid, fd)` — the kernel reuses fd numbers, so a second connection on a recently
freed fd must not merge its byte counts or endpoint into the previous connection's row.

## Known limitations (v1)

- Only `AF_INET` (IPv4) `connect()` addresses are decoded; other address families report a
  zero address rather than misdecoding.
- Captured payload content is truncated to 4096 bytes *per syscall event* (`Event.Truncated()`
  reports when this happened); byte-count totals (Connections tab, `total_len`) are accurate
  regardless, since they come from the syscall's true return value / requested count, not
  the capture cap.
- Only `connect`/`write`/`read`/`close` are traced — not `recv`/`send`/`accept` (some
  runtimes, e.g. CPython's `socket` module, use `recv`/`recvfrom` rather than `read`, so
  their socket reads won't appear as Out/In bytes in the Connections tab; plain `read()` on
  files and pipes will).
- The correlator (Connections tab) only tracks sockets *this process* called `connect()`
  on (the client role) — a traced server's accepted sockets won't show up there. The
  streamer (HTTP tab) doesn't have this limitation, since it doesn't need `connect()`/
  `accept()` at all; it content-sniffs whatever bytes flow on any fd.
- A process that dies without calling `close()` (e.g. killed) leaves its connections shown
  as still-open in the Connections tab (the correlator only reacts to `close()`; not worth
  adding `sched_process_exit`-based cleanup yet — tracked state per connection is small).
  The streamer doesn't have this gap: it decodes on `close()` *or* when the trace ends,
  whichever comes first (see below), so an in-flight/pooled connection is still decoded.
- The streamer buffers up to 64KB per direction per connection; bytes beyond that are
  silently dropped from the buffer (separately from, and in addition to, the per-event 4096
  byte capture cap above).
- Decoding fires on `close()`, or on whatever's still buffered when the trace ends (added
  for M4, since pooled clients like go-redis never close their connection) — so a
  keep-alive/pooled connection now decodes correctly, but only one request/reply recovered
  per connection this way: multiple pooled Redis commands on the same fd within one trace
  aren't disentangled (only the first survives past the earlier commands, since replies are
  paired positionally against *all* commands sent, including ones from prior pooled uses
  within the same trace window). Attaching mid-connection (missing the start of a
  request/response) yields a byte stream that won't parse. Both match the guide's
  single-request-at-a-time v1 scope.
- RESP decoding only implements the RESP2 type set (`+`,`-`,`:`,`$`,`*`) — sufficient
  because the example app forces `Protocol: 2` on its Redis client, sidestepping RESP3's
  richer types (maps, null, boolean) entirely. A traced app that negotiates RESP3 and
  receives a map-typed reply would fail to decode that reply (the command would still be
  recognized; only reply rendering would fail).
- `etrace record` only recognizes commands that arrive as RESP arrays of bulk strings
  (`*N\r\n$...`), which is how every real Redis client sends them — this is a correctness
  assumption, not a scope cut, but worth knowing if you ever craft RESP by hand.
- `recorder.Build` records only the *first* HTTP exchange seen per recording and treats
  every Redis exchange as a dependency of it, with no way to tell "this Redis call belongs
  to a *different*, later HTTP request" — matches the single-request-at-a-time scope, but
  means `etrace record` isn't meant to be left running across multiple requests.

## Roadmap

Not built yet; each is a self-contained follow-on milestone on top of the same
`collector` → channel → stage → ... → consumer architecture:

- **M5 — Replay engine**: a userspace RESP proxy that serves recorded responses instead of
  a real Redis, so a recorded test case can be replayed with the dependency offline.
- **TLS uprobes**: `SSL_write`/`SSL_read` uprobes (the `SSL_read` entry+return stash reuses
  the same pattern built for `read()` in M1) so HTTPS traffic feeds the same HTTP decoder,
  sourcing plaintext at the TLS boundary. A known technique (Pixie's SSL tracing, bcc's
  `sslsniff`), not a novel one.
- Further out, explicitly out of scope even after the above: kernel-level SK_MSG/sockops
  transparent redirection, Postgres wire-protocol decoding, automated noise/diff detection
  across recordings, container/cgroup-aware recording.
