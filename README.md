# eTraceReplay

A per-PID syscall/socket tracer built on eBPF (CO-RE via `cilium/ebpf` + `bpf2go`), with a
`bubbletea` TUI. This is Milestones 1–3 of a larger eBPF traffic-recording project — see
[Roadmap](#roadmap) for what's deliberately not built yet.

## What this does

Given a PID, `etrace trace` attaches BPF tracepoints on `connect`, `write`, `read`, and
`close`, scoped **in-kernel** to that one process (a `target_pid` rodata constant checked
at the top of every probe — tracing is never system-wide), and streams the decoded events
either to a live terminal UI or as plain text.

```
sudo ./etrace trace --pid <pid>            # interactive TUI (default)
sudo ./etrace trace --pid <pid> --no-tui   # plain-text stream
```

The TUI has three tabs (`Tab` to cycle, `q` to quit): **Events** is the flat, timestamped
syscall log; **Connections** groups them by `(pid, fd)` into one row per socket lifecycle —
remote endpoint, cumulative bytes out/in, and open/closed state, updating in place rather
than appending as new activity arrives on that socket; **HTTP** shows one row per decoded
request/response pair — method, path, status, a body preview, and whether the capture was
truncated.

Root (or `CAP_BPF`+`CAP_PERFMON`) is required to load BPF programs.

## Building

Requires: Go 1.21+, clang/llvm, `libbpf-dev`, `bpftool`, and kernel BTF
(`/sys/kernel/btf/vmlinux` must exist).

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
tab). `internal/streamer` buffers each `(pid, fd)`'s read/write bytes and, on close,
content-sniffs both directions as HTTP (feeding the HTTP tab). Every stage still forwards
the raw event stream unchanged, which is what keeps the Events tab working all the way
through the chain. This layering is also what makes the TUI testable headlessly with
`teatest` (`internal/tui/tui_test.go`): every tab consumes a plain channel, so tests inject
synthetic values instead of driving a live trace.

The streamer doesn't need `accept()` tracking to identify a traced server's inbound
sockets: it buffers every fd's bytes regardless of how the socket was established, and
tries `http.ReadRequest`/`ReadResponse` in **both** role assignments (read=request,
write=response for a traced HTTP server; the inverse for a traced client), keeping
whichever parses. The inverse case isn't exercised by anything in v1 yet, but M4 (a traced
Redis *client*) needs it, so `decode()` was made role-agnostic now rather than revisited
later.

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
  as still-open in the Connections tab, and any in-flight HTTP exchange on that fd is never
  decoded (the streamer only attempts a parse on close). Not worth adding
  `sched_process_exit`-based cleanup for either yet — tracked state per connection is small.
- The streamer buffers up to 64KB per direction per connection; bytes beyond that are
  silently dropped from the buffer (separately from, and in addition to, the per-event 4096
  byte capture cap above).
- HTTP decoding only fires once, on `close()`, for a whole connection's buffered bytes. A
  keep-alive connection that's still open when the trace ends produces no HTTP tab row, and
  attaching mid-connection (missing the start of a request/response) yields a byte stream
  that won't parse. Both match the guide's single-request-at-a-time v1 scope.

## Roadmap

Not built yet; each is a self-contained follow-on milestone on top of the same
`collector` → channel → stage → ... → consumer architecture:

- **M4 — Redis (RESP) decoding + recorder**: a minimal RESP parser plus a simple
  same-PID/time-window heuristic to attribute outbound Redis calls to the inbound HTTP
  request that triggered them, recorded as YAML test cases.
- **M5 — Replay engine**: a userspace RESP proxy that serves recorded responses instead of
  a real Redis, so a recorded test case can be replayed with the dependency offline.
- **TLS uprobes**: `SSL_write`/`SSL_read` uprobes (the `SSL_read` entry+return stash reuses
  the same pattern built for `read()` in M1) so HTTPS traffic feeds the same HTTP decoder,
  sourcing plaintext at the TLS boundary. A known technique (Pixie's SSL tracing, bcc's
  `sslsniff`), not a novel one.
- Further out, explicitly out of scope even after the above: kernel-level SK_MSG/sockops
  transparent redirection, Postgres wire-protocol decoding, automated noise/diff detection
  across recordings, container/cgroup-aware recording.
