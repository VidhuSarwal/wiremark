# eTraceReplay

A per-PID syscall/socket tracer built on eBPF (CO-RE via `cilium/ebpf` + `bpf2go`), with a
`bubbletea` TUI. This is Milestones 1–2 of a larger eBPF traffic-recording project — see
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

The TUI has two tabs (`Tab` to switch, `q` to quit): **Events** is the flat, timestamped
syscall log; **Connections** groups them by `(pid, fd)` into one row per socket lifecycle —
remote endpoint, cumulative bytes out/in, and open/closed state, updating in place rather
than appending as new activity arrives on that socket.

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
`internal/printer` (`--no-tui`) consumes that channel directly. In TUI mode,
`internal/correlator` sits in between as the *sole* consumer of the collector's channel — Go
channels deliver each value to exactly one receiver, so fanning the same channel out to two
independent consumers isn't an option — and itself owns two output channels: a passthrough
of the raw events (feeding the TUI's Events tab) and a stream of `Connection` snapshots
(feeding the Connections tab). This is also what makes the TUI testable headlessly with
`teatest` (`internal/tui/tui_test.go`): both tabs consume plain channels, so tests inject
synthetic values instead of driving a live trace.

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
- Captured payloads are truncated to 256 bytes per event.
- Only `connect`/`write`/`read`/`close` are traced — not `recv`/`send`/`accept` (some
  runtimes, e.g. CPython's `socket` module, use `recv`/`recvfrom` rather than `read`, so
  their socket reads won't appear as Out/In bytes in the Connections tab; plain `read()` on
  files and pipes will).
- The correlator only tracks sockets *this process* called `connect()` on (the client
  role). A traced process acting as a server (`accept()`ing inbound connections) won't show
  up in the Connections tab yet — M3's HTTP decoding will need to add that.
- A process that dies without calling `close()` (e.g. killed) leaves its connections shown
  as still-open; there's no `sched_process_exit`-based garbage collection in this scope. Not
  worth adding yet — tracked state per connection is small, so the cost of a leaked entry
  until the trace ends is negligible.
- The correlator tracks byte *counts* only, not the actual payload content per connection
  (each individual event's payload is still visible in the Events tab, truncated to 256
  bytes). Assembling a per-connection byte stream is M3's job, once HTTP decoding defines
  what buffering/capping it actually needs.

## Roadmap

Not built yet; each is a self-contained follow-on milestone on top of the same
`collector` → channel → consumer architecture:

- **M3 — HTTP decoding**: parse per-connection byte streams (assembled from the Events tab's
  granular read/write payloads, since the correlator only tracks counts) with
  `net/http`'s `ReadRequest`/`ReadResponse` — deliberately not a hand-rolled parser, since
  the value here is the kernel-level capture, not reimplementing `net/http`.
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
