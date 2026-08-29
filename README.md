# eTraceReplay

A per-PID syscall/socket tracer built on eBPF (CO-RE via `cilium/ebpf` + `bpf2go`), with a
`bubbletea` TUI. This is Milestone 1 of a larger eBPF traffic-recording project — see
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
`internal/printer` (plain text) and `internal/tui` (bubbletea) are two independent
consumers of that same channel — which is also what makes the TUI testable headlessly with
`teatest` (`internal/tui/tui_test.go`) by feeding it synthetic events instead of a live
trace.

`read()` is captured as an entry+exit pair: the buffer isn't populated until the syscall
returns, so `sys_enter_read` stashes `{buf, fd}` in a BPF hash map keyed by `pid_tgid`, and
`sys_exit_read` reads the buffer using the real return length. `write()`, `connect()`, and
`close()` are single-probe (`sys_enter_*` only).

## Known limitations (v1)

- Only `AF_INET` (IPv4) `connect()` addresses are decoded; other address families report a
  zero address rather than misdecoding.
- Captured payloads are truncated to 256 bytes per event.
- Only `connect`/`write`/`read`/`close` are traced — not `recv`/`send`/`accept` (some
  runtimes, e.g. CPython's `socket` module, use `recv`/`recvfrom` rather than `read`, so
  their socket reads won't appear; plain `read()` on files and pipes will).
- No correlation across events yet (that's M2) — output is a flat, timestamped stream.

## Roadmap

Not built in this pass; each is a self-contained follow-on milestone on top of the same
`collector` → channel → consumer architecture:

- **M2 — PID/FD/socket correlation**: an `internal/correlator` package grouping events by
  `(pid, fd)` into per-connection byte streams, so output shows "this connection did X"
  instead of a flat event log.
- **M3 — HTTP decoding**: parse the correlator's assembled byte streams with
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
