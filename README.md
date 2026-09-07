# Wiremark

A per-PID syscall/socket tracer built on eBPF (CO-RE via `cilium/ebpf` + `bpf2go`), with a
`bubbletea` TUI, that can record a traced HTTP request and its Redis dependencies as a
replayable YAML test case — and replay that recording later with the real dependency
offline. Optional `SSL_write`/`SSL_read` uprobes source the same HTTP decoding from
plaintext at the TLS boundary, for HTTPS traffic. This is the full v1 scope of a larger
eBPF traffic-recording project (Milestones 1–5 plus TLS uprobes) — see
[Roadmap](#roadmap) for what's deliberately out of scope even so.

New to eBPF, syscalls, or this project generally? [`GUIDE.md`](GUIDE.md) explains everything
from scratch, in plain language, before you read the reference below.

## What this does

Given a PID, `wiremark trace` attaches BPF tracepoints on `connect`, `write`, `read`, and
`close`, scoped **in-kernel** to that one process (a `target_pid` rodata constant checked
at the top of every probe — tracing is never system-wide), and streams the decoded events
either to a live terminal UI or as plain text.

```
sudo ./wiremark trace --pid <pid>            # interactive TUI (default)
sudo ./wiremark trace --pid <pid> --no-tui   # plain-text stream
sudo ./wiremark trace --pid <pid> --tls      # also decode SSL_write/SSL_read plaintext
sudo ./wiremark record --pid <pid> -o test.yaml   # record one HTTP request + Redis deps as YAML
./wiremark run --test test.yaml -- ./your-app     # replay: your-app's Redis deps are served
                                                 # from test.yaml, no real Redis needed
```

`--tls` attaches `SSL_write`/`SSL_read` uprobes to the traced process's own loaded libssl
(resolved from `/proc/<pid>/maps`), so it only does anything for a process that actually
links OpenSSL directly — Go's `crypto/tls` never calls it, so it won't help against a Go
HTTPS client or server. `curl`, `openssl s_client`/`s_server`, and most non-Go language
runtimes' TLS stacks do.

### Interactive launcher

Not sure which command/flags/PID you want, or just want to point-and-click instead of
typing a full invocation? `wiremark launch` is a `bubbletea` menu that picks a mode first
(the four `trace`/`record` variants above, or a `run` replay), then walks through only
the inputs that mode actually needs — a PID (filterable, type to narrow a long process
list), an output path, or a YAML file plus a command to exec:

```
./wiremark launch
```

It doesn't run anything itself: once you confirm a selection, it tears down its own UI,
prints the exact command it assembled, and `exec`s straight into it (`sudo`-prefixed only
for the modes that load BPF). The launcher process itself never needs root.

The TUI has three tabs (`Tab` to cycle, `q` to quit): **Events** is the flat, timestamped
syscall (and, with `--tls`, `SSL_write`/`SSL_read`) log; **Connections** groups
syscall-sourced traffic by `(pid, fd)` into one row per socket lifecycle — remote endpoint,
cumulative bytes out/in, and open/closed state, updating in place rather than appending as
new activity arrives on that socket (TLS traffic has no fd and isn't tracked here — see
Architecture); **HTTP** shows one row per decoded HTTP request/response pair — method,
path, status, a body preview, and whether the capture was truncated (Redis traffic doesn't
get a TUI tab — see Architecture). **Note:** a connection never closed during the trace —
every TLS connection, plus a pooled/keep-alive plain socket — only decodes at the
end-of-trace flush, which quitting the TUI happens *before*, so it never populates the HTTP
tab; its raw traffic still appears live in the Events tab (plaintext, for TLS). Use
`--no-tui` or `wiremark record` to see the decoded form for those.

`wiremark record` runs until `Ctrl-C`, then writes a YAML test case built from what it saw
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

`wiremark run` reads that YAML back and stands in for the real Redis: it starts a userspace
RESP2 proxy for the recorded `type: redis` dependencies, points the given command at it via
a `REDIS_ADDR` environment variable, and execs it. Stopping the real Redis first and running
`curl -X POST /users` again through `wiremark run` returns the identical recorded response —
the app never notices its dependency is offline. No eBPF is involved in replay at all; it's
plain userspace proxying, and no root is required.

Root (or `CAP_BPF`+`CAP_PERFMON`) is required to load BPF programs (`trace`/`record` only).

## Building

Requires: Go 1.21+, clang/llvm, `libbpf-dev`, `bpftool`, and kernel BTF
(`/sys/kernel/btf/vmlinux` must exist). `wiremark record`'s Redis decoding only needs a Redis
instance at trace time (e.g. `redis-server --save "" --appendonly no`, stopped again after
— this project doesn't install or run Redis as a standing service), not to build or test.

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
make build     # regenerates BPF bindings (bpf2go) and builds ./wiremark
make test      # unit + headless TUI tests, no root required
```

`bpf/vmlinux.h` is machine-generated and gitignored — regenerate it on whatever box you're
building on. `internal/bpfgen/gen.go`'s TLS build target also computes a
`-D__TARGET_ARCH_<arch>` flag from `uname -m` for the same reason: the uprobe code's
`PT_REGS_PARMn`/`PT_REGS_RC` macros are architecture-specific and fail loudly at compile
time (not silently) without it.

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

`wiremark record` chains `collector → streamer` directly (it needs the `Exchange` stream, not
the TUI's `Connection` view) and calls `internal/recorder.Build` on everything the streamer
decoded during the trace: the first HTTP exchange observed becomes the recorded
request/response, every Redis call across every Redis exchange becomes a dependency, in
order. No time-window matching is needed to tell "the request" from "its dependencies" —
protocol type alone separates them, which is enough at this project's single-request-at-a-
time scope (see Known limitations). `internal/storage` is a deliberately generic YAML
read/write helper with no knowledge of the `TestCase` shape.

Streamer decodes on `close()`, or on whatever's still buffered when the trace ends —
added for `wiremark record`, since connection-pooling clients like `go-redis` never call
`close()` on a connection they intend to reuse. Without this, Redis traffic would be
captured perfectly on the wire and then silently produce nothing.

`internal/replay` is the read side of the same schema `internal/recorder` writes: it holds
no eBPF, no channels, and no relationship to the trace pipeline above at all — `wiremark run`
loads a YAML file directly and starts a `replay.Proxy` that speaks just enough RESP2 to (1)
tolerate a real client's connection handshake (`HELLO`, `CLIENT SETINFO`, ...) with a
syntactically valid RESP error reply, since those commands were filtered out of the
recording by `decoder.IsAdminCommand` and have no recorded reply to give back, and (2) match
a real command against the recorded dependency list by exact, case-insensitive text and
reply with `decoder.EncodeReply` — the inverse of the `RESPValue.String()` rendering
`TryRESP` used to store the reply as a plain string in the first place. `wiremark run` execs
the given command with `REDIS_ADDR` pointing at the proxy; the app's own code is unaware
it's talking to anything but Redis.

`read()` is captured as an entry+exit pair: the buffer isn't populated until the syscall
returns, so `sys_enter_read` stashes `{buf, fd}` in a BPF hash map keyed by `pid_tgid`, and
`sys_exit_read` reads the buffer using the real return length. `write()`, `connect()`, and
`close()` are single-probe (`sys_enter_*` only).

The correlator identifies a connection by a monotonic `Seq` assigned at `connect()` time,
not just `(pid, fd)` — the kernel reuses fd numbers, so a second connection on a recently
freed fd must not merge its byte counts or endpoint into the previous connection's row.

`--tls` attaches a separate BPF object (`bpf/tls.bpf.c`, its own `bpf2go` target) with
uprobes on `SSL_write` (single-probe, like `write()`) and `SSL_read` (entry+return stash,
like `read()` — the buffer isn't populated until `SSL_read` returns). `SSL_write`/`SSL_read`
take an opaque `SSL*` with no file descriptor anywhere in their signature, so `struct
event` carries a `ssl_ptr` field as the connection identity for these ops instead (`fd` is
always `-1`), and `internal/streamer`'s connection key gained a `kind` tag to keep an fd
and an unrelated `ssl_ptr` that happen to share a numeric value from being merged into one
buffer. `Collector.Run` merges the syscall and TLS ring buffers into one event channel, so
every downstream stage (correlator, streamer, TUI) sees TLS events the same way it sees
syscall ones — no protocol-specific plumbing needed past the collector. `EnableTLS`
resolves the traced process's own loaded libssl from `/proc/<pid>/maps` (so it works
whether the process linked the system OpenSSL or a bundled one) and attaches with
`link.UprobeOptions{PID: ...}`, which scopes the attachment itself to that one process at
the kernel level — stronger than the syscall tracepoints' guard-clause-only approach, since
a call in a different process never reaches the program to be checked at all.

`internal/launcher` has no relationship to any of the above beyond assembling command-line
args for it: a `bubbletea` model, given a `[]Process` and a YAML-path default (never reading
`/proc` or the filesystem itself, matching the rest of the TUI's testability pattern), walks
a mode-first flow to a `Result{Args, NeedsSudo}` and quits. `cmd/wiremark`'s `launch` command
runs that to completion, lets its `tea.Program` fully tear down, then `syscall.Exec`s the
assembled command — never in-process, and never while its own UI is still on screen (`trace`
launched from the menu runs its own `bubbletea` program, and one can't nest inside another
without both fighting over the alt-screen).

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
- `wiremark record` only recognizes commands that arrive as RESP arrays of bulk strings
  (`*N\r\n$...`), which is how every real Redis client sends them — this is a correctness
  assumption, not a scope cut, but worth knowing if you ever craft RESP by hand.
- `recorder.Build` records only the *first* HTTP exchange seen per recording and treats
  every Redis exchange as a dependency of it, with no way to tell "this Redis call belongs
  to a *different*, later HTTP request" — matches the single-request-at-a-time scope, but
  means `wiremark record` isn't meant to be left running across multiple requests.
- `wiremark run`'s proxy matches an incoming command against a recorded dependency by exact,
  case-insensitive text (`strings.Join(cmd, " ")`) — a command with different argument
  values than what was recorded (e.g. `set user:42 Bob` when the recording has
  `set user:42 Alice`) gets a "no recorded reply" RESP error, not a fuzzy or parameterized
  match. Matches the guide's scope of replaying one recorded interaction exactly, not a
  general-purpose Redis mock.
- The replay proxy only serves `type: redis` dependencies (the only dependency type M4's
  recorder produces); it has no HTTP-dependency replay, since v1 has no scenario that needs
  one (the HTTP exchange is the request *under test*, not a dependency of it).
- `EncodeReply` reconstructs RESP wire bytes from the plain display string
  `RESPValue.String()` stored in the YAML (e.g. `"OK"`), not from the original type byte —
  round-trips exactly for every reply shape this project's example app actually produces
  (simple strings, `(nil)`, `(error) ...`, `(integer) ...`), but a value that's ambiguous
  between simple-string and bulk-string encoding (e.g. a recorded bulk-string reply whose
  content happens to *look* like plain text) is re-encoded as a simple string. Real Redis
  clients decode both the same way for ordinary string values, so this hasn't mattered in
  practice, but it's not a byte-exact replay of the original wire format.
- `--tls` only fires for calls to the plain `SSL_write`/`SSL_read` symbols. Some libssl
  callers use `SSL_write_ex`/`SSL_read_ex` instead for some or all of their traffic
  (confirmed live: `openssl s_server`'s `-www` response path does, while `curl` and
  `openssl s_client` call the plain functions) — such traffic isn't captured. Not a
  fundamental limitation (the same uprobe technique applies to the `_ex` symbols), just not
  built, since nothing in this project's own test fixtures needed it.
- `--tls` has no TLS-level connection-close probe (no `SSL_shutdown`/`SSL_free` uprobe), so
  every TLS connection is decoded only via streamer's end-of-trace flush, never on close —
  see the note on this in "What this does" above about the TUI exiting before that flush
  renders.
- `internal/correlator`'s Connections tab has no concept of an `ssl_ptr`-keyed connection at
  all (it only tracks `connect()`-based fd lifecycles); TLS traffic is visible in the Events
  and HTTP tabs but never in Connections.
- `wiremark launch`'s `run` mode splits the command-to-exec on whitespace (`strings.Fields`),
  not a shell-aware tokenizer — a command whose arguments need quoting (spaces, globs) won't
  parse correctly. Type the full `wiremark run --test ... -- <command>` invocation directly for
  those cases; the launcher is a convenience path for the common one, not a shell.

## Roadmap

Not built in v1; each is a substantial follow-on beyond what this project set out to do,
listed for context rather than as near-term plans:

- Kernel-level `SK_MSG`/sockops transparent redirection (v1's replay uses a userspace env-var
  redirect instead — see `internal/replay`).
- Postgres wire-protocol decoding, alongside the existing HTTP/RESP2 decoders.
- Automated noise/diff detection across recordings (e.g. flagging a replay whose response
  differs from the original recording).
- Container/cgroup-aware recording (tracing by cgroup rather than a single PID).
