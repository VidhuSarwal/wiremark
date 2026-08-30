# eTraceReplay, explained from scratch

This document assumes you know how to use a terminal and a little bit of programming, but
nothing about eBPF, syscalls, kernel tracing, or any of the specific jargon this project
uses. If you already know that stuff, read [`README.md`](README.md) instead — it's the
precise technical reference. This document is the "why does any of this exist and how does
it actually work" version, written to be read start to finish.

`NOTES.md` is a third document, for later: it's the messy, honest log of every bug and wrong
assumption hit while building this, kept for a future blog post. Read it once this one makes
sense and you're curious about the "how did you actually find that out" details.

---

## 1. What problem does this solve?

Say you have a web server. It does something, and to do that something, it talks to other
things over the network — maybe it calls a database, maybe it calls another web service.
Now say you want to write an automated test for that web server, but you don't want your
test to depend on a real database being up and running every time.

The classic way to solve this is to **record** a real interaction once (the request that
came in, and every network call the server made while handling it, and the responses it
got back), save that recording, and then **replay** it later: run the server again, but
this time feed it the recorded responses instead of letting it talk to the real database.
The server can't tell the difference — it made the same call, in the same format, and got a
response that looks the same. Your test runs fast, doesn't need a database, and is
deterministic (same input, same output, every time).

That's what eTraceReplay does, for one specific case: an HTTP server whose only dependency
is Redis (a simple key-value database). `etrace record` watches one request go through your
server and writes down everything it saw. `etrace run` reads that recording back and pretends
to be Redis, so you can run your server against the recording instead of a real Redis.

The interesting part — and the reason this project exists rather than just being "write a
proxy in front of Redis" — is *how* it watches the traffic. It doesn't sit in front of the
server as a network proxy. It watches from **inside the Linux kernel**, using a technology
called eBPF, which is explained below. That's a more powerful vantage point: it sees
*everything* the process does at the syscall level, plain HTTP or encrypted HTTPS, without
the server needing to be configured to route through anything.

---

## 2. Background concepts, one at a time

You don't need to memorize all of this — just read it once so the rest of the document makes
sense. Come back to this section if a later part uses a term you don't recognize.

### A process and its PID

Every running program on your computer is a **process**. Linux gives every process a number
when it starts, called a **PID** (Process ID). If you run `ps aux` or `top`, you'll see a
column of PIDs — that's how the operating system (and tools like this one) refer to "which
specific running program do you mean." This project works by pointing at one specific PID
and watching *only* that process.

### A syscall

A running program can't directly touch the network, the disk, or talk to other programs by
itself — only the operating system kernel can actually do those things, because the kernel
is the thing with privileged access to the hardware. So when your program wants to, say,
open a network connection, it doesn't do it itself: it asks the kernel to do it, through a
well-defined request called a **system call**, or **syscall** for short.

There's a small, fixed set of syscalls that matter for networking:
- `connect()` — "kernel, please open a connection to this address."
- `write()` — "kernel, please send these bytes out on this connection."
- `read()` — "kernel, please give me whatever bytes have arrived on this connection."
- `close()` — "kernel, I'm done with this connection."

Every single network interaction any program on Linux does — plain HTTP, a database
connection, anything — eventually goes through some sequence of these four calls (plus a
few others this project doesn't need). This matters because it means: if you can watch these
four syscalls happen for one process, you can reconstruct *everything* that process sent and
received over the network, regardless of what protocol it thinks it's speaking.

### eBPF — a camera the kernel lets you install

Here's the key idea. Normally, watching what's happening inside the kernel — like "tell me
every time this one process calls `read()`" — isn't something you can do from an ordinary
program. The kernel is a black box from the outside.

**eBPF** (extended Berkeley Packet Filter — the name is historical and doesn't matter) is a
technology that lets you write a small, tightly-restricted program and load it *into the
kernel itself*, where it runs every time some specific event happens — like "this specific
syscall was just called." Think of it as being allowed to install a tiny security camera at
one exact spot inside a building you don't otherwise have access to: you can't wander the
building, but at that one spot, you see everything that passes.

Why "tightly restricted"? Because letting arbitrary code run inside the kernel would be a
huge safety and security risk (a bug there can crash or corrupt the whole machine, not just
one program). So before the kernel will run your eBPF program, it runs it through something
called the **verifier**: a static checker that proves your program can't do anything unsafe
(no infinite loops, no out-of-bounds memory access, etc.) before it's ever allowed to
execute. If your program fails that check, it simply doesn't load — the kernel refuses it,
rather than running something potentially dangerous. You'll see this mentioned in
`NOTES.md` as a real thing that happened during development: a buggy eBPF program got
rejected at load time with an error message, not a kernel crash.

This project's eBPF programs are written in a restricted subset of C (that's what the `.bpf.c`
files in the `bpf/` directory are), compiled with `clang`, and loaded from a normal Go
program using a library called `cilium/ebpf`.

### Tracepoints and uprobes — the two kinds of "camera spots"

eBPF programs need to attach to a specific point where they'll be triggered. This project
uses two kinds:

- A **tracepoint** is a fixed instrumentation point the kernel itself already provides — for
  example, "right when any process calls `read()`." This project attaches to the
  tracepoints for `connect`, `write`, `read`, and `close`. This is how the plain HTTP/Redis
  tracing (`etrace trace`, `etrace record`) works.
- A **uprobe** (userspace probe) is similar, but instead of a kernel-provided event, you
  point it at a specific function *inside a specific program's own code* — for example, "the
  `SSL_write` function inside this process's copy of the OpenSSL library." This is how the
  optional `--tls` flag works: it doesn't watch the network syscalls (which would only see
  scrambled, encrypted bytes for HTTPS traffic) — instead, it watches the moment *just
  before* the program hands data to its encryption library, catching the plaintext before
  it gets encrypted.

### Why this matters for HTTPS specifically

If a program uses HTTPS, the bytes going over the actual network connection are encrypted —
watching `read()`/`write()` for that connection just gets you scrambled ciphertext, useless
for understanding what was actually said. But the program itself, before encrypting
anything, has the plaintext in memory and hands it to its TLS/SSL library to encrypt. A
uprobe on that library's encrypt/decrypt functions sees the data at exactly the point it's
still plaintext. That's the whole trick behind `--tls`, and it's a well-known technique (used
by real observability tools like Pixie and bcc's `sslsniff`) — not something novel invented
for this project.

One important catch: this only works for programs that call a C library like OpenSSL
directly. Go programs' built-in HTTPS support (`crypto/tls`) is written entirely in Go and
never calls OpenSSL, so `--tls` can't see inside a Go program's HTTPS traffic. It works for
`curl`, `openssl` itself, and most non-Go language runtimes.

### RESP — the wire format Redis speaks

Redis (the database this project can record/replay) sends commands and replies as plain
text, in a simple format called **RESP** (REdis Serialization Protocol). A command like
"set the key `user:42` to the value `Alice`" looks like this on the wire:

```
*3
$3
set
$7
user:42
$5
Alice
```

(The `*3` means "an array of 3 items follows"; each `$N` means "the next line is N bytes
long.") You don't need to memorize this format, but it's worth seeing once: it's simple
enough that this project's Redis decoder (`internal/decoder/resp.go`) is only a few dozen
lines of code, unlike parsing HTTP or a binary protocol.

### YAML — the file format for recordings

A recorded test case is saved as a **YAML** file — a human-readable text format for
structured data (similar in spirit to JSON, but meant to be easy for a person to read and
edit directly, using indentation instead of braces). Here's an actual example this project
produces:

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

You can open this in any text editor and read exactly what happened: a `POST /users` request
came in, the server did one Redis `SET` command and got back `OK`, and the server then
replied with `201 Created` and a JSON body.

### TUI — a terminal user interface

Most command-line tools just print lines of text and stop. A **TUI** (Terminal User
Interface) is a program that takes over the whole terminal window to draw an interactive
display — tables, tabs, highlighting, things you navigate with arrow keys — while still
running in a plain terminal, no graphics needed. This project's live-tracing view (`etrace
trace`) is a TUI with three tabs you switch between with the `Tab` key. It's built using a Go
library called `bubbletea`.

### PID filtering — why this doesn't watch your whole computer

An eBPF program attached to, say, "every time any process on this machine calls `read()`"
would fire constantly, for every program on your computer, all the time — a flood of
irrelevant data, and a real performance/safety concern if left running. This project always
scopes tracing down to **one PID** you specify — the eBPF program itself checks "is this the
one process I care about?" before doing anything, right at the start, for every single event.
(In `NOTES.md` there's a war story about what happens if you get this wrong: an early,
unfiltered version of this accidentally captured 77 megabytes of unrelated system traffic in
a few seconds.)

---

## 3. What the tool actually does, command by command

The compiled program is a single binary, `etrace`, with several subcommands.

### `etrace trace` — watch a process live

```bash
sudo ./etrace trace --pid 12345
```

Attaches to PID 12345 and shows you a live, scrolling view of everything it does on the
network — every `connect`, every byte read or written, every close — updating in real time
as it happens. Needs `sudo` because loading an eBPF program into the kernel requires
elevated privileges (this is `sudo`, not "run everything as root" — the eBPF verifier is
still the actual safety mechanism; `sudo` is just the permission gate to reach it).

Add `--no-tui` for a plain scrolling text log instead of the interactive display (useful for
piping into `grep` or redirecting to a file), or `--tls` to also decrypt HTTPS traffic for
processes that use OpenSSL directly (see the eBPF section above).

### `etrace record` — capture one request as a test case

```bash
sudo ./etrace record --pid 12345 -o test.yaml
```

Watches PID 12345 the same way, but instead of showing you a live view, it waits until you
press Ctrl-C, then writes down everything it understood as one structured YAML file: the one
HTTP request/response it saw, and any Redis commands the server made while handling it.

### `etrace run` — replay a test case without the real dependency

```bash
./etrace run --test test.yaml -- ./your-server
```

Reads `test.yaml` back, starts a small stand-in Redis server (just for the commands and
replies that were actually recorded), and launches `./your-server` with an environment
variable pointing it at that stand-in instead of a real Redis. Your server does exactly what
it always does — connects to "Redis," sends a command, gets a reply — except the reply comes
from the recording, and the real Redis doesn't even need to exist. This is the one command
that doesn't need `sudo`: there's no eBPF here at all, just an ordinary network server
written in Go.

### `etrace launch` — an interactive menu, if you don't want to remember flags

```bash
./etrace launch
```

A menu-driven front end for all of the above: pick a mode with arrow keys, pick a target
process from a searchable list (or fill in a couple of text fields for `record`/`run`), and
it assembles and runs the exact command for you — printing it first so you can see exactly
what it's about to do.

---

## 4. How it works under the hood, in plain words

Here's the pipeline, from the README, translated into plain language:

```
collector.Event  --->  correlator.Run  --->  streamer.Run  --->  tui.Run
```

Think of this as a small assembly line, where each station only knows how to do one job and
hands its work to the next station:

1. **`internal/collector`** is the only part of the program that actually talks to eBPF. It
   loads the kernel programs, reads the raw events they produce, and turns each one into a
   plain Go value (`Event`) — "at this time, this PID did this operation on this file
   descriptor, here are the bytes involved." It doesn't know or care what a TUI is, what
   HTTP is, or what happens to the event afterward. It just publishes a stream of events.

2. **`internal/correlator`** takes that stream and groups events by *connection* — so instead
   of a flat list of individual reads and writes, you get "this one connection to this one
   remote address sent 400 bytes and received 1200 bytes before closing." This is what
   powers the Connections tab.

3. **`internal/streamer`** takes the *same original* stream (each station gets its own full
   copy, more on why below) and, per connection, buffers up all the bytes sent and received,
   then tries to recognize what protocol they're actually speaking — is this HTTP? Is this
   Redis's RESP format? — using `internal/decoder`'s pure parsing functions. Once it
   recognizes something, it emits a decoded, human-readable "Exchange" (an HTTP
   request/response pair, or a list of Redis commands and their replies).

4. **`internal/tui`** just displays whatever the previous two stages hand it, across three
   tabs. It's not smart about networking at all — it's purely a renderer.

Why does the collector's output effectively get consumed by *both* the correlator and the
streamer, rather than one feeding into the other? Because in Go, a channel (the pipe-like
thing used to pass values between concurrent parts of a program) only ever delivers each
value to *one* receiver — you can't have two independent listeners both reading the same
channel and each seeing every value. So each stage that needs the raw events reads them from
the previous stage and re-publishes its own copy onward, in addition to doing its own job.
That's why the diagram above shows each arrow labeled with what it's forwarding.

This layered design is also *why* the project is testable at all without needing root
access or a live eBPF trace for most of its test suite: every stage after the collector just
consumes plain Go values from a channel, so a test can feed in fake, synthetic events instead
of running a real trace, and check what comes out the other end. Only a small number of
tests actually need `sudo` and a live kernel — the ones that check the eBPF programs
themselves work correctly.

`etrace record` and `etrace run` don't go through the TUI at all — `record` chains
`collector → streamer` directly (it wants the decoded Exchange list to build a YAML file
from, not a live display), and `run` doesn't touch the trace pipeline whatsoever — it's a
completely separate, ordinary network proxy that happens to read the YAML file `record`
produces.

---

## 5. A worked example, step by step

This mirrors what's in `README.md`'s testing section, with the "why" filled in.

```bash
# Build everything
make build
go build -o /tmp/go-http-app ./examples/go-http-app

# Start a little example web server that this project ships with, for testing against
/tmp/go-http-app &
APP_PID=$!

# Watch it live — you're about to see every network syscall it makes
sudo ./etrace trace --pid $APP_PID
```

In another terminal, run `curl http://127.0.0.1:18099/medium`. In the TUI, you'll see (on
the Events tab) a `CONNECT`, then a `READ` containing the literal bytes of the HTTP request
curl sent, then a `WRITE` containing the HTTP response — because that's the actual sequence
of syscalls the kernel saw happen. Press `Tab` to switch to the HTTP tab, and you'll see the
same interaction, but decoded: method, path, status code, a preview of the body.

That's the entire idea in miniature: the Events tab is "what the kernel literally saw," and
the HTTP tab is "what internal/decoder made sense of it."

For the record/replay demo, see `README.md`'s testing section — it walks through recording a
request against a real Redis, then replaying it with Redis turned off entirely, to prove the
recording is actually self-sufficient.

---

## 6. Glossary

| Term | Meaning |
|---|---|
| Process / PID | A running program / the number Linux assigns to identify it |
| Syscall | A request a program makes to the kernel to do something privileged (network, disk, etc.) |
| eBPF | A way to run small, kernel-verified programs inside the Linux kernel, triggered by specific events |
| Verifier | The kernel's static safety-checker that an eBPF program must pass before it's allowed to run |
| Tracepoint | A fixed, kernel-provided instrumentation point (e.g. "a `read()` syscall just happened") |
| Uprobe | An instrumentation point you attach to a specific function inside a specific program's own code |
| Ring buffer | The mechanism eBPF uses to hand events from the kernel back to your regular program efficiently |
| RESP | The plain-text wire format Redis uses for commands and replies |
| YAML | A human-readable structured text file format, used here for recorded test cases |
| TUI | A terminal user interface — an interactive, full-screen display inside a plain terminal |
| Channel (Go) | A typed pipe for passing values between concurrently running parts of a Go program |
| CO-RE | "Compile Once, Run Everywhere" — a technique (used by this project) that lets one compiled eBPF program work across different kernel versions |
| BTF | Kernel type information (BPF Type Format) that CO-RE relies on to adjust to the running kernel's actual data layout |

---

## Where to go next

- **`README.md`** — the precise technical reference: exact commands, exact architecture,
  every known limitation spelled out.
- **`NOTES.md`** — the development diary: every bug found, how it was diagnosed, and what it
  taught. Read this once the above makes sense and you want the "how do you actually debug
  something like this" story.
