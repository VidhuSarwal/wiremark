// Package streamer assembles per-(pid,fd) byte streams from the raw Event
// stream and content-sniffs them via internal/decoder. It deliberately
// doesn't need accept() tracking: it buffers every fd's read/write bytes
// regardless of how the socket was established, and on close (or when the
// trace ends, for connections that are never explicitly closed -- see Run)
// tries each supported protocol in turn, keeping whichever parses.
package streamer

import (
	"github.com/vidhu/etracer/internal/collector"
	"github.com/vidhu/etracer/internal/decoder"
)

// Protocol identifies what a decoded Exchange turned out to be.
type Protocol int

const (
	ProtocolUnknown Protocol = iota
	ProtocolHTTP
	ProtocolRedis
)

// Exchange is a decoded request/response pair assembled from one
// connection's lifetime. Exactly one of HTTP or Redis is populated,
// according to Protocol.
type Exchange struct {
	PID      uint32
	FD       int32
	Protocol Protocol
	HTTP     *decoder.HTTPExchange
	Redis    []decoder.RedisCall
	// Truncated is set if any contributing event's payload was cut short by
	// the capture buffer cap -- the parse may have succeeded on incomplete
	// data (e.g. a short body) rather than failed outright.
	Truncated bool
}

// decode content-sniffs readBuf/writeBuf, trying HTTP first and then RESP
// (write=command/read=reply -- the only realistic role for a Redis client).
// Returns ok=false if neither protocol recognized the bytes.
func decode(pid uint32, fd int32, readBuf, writeBuf []byte, truncated bool) (Exchange, bool) {
	ex := Exchange{PID: pid, FD: fd, Truncated: truncated}

	if httpEx, ok := decoder.TryHTTP(readBuf, writeBuf); ok {
		ex.Protocol = ProtocolHTTP
		ex.HTTP = &httpEx
		return ex, true
	}
	if calls, ok := decoder.TryRESP(writeBuf, readBuf); ok {
		ex.Protocol = ProtocolRedis
		ex.Redis = calls
		return ex, true
	}
	return ex, false
}

// bufCap bounds memory per connection per direction; bytes beyond this are
// dropped (Exchange.Truncated reflects this via the underlying events'
// Truncated() flag, not this cap directly -- see appendCapped).
const bufCap = 64 * 1024

// connKind discriminates the two shapes of connection identity this project
// captures: a plain fd (syscall-sourced traffic) or an SSL* pointer
// (TLS-sourced traffic, which has no fd recoverable in-kernel -- see
// bpf/types.h's ssl_ptr field). Both need to coexist in the same map without
// colliding, since a small fd number and a heap pointer truncated to the
// wrong width could otherwise alias.
type connKind uint8

const (
	connFD connKind = iota
	connTLS
)

type key struct {
	pid  uint32
	kind connKind
	id   uint64 // fd (widened) for connFD, the SSL* value for connTLS
}

type connBufs struct {
	read, write []byte
	truncated   bool
}

func appendCapped(dst *[]byte, add []byte) {
	room := bufCap - len(*dst)
	if room <= 0 {
		return
	}
	if len(add) > room {
		add = add[:room]
	}
	*dst = append(*dst, add...)
}

// Run consumes events (becoming its sole receiver) and returns two
// channels: rawOut passes every event through unchanged, and exchanges
// emits a decoded Exchange each time a connection with recognized traffic
// closes -- or, for a connection never explicitly closed (e.g. a pooled
// client connection), when the trace ends. Both channels close when events
// closes.
func Run(events <-chan collector.Event) (rawOut <-chan collector.Event, exchanges <-chan Exchange) {
	raw := make(chan collector.Event, 64)
	out := make(chan Exchange, 16)

	go func() {
		defer close(raw)
		defer close(out)

		bufs := make(map[key]*connBufs)

		get := func(k key) *connBufs {
			b := bufs[k]
			if b == nil {
				b = &connBufs{}
				bufs[k] = b
			}
			return b
		}

		for ev := range events {
			raw <- ev

			var k key
			switch ev.Operation {
			case collector.OpRead, collector.OpWrite, collector.OpClose:
				k = key{pid: ev.PID, kind: connFD, id: uint64(uint32(ev.FD))}
			case collector.OpSSLRead, collector.OpSSLWrite:
				k = key{pid: ev.PID, kind: connTLS, id: ev.SSLPtr}
			default:
				continue // OpConnect: nothing for the streamer to buffer
			}

			switch ev.Operation {
			case collector.OpRead, collector.OpSSLRead:
				b := get(k)
				appendCapped(&b.read, ev.Payload())
				b.truncated = b.truncated || ev.Truncated()
			case collector.OpWrite, collector.OpSSLWrite:
				b := get(k)
				appendCapped(&b.write, ev.Payload())
				b.truncated = b.truncated || ev.Truncated()
			case collector.OpClose:
				// TLS connections have no close probe (see bpf/tls.bpf.c) --
				// they're only ever decoded by the end-of-trace flush below,
				// same as a pooled go-redis connection.
				if b, ok := bufs[k]; ok {
					if ex, ok := decode(ev.PID, ev.FD, b.read, b.write, b.truncated); ok {
						out <- ex
					}
					delete(bufs, k)
				}
			}
		}

		// Flush whatever's left when the trace ends: a pooled client
		// connection (e.g. go-redis) is never closed, so without this a
		// buffer that never saw OpClose would be silently discarded and
		// its traffic would never be decoded. This also retroactively
		// covers M3's documented keep-alive-connection limitation, and is
		// the only path TLS connections are ever decoded through, since
		// there's no SSL_shutdown/SSL_free probe. Scoped to one
		// command/reply pair per connection -- multiple pooled commands on
		// the same connection within one trace aren't disentangled.
		for k, b := range bufs {
			fd := int32(-1)
			if k.kind == connFD {
				fd = int32(k.id)
			}
			if ex, ok := decode(k.pid, fd, b.read, b.write, b.truncated); ok {
				out <- ex
			}
		}
	}()

	return raw, out
}
