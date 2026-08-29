// Package correlator groups the collector's flat Event stream into
// per-connection state keyed by (pid, fd): remote endpoint, cumulative bytes
// read/written, and open/closed lifecycle. It tracks only sockets that were
// established with a connect() this process observed (the client role) --
// sockets accepted from an inbound connection aren't tracked yet.
package correlator

import (
	"time"

	"github.com/vidhu/etracer/internal/collector"
)

// Connection is a snapshot of one socket's state at the time of the event
// that produced it. Seq uniquely identifies a connection's lifecycle: the
// kernel reuses fds, so (PID, FD) alone isn't a stable identity across
// separate connections on the same fd.
type Connection struct {
	Seq        uint64
	PID        uint32
	FD         int32
	Comm       string
	RemoteAddr uint32
	RemotePort uint16
	BytesOut   uint64
	BytesIn    uint64
	Opened     time.Time
	Closed     bool
	ClosedAt   time.Time
}

// RemoteAddrString renders RemoteAddr/RemotePort as "a.b.c.d:port".
func (c Connection) RemoteAddrString() string {
	return collector.FormatIPv4Port(c.RemoteAddr, c.RemotePort)
}

type key struct {
	pid uint32
	fd  int32
}

// Run consumes events (becoming its sole receiver) and returns two channels:
// rawOut passes every event through unchanged, for consumers that still want
// the flat M1 stream (e.g. the TUI's event-log tab), and connOut emits a
// Connection snapshot each time a tracked connection's state changes. Both
// channels close when events closes.
func Run(events <-chan collector.Event, timeOf func(collector.Event) time.Time) (rawOut <-chan collector.Event, connOut <-chan Connection) {
	raw := make(chan collector.Event, 64)
	conns := make(chan Connection, 64)

	go func() {
		defer close(raw)
		defer close(conns)

		tracked := make(map[key]*Connection)
		var nextSeq uint64

		for ev := range events {
			raw <- ev

			k := key{pid: ev.PID, fd: ev.FD}
			switch ev.Operation {
			case collector.OpConnect:
				nextSeq++
				c := &Connection{
					Seq:        nextSeq,
					PID:        ev.PID,
					FD:         ev.FD,
					Comm:       collector.Comm(ev.PID),
					RemoteAddr: ev.RemoteAddr,
					RemotePort: ev.RemotePort,
					Opened:     timeOf(ev),
				}
				tracked[k] = c
				conns <- *c
			case collector.OpWrite:
				if c, ok := tracked[k]; ok {
					c.BytesOut += uint64(ev.DataLen)
					conns <- *c
				}
			case collector.OpRead:
				if c, ok := tracked[k]; ok {
					c.BytesIn += uint64(ev.DataLen)
					conns <- *c
				}
			case collector.OpClose:
				if c, ok := tracked[k]; ok {
					c.Closed = true
					c.ClosedAt = timeOf(ev)
					conns <- *c
					delete(tracked, k)
				}
			}
		}
	}()

	return raw, conns
}
