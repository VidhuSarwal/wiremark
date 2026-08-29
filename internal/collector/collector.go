package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/vidhu/etracer/internal/bpfgen"
)

const (
	OpConnect  uint32 = 0
	OpRead     uint32 = 1
	OpWrite    uint32 = 2
	OpClose    uint32 = 3
	OpSSLWrite uint32 = 4
	OpSSLRead  uint32 = 5
)

// dataCap must match bpf/types.h's DATA_CAP.
const dataCap = 4096

// Event mirrors bpf/types.h's struct event.
type Event struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	FD        int32 // -1 for OpSSLWrite/OpSSLRead; see SSLPtr
	Operation uint32
	Ret       int32
	_         uint32 // padding: ret ends at offset 28, SSLPtr needs 8-byte alignment
	SSLPtr    uint64 // SSL* identity, valid for OpSSLWrite/OpSSLRead; 0 otherwise

	RemoteAddr uint32
	RemotePort uint16
	_          uint16 // padding to match C struct layout
	TotalLen   uint32 // true byte count for OpRead/OpWrite/OpSSL*; may exceed DataLen
	DataLen    uint32 // captured (possibly truncated) length of Data
	Data       [dataCap]byte
}

// Payload returns the captured bytes for a read/write event. Truncated
// reports whether TotalLen exceeds what was actually captured -- callers
// assembling a byte stream (e.g. for HTTP decoding) need to know when data
// is missing rather than silently parsing a partial stream as complete.
func (e Event) Payload() []byte {
	return e.Data[:e.DataLen]
}

// Truncated reports whether the syscall's true byte count exceeded what
// this event captured.
func (e Event) Truncated() bool {
	return e.TotalLen > e.DataLen
}

// RemoteAddrString renders RemoteAddr/RemotePort as "a.b.c.d:port", valid
// for OpConnect events with an AF_INET remote address.
func (e Event) RemoteAddrString() string {
	return FormatIPv4Port(e.RemoteAddr, e.RemotePort)
}

// FormatIPv4Port renders an IPv4 address (as captured from a kernel
// sockaddr_in, i.e. little-endian byte order) and port as "a.b.c.d:port".
// Shared with internal/correlator, which decodes the same wire format.
func FormatIPv4Port(addr uint32, port uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24), port)
}

// Collector loads the BPF programs, attaches them, and streams decoded
// events on a channel. It never touches the terminal.
type Collector struct {
	pid   uint32
	objs  bpfgen.SyscallObjects
	links []link.Link
	rd    *ringbuf.Reader

	// tlsObjs/tlsRd are only populated if EnableTLS succeeds -- TLS uprobes
	// are opt-in, not attached by New.
	tlsEnabled bool
	tlsObjs    bpfgen.TlsObjects
	tlsRd      *ringbuf.Reader

	// monoRefNs/wallRef let EventTime convert a BPF event's boot-relative
	// bpf_ktime_get_ns() timestamp into a wall-clock time.Time.
	monoRefNs uint64
	wallRef   time.Time
}

// EventTime converts an Event's boot-relative monotonic timestamp (as
// produced by bpf_ktime_get_ns in the kernel) into wall-clock time.
func (c *Collector) EventTime(ev Event) time.Time {
	delta := int64(ev.Timestamp) - int64(c.monoRefNs)
	return c.wallRef.Add(time.Duration(delta))
}

// New loads and attaches the syscall tracepoints, scoped in-kernel to pid.
// pid must be non-zero: the BPF program's target_pid defaults to 0, which
// matches no process, so there is no accidental system-wide tracing mode.
func New(pid uint32) (*Collector, error) {
	if pid == 0 {
		return nil, fmt.Errorf("pid must be non-zero")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := bpfgen.LoadSyscall()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		return nil, fmt.Errorf("set target_pid: %w", err)
	}

	var objs bpfgen.SyscallObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, fmt.Errorf("read monotonic clock: %w", err)
	}

	c := &Collector{
		pid:       pid,
		objs:      objs,
		monoRefNs: uint64(ts.Sec)*1e9 + uint64(ts.Nsec),
		wallRef:   time.Now(),
	}

	tracepoints := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sys_enter_connect", objs.TraceEnterConnect},
		{"sys_enter_write", objs.TraceEnterWrite},
		{"sys_enter_read", objs.TraceEnterRead},
		{"sys_exit_read", objs.TraceExitRead},
		{"sys_enter_close", objs.TraceEnterClose},
	}
	for _, tpDef := range tracepoints {
		tp, err := link.Tracepoint("syscalls", tpDef.name, tpDef.prog, nil)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s: %w", tpDef.name, err)
		}
		c.links = append(c.links, tp)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	c.rd = rd

	return c, nil
}

// EnableTLS attaches SSL_write/SSL_read uprobes against the traced process's
// own loaded libssl (resolved from /proc/<pid>/maps, so it works whether the
// process linked the system OpenSSL or a bundled one), scoped to pid both
// in-kernel (target_pid, same guard as the syscall programs) and at attach
// time (link.UprobeOptions.PID) -- uprobes support PID-scoped attachment
// directly, which is stronger than the syscall tracepoints' guard-clause-only
// approach, since a mismatched call in another process never even reaches
// this program to be checked. Must be called after New and before Run; TLS
// tracing is opt-in and not attached by New.
func (c *Collector) EnableTLS() error {
	libssl, err := findMappedLibrary(c.pid, "libssl.so")
	if err != nil {
		return fmt.Errorf("find libssl: %w", err)
	}

	spec, err := bpfgen.LoadTls()
	if err != nil {
		return fmt.Errorf("load tls bpf spec: %w", err)
	}
	if err := spec.Variables["target_pid"].Set(c.pid); err != nil {
		return fmt.Errorf("set tls target_pid: %w", err)
	}
	if err := spec.LoadAndAssign(&c.tlsObjs, nil); err != nil {
		return fmt.Errorf("load tls bpf objects: %w", err)
	}
	c.tlsEnabled = true

	ex, err := link.OpenExecutable(libssl)
	if err != nil {
		return fmt.Errorf("open %s: %w", libssl, err)
	}

	opts := &link.UprobeOptions{PID: int(c.pid)}
	uprobes := []struct {
		symbol string
		prog   *ebpf.Program
		ret    bool
	}{
		{"SSL_write", c.tlsObjs.TraceSslWrite, false},
		{"SSL_read", c.tlsObjs.TraceSslReadEnter, false},
		{"SSL_read", c.tlsObjs.TraceSslReadExit, true},
	}
	for _, u := range uprobes {
		var l link.Link
		var err error
		if u.ret {
			l, err = ex.Uretprobe(u.symbol, u.prog, opts)
		} else {
			l, err = ex.Uprobe(u.symbol, u.prog, opts)
		}
		if err != nil {
			return fmt.Errorf("attach uprobe %s (ret=%v): %w", u.symbol, u.ret, err)
		}
		c.links = append(c.links, l)
	}

	rd, err := ringbuf.NewReader(c.tlsObjs.Events)
	if err != nil {
		return fmt.Errorf("open tls ringbuf reader: %w", err)
	}
	c.tlsRd = rd

	return nil
}

// decodeEvent decodes a raw ring buffer record into an Event. The field
// order and padding must match bpf/types.h's struct event exactly.
func decodeEvent(raw []byte) (Event, error) {
	var ev Event
	err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev)
	return ev, err
}

// readLoop reads one ring buffer until it's closed or an unrecoverable error
// occurs, publishing decoded events onto the shared events/errs channels.
func readLoop(rd *ringbuf.Reader, events chan<- Event, errs chan<- error) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			errs <- fmt.Errorf("read ringbuf: %w", err)
			return
		}

		ev, err := decodeEvent(record.RawSample)
		if err != nil {
			errs <- fmt.Errorf("decode event: %w", err)
			continue
		}
		events <- ev
	}
}

// Run reads the ring buffer(s) -- the syscall one always, plus the TLS one
// too if EnableTLS was called -- until Close or an unrecoverable error,
// publishing decoded events on the returned channel. Both channels close
// once every ring buffer's reader has returned.
func (c *Collector) Run() (<-chan Event, <-chan error) {
	events := make(chan Event, 64)
	errs := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readLoop(c.rd, events, errs)
	}()

	if c.tlsEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			readLoop(c.tlsRd, events, errs)
		}()
	}

	go func() {
		wg.Wait()
		close(events)
		close(errs)
	}()

	return events, errs
}

// Close releases all BPF resources (links, maps, programs, ringbuf readers).
func (c *Collector) Close() error {
	var firstErr error
	if c.rd != nil {
		if err := c.rd.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.tlsRd != nil {
		if err := c.tlsRd.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, l := range c.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := c.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if c.tlsEnabled {
		if err := c.tlsObjs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
