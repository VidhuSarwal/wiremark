package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/vidhu/etracer/internal/bpfgen"
)

const (
	OpConnect uint32 = 0
	OpRead    uint32 = 1
	OpWrite   uint32 = 2
	OpClose   uint32 = 3
)

// dataCap must match bpf/types.h's DATA_CAP.
const dataCap = 4096

// Event mirrors bpf/types.h's struct event.
type Event struct {
	PID        uint32
	TID        uint32
	Timestamp  uint64
	FD         int32
	Operation  uint32
	Ret        int32
	RemoteAddr uint32
	RemotePort uint16
	_          uint16 // padding to match C struct layout
	TotalLen   uint32 // true byte count for OpRead/OpWrite; may exceed DataLen
	DataLen    uint32 // captured (possibly truncated) length of Data
	Data       [dataCap]byte
	_          [4]byte // trailing padding to match the C struct's 8-byte alignment
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
	objs  bpfgen.SyscallObjects
	links []link.Link
	rd    *ringbuf.Reader

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

// decodeEvent decodes a raw ring buffer record into an Event. The field
// order and padding must match bpf/types.h's struct event exactly.
func decodeEvent(raw []byte) (Event, error) {
	var ev Event
	err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev)
	return ev, err
}

// Run reads the ring buffer until the reader is closed (via Close) or an
// unrecoverable error occurs, publishing decoded events on the returned
// channel. The channel is closed when Run returns.
func (c *Collector) Run() (<-chan Event, <-chan error) {
	events := make(chan Event, 64)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)
		for {
			record, err := c.rd.Read()
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
	}()

	return events, errs
}

// Close releases all BPF resources (links, maps, programs, ringbuf reader).
func (c *Collector) Close() error {
	var firstErr error
	if c.rd != nil {
		if err := c.rd.Close(); err != nil && firstErr == nil {
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
	return firstErr
}
