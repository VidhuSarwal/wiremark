package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/vidhu/etracer/internal/bpfgen"
)

const (
	OpConnect uint32 = 0
	OpRead    uint32 = 1
	OpWrite   uint32 = 2
	OpClose   uint32 = 3
)

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
	DataLen    uint32
	Data       [256]byte
}

// Collector loads the BPF programs, attaches them, and streams decoded
// events on a channel. It never touches the terminal.
type Collector struct {
	objs  bpfgen.SyscallObjects
	links []link.Link
	rd    *ringbuf.Reader
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

	c := &Collector{objs: objs}

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

			var ev Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
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
