package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

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

func New() (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs bpfgen.SyscallObjects
	if err := bpfgen.LoadSyscallObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	c := &Collector{objs: objs}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceEnterConnect, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach sys_enter_connect: %w", err)
	}
	c.links = append(c.links, tp)

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
