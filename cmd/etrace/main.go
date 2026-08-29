package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/vidhu/etracer/internal/collector"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: etrace-smoke <pid>")
		os.Exit(1)
	}
	pid, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid pid:", err)
		os.Exit(1)
	}

	c, err := collector.New(uint32(pid))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer c.Close()

	events, errs := c.Run()
	fmt.Printf("smoke test: tracing pid %d (Ctrl-C to stop)...\n", pid)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			switch ev.Operation {
			case collector.OpConnect:
				fmt.Printf("PID %d fd=%d CONNECT -> %d.%d.%d.%d:%d\n",
					ev.PID, ev.FD,
					byte(ev.RemoteAddr), byte(ev.RemoteAddr>>8), byte(ev.RemoteAddr>>16), byte(ev.RemoteAddr>>24),
					ev.RemotePort)
			case collector.OpWrite:
				fmt.Printf("PID %d fd=%d WRITE %d bytes: %q\n", ev.PID, ev.FD, ev.DataLen, ev.Data[:ev.DataLen])
			case collector.OpRead:
				fmt.Printf("PID %d fd=%d READ %d bytes: %q\n", ev.PID, ev.FD, ev.DataLen, ev.Data[:ev.DataLen])
			case collector.OpClose:
				fmt.Printf("PID %d fd=%d CLOSE\n", ev.PID, ev.FD)
			}
		case err, ok := <-errs:
			if !ok {
				return
			}
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	}
}
