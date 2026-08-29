package main

import (
	"fmt"
	"os"

	"github.com/vidhu/etracer/internal/collector"
)

func main() {
	c, err := collector.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer c.Close()

	events, errs := c.Run()
	fmt.Println("smoke test: attached sys_enter_connect, waiting for events (Ctrl-C to stop)...")
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			fmt.Printf("PID %d fd=%d connect -> %d.%d.%d.%d:%d\n",
				ev.PID, ev.FD,
				byte(ev.RemoteAddr), byte(ev.RemoteAddr>>8), byte(ev.RemoteAddr>>16), byte(ev.RemoteAddr>>24),
				ev.RemotePort)
		case err, ok := <-errs:
			if !ok {
				return
			}
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	}
}
