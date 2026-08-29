package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vidhu/etracer/internal/collector"
	"github.com/vidhu/etracer/internal/correlator"
	"github.com/vidhu/etracer/internal/printer"
	"github.com/vidhu/etracer/internal/tui"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{Use: "etrace"}
	root.AddCommand(traceCmd())
	return root
}

func traceCmd() *cobra.Command {
	var pid int
	var noTUI bool

	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace connect/write/read/close syscalls for a PID",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pid <= 0 {
				return fmt.Errorf("--pid is required and must be positive")
			}

			c, err := collector.New(uint32(pid))
			if err != nil {
				return fmt.Errorf("start collector: %w", err)
			}
			defer c.Close()

			events, errs := c.Run()
			go func() {
				for err := range errs {
					fmt.Fprintln(os.Stderr, "collector error:", err)
				}
			}()

			if noTUI {
				printer.Print(os.Stdout, events, c.EventTime)
				return nil
			}

			rawEvents, conns := correlator.Run(events, c.EventTime)
			return tui.Run(rawEvents, conns, c.EventTime)
		},
	}

	cmd.Flags().IntVar(&pid, "pid", 0, "PID to trace (required)")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "print plain-text events instead of launching the TUI")
	return cmd
}
