package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"

	"github.com/spf13/cobra"

	"github.com/vidhu/etracer/internal/collector"
	"github.com/vidhu/etracer/internal/correlator"
	"github.com/vidhu/etracer/internal/printer"
	"github.com/vidhu/etracer/internal/recorder"
	"github.com/vidhu/etracer/internal/replay"
	"github.com/vidhu/etracer/internal/storage"
	"github.com/vidhu/etracer/internal/streamer"
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
	root.AddCommand(recordCmd())
	root.AddCommand(runCmd())
	return root
}

func traceCmd() *cobra.Command {
	var pid int
	var noTUI bool
	var tls bool

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

			if tls {
				if err := c.EnableTLS(); err != nil {
					return fmt.Errorf("enable TLS uprobes: %w", err)
				}
			}

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

			rawEvents1, conns := correlator.Run(events, c.EventTime)
			rawEvents2, exchanges := streamer.Run(rawEvents1)
			return tui.Run(rawEvents2, conns, exchanges, c.EventTime)
		},
	}

	cmd.Flags().IntVar(&pid, "pid", 0, "PID to trace (required)")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "print plain-text events instead of launching the TUI")
	cmd.Flags().BoolVar(&tls, "tls", false, "also attach SSL_write/SSL_read uprobes to capture TLS plaintext (requires the target to link libssl)")
	return cmd
}

func recordCmd() *cobra.Command {
	var pid int
	var output string
	var name string

	cmd := &cobra.Command{
		Use:   "record",
		Short: "Record one HTTP request (and any Redis dependencies) as a YAML test case",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pid <= 0 {
				return fmt.Errorf("--pid is required and must be positive")
			}
			if output == "" {
				return fmt.Errorf("--output is required")
			}

			c, err := collector.New(uint32(pid))
			if err != nil {
				return fmt.Errorf("start collector: %w", err)
			}
			var closeOnce sync.Once
			closeCollector := func() { closeOnce.Do(func() { c.Close() }) }
			defer closeCollector()

			// Ctrl-C stops the recording (closing the collector ends the
			// ring buffer read, which cascades through streamer to close
			// the exchanges channel below) rather than aborting the process
			// -- the guide's own demo flow is start recording, send one
			// request, then Ctrl-C to finish.
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() {
				<-sigCh
				fmt.Fprintln(os.Stderr, "\nstopping recording...")
				closeCollector()
			}()

			events, errs := c.Run()
			go func() {
				for err := range errs {
					fmt.Fprintln(os.Stderr, "collector error:", err)
				}
			}()

			_, exchanges := streamer.Run(events)
			fmt.Fprintf(os.Stderr, "recording pid %d, press Ctrl-C when done...\n", pid)

			var collected []streamer.Exchange
			for ex := range exchanges {
				collected = append(collected, ex)
			}

			tc, err := recorder.Build(name, collected)
			if err != nil {
				return fmt.Errorf("build test case: %w", err)
			}
			if err := storage.WriteYAML(output, tc); err != nil {
				return fmt.Errorf("write %s: %w", output, err)
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", output)
			return nil
		},
	}

	cmd.Flags().IntVar(&pid, "pid", 0, "PID to trace (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "path to write the YAML test case (required)")
	cmd.Flags().StringVar(&name, "name", "recorded-test", "name for the recorded test case")
	return cmd
}

// runCmd replays a recorded test case's Redis dependencies while running the
// given command -- no eBPF, no kernel-level redirection: the subprocess is
// simply pointed at the replay proxy's address via REDIS_ADDR instead of a
// real Redis, per the guide's stated v1 scope for M5.
func runCmd() *cobra.Command {
	var testPath string

	cmd := &cobra.Command{
		Use:   "run --test <path> -- <command> [args...]",
		Short: "Run a command with its Redis dependencies served from a recorded test case",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if testPath == "" {
				return fmt.Errorf("--test is required")
			}

			var tc recorder.TestCase
			if err := storage.ReadYAML(testPath, &tc); err != nil {
				return fmt.Errorf("read %s: %w", testPath, err)
			}

			var redisDeps []recorder.Dependency
			for _, dep := range tc.Dependencies {
				if dep.Type == "redis" {
					redisDeps = append(redisDeps, dep)
				}
			}

			// Bind before exec'ing the subprocess: otherwise the app's
			// first connection attempt could race the listener coming up.
			proxy, err := replay.NewProxy(redisDeps)
			if err != nil {
				return fmt.Errorf("start replay proxy: %w", err)
			}
			defer proxy.Close()
			go proxy.Serve()

			sub := exec.Command(args[0], args[1:]...)
			sub.Stdout = os.Stdout
			sub.Stderr = os.Stderr
			sub.Stdin = os.Stdin
			sub.Env = append(os.Environ(), "REDIS_ADDR="+proxy.Addr())

			if err := sub.Start(); err != nil {
				return fmt.Errorf("start %s: %w", args[0], err)
			}

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() {
				<-sigCh
				sub.Process.Signal(os.Interrupt)
			}()

			fmt.Fprintf(os.Stderr, "replaying %d redis dependencies from %s (proxy at %s)\n", len(redisDeps), testPath, proxy.Addr())
			return sub.Wait()
		},
	}

	cmd.Flags().StringVar(&testPath, "test", "", "path to a recorded YAML test case (required)")
	return cmd
}
