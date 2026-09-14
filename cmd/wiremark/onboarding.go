package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// introText is what a bare `wiremark` (no subcommand) prints. It's aimed at
// someone who has never seen the tool before and doesn't want to read the
// full README first.
const introText = `wiremark watches a program while it runs, writes down the HTTP
requests and Redis calls it makes, and lets you play that recording back
later -- without Redis needing to be running.

Try it in 3 steps:

  1. Watch your app while it's running
       sudo wiremark trace --pid <pid>

  2. Record one real request
       sudo wiremark record --pid <pid> -o test.yaml

  3. Replay it later, even with Redis turned off
       wiremark run --test test.yaml -- ./your-app

New here? Run 'wiremark quickstart' for a slower, step-by-step walkthrough,
or 'wiremark launch' for a menu that picks the flags for you.
`

// quickstartText is the guided walkthrough for someone who has never used a
// PID, never traced a process, and doesn't know what any of the flags mean.
const quickstartText = `wiremark, step by step
=======================

wiremark watches a running program and writes down what it does --
specifically its HTTP requests and any Redis calls it makes. Later, you
can replay that recording without Redis needing to be alive.

STEP 1 -- find the process you want to watch
  Every running program has a PID (a process ID number). If you're
  starting your app yourself, you already have it:
      ./your-app &
      APP_PID=$!
  Or find one that's already running:
      pgrep your-app

STEP 2 -- watch it live (optional -- just to see what's happening)
      sudo wiremark trace --pid $APP_PID
  This opens a live view of the syscalls your app is making.

STEP 3 -- record one real interaction
      sudo wiremark record --pid $APP_PID -o test.yaml
  While this is running, send your app a request (curl it, click the
  button, whatever triggers it), then press Ctrl-C. This writes
  test.yaml -- a plain-text file describing what just happened.

STEP 4 -- replay it, without Redis
      wiremark run --test test.yaml -- ./your-app
  Your app runs again, but this time wiremark answers its Redis calls
  using the recording. Redis itself doesn't need to be running at all.

Don't want to remember flags? Run 'wiremark launch' for an interactive
menu that walks you through picking a mode and a target.

Full docs: https://github.com/VidhuSarwal/wiremark/blob/main/GUIDE.md
`

func quickstartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quickstart",
		Short: "Print a step-by-step walkthrough for first-time use",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprint(cmd.OutOrStdout(), quickstartText)
		},
	}
}

// firstRunMarkerPath returns the path used to remember whether the one-time
// first-run banner has already been shown. It follows XDG conventions via
// os.UserConfigDir rather than inventing a bespoke dotfile location.
func firstRunMarkerPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wiremark", ".first-run"), nil
}

// isTerminal reports whether f looks like an interactive terminal rather
// than a pipe, file, or CI log. It's a minimal, dependency-free check
// (avoids pulling in golang.org/x/term for a single call site).
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// maybePrintFirstRunBanner prints a short, one-time pointer to `quickstart`
// the very first time wiremark is ever run on this machine, then stays
// silent on every invocation after that. It's skipped entirely for
// non-interactive stderr (CI, scripts, piped installs) so it never pollutes
// automated output.
func maybePrintFirstRunBanner() {
	if !isTerminal(os.Stderr) {
		return
	}

	path, err := firstRunMarkerPath()
	if err != nil {
		return // best-effort: don't fail a real command over a missing marker
	}
	if _, err := os.Stat(path); err == nil {
		return // already shown before
	}

	fmt.Fprintln(os.Stderr, "wiremark: first time seeing you here -- run `wiremark quickstart` for a step-by-step walkthrough.")
	fmt.Fprintln(os.Stderr)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, nil, 0o644)
}
