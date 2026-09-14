package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShouldShowFirstRunBanner(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"quickstart"}, false},
		{[]string{"--help"}, false},
		{[]string{"-h"}, false},
		{[]string{"trace", "--pid", "123"}, true},
		{[]string{"record"}, true},
		{[]string{"launch"}, true},
	}

	for _, tc := range cases {
		if got := shouldShowFirstRunBanner(tc.args); got != tc.want {
			t.Errorf("shouldShowFirstRunBanner(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestFirstRunMarkerPathUsesConfigDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	path, err := firstRunMarkerPath()
	if err != nil {
		t.Fatalf("firstRunMarkerPath() error: %v", err)
	}

	want := filepath.Join(dir, "wiremark", ".first-run")
	if path != want {
		t.Errorf("firstRunMarkerPath() = %q, want %q", path, want)
	}
}

func TestMaybePrintFirstRunBannerIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	path, err := firstRunMarkerPath()
	if err != nil {
		t.Fatalf("firstRunMarkerPath() error: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("marker already exists before first call: %s", path)
	}

	// isTerminal(os.Stderr) will be false under `go test` (stderr is
	// redirected), so maybePrintFirstRunBanner should be a no-op here --
	// this test only exercises that it doesn't panic or error, and that
	// repeated calls stay consistent. The marker-creation path itself is
	// covered indirectly via firstRunMarkerPath + the isTerminal guard
	// documented in maybePrintFirstRunBanner.
	maybePrintFirstRunBanner()
	maybePrintFirstRunBanner()

	if _, err := os.Stat(path); err == nil {
		t.Fatalf("marker was created despite non-terminal stderr under `go test`: %s", path)
	}
}

func TestIsTerminalFalseForRegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()

	if isTerminal(f) {
		t.Error("isTerminal(regular file) = true, want false")
	}
}
