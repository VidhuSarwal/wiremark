// Package tui is the bubbletea live-view consumer of the collector's Event
// stream. Implemented in a follow-up commit; stubbed for now so cmd/etrace
// can wire up --no-tui as the working path first.
package tui

import (
	"fmt"
	"time"

	"github.com/vidhu/etracer/internal/collector"
)

func Run(events <-chan collector.Event, timeOf func(collector.Event) time.Time) error {
	return fmt.Errorf("tui: not yet implemented, use --no-tui")
}
