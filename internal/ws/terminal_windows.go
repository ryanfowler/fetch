//go:build windows

package ws

import (
	"context"
	"time"
)

// watchResize polls for terminal size changes on Windows (no SIGWINCH).
// It blocks until ctx is cancelled.
func (t *terminal) watchResize(ctx context.Context, resizeCh chan<- struct{}) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	prevRows, prevCols := t.size()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.refreshSize()
			rows, cols := t.size()
			if rows != prevRows || cols != prevCols {
				prevRows = rows
				prevCols = cols
				select {
				case resizeCh <- struct{}{}:
				default:
				}
			}
		}
	}
}
