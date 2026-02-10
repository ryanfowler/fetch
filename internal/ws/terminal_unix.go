//go:build unix

package ws

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// watchResize listens for SIGWINCH and signals resizeCh on terminal size
// changes. It blocks until ctx is cancelled.
func (t *terminal) watchResize(ctx context.Context, resizeCh chan<- struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			t.refreshSize()
			select {
			case resizeCh <- struct{}{}:
			default:
			}
		}
	}
}
