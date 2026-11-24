package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRaceCandidatesClosesSuccessesWhenCancelled(t *testing.T) {
	// Cancel the race at the moment an attempt succeeds. Every successful
	// result that the caller does not receive must be closed.
	candidates := []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}
	var opened, closed atomic.Int64
	for range 2000 {
		ctx, cancel := context.WithCancel(context.Background())
		var once sync.Once
		attempt := func(context.Context, net.IPAddr) (int, error) {
			opened.Add(1)
			once.Do(cancel)
			return 1, nil
		}
		value, err := RaceCandidates(ctx, candidates, attempt, func(int) { closed.Add(1) })
		if err == nil && value == 1 {
			// The caller owns a returned result.
			closed.Add(1)
		}
		cancel()
	}
	// Closing can finish after RaceCandidates returns, in the attempt's own
	// goroutine. Wait for that, also on a slow machine.
	deadline := time.Now().Add(5 * time.Second)
	for closed.Load() != opened.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if o, c := opened.Load(), closed.Load(); o != c {
		t.Fatalf("opened %d results, closed %d", o, c)
	}
}
