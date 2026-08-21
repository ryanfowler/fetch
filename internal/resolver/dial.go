package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	happyEyeballsDelay = 100 * time.Millisecond
	maxDialCandidates  = 16
)

// RaceCandidates starts address attempts with a bounded Happy Eyeballs delay.
// The caller controls the transport attempt and loser cleanup, so the same
// policy works for TCP, TLS, and QUIC. The candidate order is significant:
// callers should put their preferred address family first.
func RaceCandidates[T any](ctx context.Context, candidates []net.IPAddr, attempt func(context.Context, net.IPAddr) (T, error), closeResult func(T)) (T, error) {
	var zero T
	if ctx == nil {
		return zero, errors.New("dial context is nil")
	}
	if attempt == nil {
		return zero, errors.New("dial attempt is nil")
	}
	candidates = deduplicateAddresses(candidates)
	if len(candidates) > maxDialCandidates {
		candidates = candidates[:maxDialCandidates]
	}
	if len(candidates) == 0 {
		return zero, errors.New("no addresses found")
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The channel is large enough for every attempt. This is important: once
	// a winner is selected we return immediately, and a dial implementation is
	// allowed to finish later even when it does not observe cancellation. A
	// result sender must never be left blocked by the race coordinator.
	results := make(chan candidateResult[T], len(candidates))
	// -1 means that the race is still selecting a winner. A non-negative value
	// identifies the winner, and -2 means that the caller cancelled or that all
	// attempts failed. Attempt goroutines use this state to close late loser
	// connections without a background drain goroutine that could leak forever.
	var state atomic.Int32
	state.Store(-1)

	launch := func(index int, candidate net.IPAddr) {
		go func() {
			value, err := attempt(raceCtx, candidate)
			var close sync.Once
			closeValue := func() {
				if closeResult != nil {
					close.Do(func() { closeResult(value) })
				}
			}
			if err == nil {
				// The post-send check closes a successful attempt that completed
				// concurrently with selection of another winner. The selected
				// result has the same index and is never closed here.
				defer func() {
					if selected := state.Load(); selected >= 0 && selected != int32(index) {
						closeValue()
					} else if selected == -2 {
						closeValue()
					}
				}()
			}
			results <- candidateResult[T]{index: index, value: value, err: err, close: closeValue}
		}()
	}

	next, active := 1, 1
	launch(0, candidates[0])
	timer := time.NewTimer(happyEyeballsDelay)
	defer timer.Stop()
	var timerC <-chan time.Time = timer.C
	var lastErr error
	for active > 0 || next < len(candidates) {
		if active == 0 && next < len(candidates) {
			launch(next, candidates[next])
			next++
			active++
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timerC = nil
		}
		select {
		case got := <-results:
			active--
			if got.err == nil {
				state.Store(int32(got.index))
				cancel()
				// Close successful losers that already completed. Later
				// completions close themselves after observing the state.
				for i := 0; i < active; i++ {
					select {
					case loser := <-results:
						if loser.err == nil && loser.index != got.index {
							loser.close()
						}
					default:
						// Results that are not ready will close themselves when
						// their attempt observes the selected winner.
						i = active
					}
				}
				return got.value, nil
			}
			lastErr = got.err
		case <-timerC:
			if next < len(candidates) {
				launch(next, candidates[next])
				next++
				active++
			}
			if next < len(candidates) {
				timer.Reset(happyEyeballsDelay)
				timerC = timer.C
			} else {
				timerC = nil
			}
		case <-ctx.Done():
			state.Store(-2)
			cancel()
			return zero, contextError(ctx)
		}
	}
	state.Store(-2)
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	if lastErr == nil {
		lastErr = errors.New("all resolved addresses failed")
	}
	return zero, lastErr
}

type candidateResult[T any] struct {
	index int
	value T
	err   error
	close func()
}
