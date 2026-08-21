package resolver

import (
	"context"
	"errors"
	"net"
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
	candidates = deduplicateAddresses(candidates)
	if len(candidates) > maxDialCandidates {
		candidates = candidates[:maxDialCandidates]
	}
	if len(candidates) == 0 {
		return zero, errors.New("no addresses found")
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan candidateResult[T], len(candidates))
	launch := func(candidate net.IPAddr) {
		go func() {
			value, err := attempt(raceCtx, candidate)
			results <- candidateResult[T]{value: value, err: err}
		}()
	}

	next, active := 1, 1
	launch(candidates[0])
	timer := time.NewTimer(happyEyeballsDelay)
	defer timer.Stop()
	var timerC <-chan time.Time = timer.C
	var lastErr error
	for active > 0 || next < len(candidates) {
		if active == 0 && next < len(candidates) {
			launch(candidates[next])
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
				cancel()
				go drainCandidates(results, active, closeResult)
				return got.value, nil
			}
			lastErr = got.err
		case <-timerC:
			if next < len(candidates) {
				launch(candidates[next])
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
			cancel()
			go drainCandidates(results, active, closeResult)
			return zero, ctx.Err()
		}
	}
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	if lastErr == nil {
		lastErr = errors.New("all resolved addresses failed")
	}
	return zero, lastErr
}

type candidateResult[T any] struct {
	value T
	err   error
}

func drainCandidates[T any](results <-chan candidateResult[T], count int, closeResult func(T)) {
	for range count {
		got := <-results
		if got.err == nil && closeResult != nil {
			closeResult(got.value)
		}
	}
}
