package core

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Budget is an immutable wall-clock budget. A zero duration is unlimited;
// every finite child operation observes the same absolute deadline.
type Budget struct {
	start    time.Time
	deadline time.Time
	timeout  time.Duration
	limited  bool
}

// NewBudget creates a budget starting at the current wall-clock time.
func NewBudget(timeout time.Duration) (Budget, error) {
	return NewBudgetAt(timeout, time.Now())
}

// NewBudgetFromOptional treats nil as an unlimited budget. It is convenient
// for configuration fields where absence and an explicit zero both disable a
// timeout.
func NewBudgetFromOptional(timeout *time.Duration) (Budget, error) {
	return NewBudgetFromOptionalAt(timeout, time.Now())
}

// NewBudgetFromOptionalAt is the injectable-clock form of
// NewBudgetFromOptional.
func NewBudgetFromOptionalAt(timeout *time.Duration, start time.Time) (Budget, error) {
	if timeout == nil {
		return NewBudgetAt(0, start)
	}
	return NewBudgetAt(*timeout, start)
}

// NewBudgetAt creates a budget with an injectable start time for deterministic
// tests. Negative durations are invalid; zero means no deadline.
func NewBudgetAt(timeout time.Duration, start time.Time) (Budget, error) {
	if timeout < 0 {
		return Budget{}, fmt.Errorf("timeout must be non-negative: %s", timeout)
	}
	if start.IsZero() {
		return Budget{}, errors.New("budget start time is required")
	}
	if timeout == 0 {
		return Budget{start: start}, nil
	}
	deadline := start.Add(timeout)
	if !deadline.After(start) {
		return Budget{}, errors.New("timeout overflows deadline")
	}
	return Budget{start: start, deadline: deadline, timeout: timeout, limited: true}, nil
}

// Limited reports whether this budget has a finite deadline.
func (b Budget) Limited() bool { return b.limited }

// Deadline returns the absolute deadline, if this budget is finite.
func (b Budget) Deadline() (time.Time, bool) { return b.deadline, b.limited }

// Remaining returns the time left and whether the budget is finite. An
// exhausted finite budget returns zero and true; an unlimited budget returns
// zero and false.
func (b Budget) Remaining() (time.Duration, bool) {
	return b.RemainingAt(time.Now())
}

// RemainingAt is Remaining with an injected clock for deterministic tests.
func (b Budget) RemainingAt(now time.Time) (time.Duration, bool) {
	if !b.limited {
		return 0, false
	}
	remaining := b.deadline.Sub(now)
	if remaining <= 0 {
		return 0, true
	}
	return remaining, true
}

// Expired reports whether a finite budget has elapsed.
func (b Budget) Expired() bool {
	remaining, limited := b.Remaining()
	return limited && remaining == 0
}

// TimeoutError returns the stable error for an exhausted budget.
func (b Budget) TimeoutError(phase string) error {
	return TimeoutError{Duration: b.timeout, Phase: phase}
}

// ConnectionTimeoutError returns the connection-scoped form of the budget
// error while retaining the same absolute deadline.
func (b Budget) ConnectionTimeoutError(phase string) error {
	return TimeoutError{Duration: b.timeout, Phase: phase, Connection: true}
}

// Check reports a timeout when the budget is exhausted. It is an explicit
// checkpoint for operations that do not yet derive a context.
func (b Budget) Check(phase string) error {
	if !b.Expired() {
		return nil
	}
	return b.TimeoutError(phase)
}

// Err returns nil while the budget remains available, or its stable timeout
// error after exhaustion.
func (b Budget) Err() error {
	if !b.Expired() {
		return nil
	}
	return b.TimeoutError("")
}

// ErrAt is Err with an injected clock and optional phase label.
func (b Budget) ErrAt(now time.Time, phase string) error {
	remaining, limited := b.RemainingAt(now)
	if !limited || remaining > 0 {
		return nil
	}
	return b.TimeoutError(phase)
}

// WithContext derives a cancellable context that observes this budget. If a
// parent deadline is earlier, it is preserved rather than being reset.
func (b Budget) WithContext(parent context.Context, phase string) (context.Context, context.CancelFunc) {
	return b.withContext(parent, phase, false)
}

// WithConnectionContext derives a context whose timeout is reported as a
// connection timeout. It shares the same absolute deadline as WithContext.
func (b Budget) WithConnectionContext(parent context.Context, phase string) (context.Context, context.CancelFunc) {
	return b.withContext(parent, phase, true)
}

func (b Budget) withContext(parent context.Context, phase string, connection bool) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if !b.limited {
		return context.WithCancel(parent)
	}
	if parentDeadline, ok := parent.Deadline(); ok && !b.deadline.Before(parentDeadline) {
		return context.WithCancel(parent)
	}

	var cause error
	if connection {
		cause = b.ConnectionTimeoutError(phase)
	} else {
		cause = b.TimeoutError(phase)
	}
	return context.WithDeadlineCause(parent, b.deadline, cause)
}

// Child returns a budget view with the same immutable deadline. The phase is
// used only when the child derives a context or reports its timeout.
func (b Budget) Child(phase string) BudgetChild { return BudgetChild{budget: b, phase: phase} }

// BudgetChild associates a diagnostic phase with an existing budget without
// creating a new deadline.
type BudgetChild struct {
	budget Budget
	phase  string
}

func (c BudgetChild) Remaining() (time.Duration, bool) { return c.budget.Remaining() }

func (c BudgetChild) Err() error {
	if !c.budget.Expired() {
		return nil
	}
	return c.budget.TimeoutError(c.phase)
}

func (c BudgetChild) WithContext(parent context.Context) (context.Context, context.CancelFunc) {
	return c.budget.WithContext(parent, c.phase)
}
