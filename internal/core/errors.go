package core

import (
	"fmt"
	"time"
)

// ErrRequestTimedOut represents the error when the request times out.
type ErrRequestTimedOut struct {
	Timeout time.Duration
}

func (err ErrRequestTimedOut) Error() string {
	return fmt.Sprintf("request timed out after %s", err.Timeout)
}

// SignalError represents the error when a signal is caught.
type SignalError string

func (err SignalError) Error() string {
	return fmt.Sprintf("received signal: %s", string(err))
}
