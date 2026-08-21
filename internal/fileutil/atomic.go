package fileutil

import (
	"errors"
	"sync"
)

var noSymlinkCommitMu sync.Mutex

// CommittedError reports a cleanup error after the destination was already
// installed. Callers must not report the operation as an uncommitted write.
type CommittedError struct {
	Err error
}

func (e *CommittedError) Error() string { return "destination committed: " + e.Err.Error() }
func (e *CommittedError) Unwrap() error { return e.Err }

func committedError(err error) bool {
	var committed *CommittedError
	return errors.As(err, &committed)
}
