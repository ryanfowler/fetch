package vars

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"golang.org/x/term"
)

var (
	IsStderrTerm bool
	IsStdoutTerm bool

	UserAgent string
	Version   string
)

func init() {
	IsStderrTerm = term.IsTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = term.IsTerminal(int(os.Stdout.Fd()))

	Version = getVersion()
	UserAgent = "fetch/" + Version
}

func getVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "v(dev)"
	}
	return info.Main.Version
}

type KeyVal struct {
	Key, Val string
}

type ErrRequestTimedOut struct {
	Timeout time.Duration
}

func (err ErrRequestTimedOut) Error() string {
	return fmt.Sprintf("request timed out after %s", err.Timeout)
}

type SignalError string

func (err SignalError) Error() string {
	return fmt.Sprintf("received signal: %s", string(err))
}
