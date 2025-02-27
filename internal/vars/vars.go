package vars

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

var (
	IsStderrTerm bool
	IsStdoutTerm bool
)

func init() {
	IsStderrTerm = term.IsTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = term.IsTerminal(int(os.Stdout.Fd()))
}

type KeyVal struct {
	Key, Val string
}

type SignalError string

func (err SignalError) Error() string {
	return fmt.Sprintf("received signal: %s", string(err))
}
