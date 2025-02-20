package vars

import (
	"os"

	"golang.org/x/term"
)

var (
	IsStderrTerm bool
	IsStdoutTerm bool
)

type KeyVal struct {
	Key, Val string
}

func init() {
	IsStderrTerm = term.IsTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = term.IsTerminal(int(os.Stdout.Fd()))
}
