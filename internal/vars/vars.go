package vars

import (
	"os"

	"github.com/ryanfowler/fetch"

	"golang.org/x/term"
)

var (
	UserAgent string
	Version   = fetch.Version

	IsStderrTerm bool
	IsStdoutTerm bool
)

type KeyVal struct {
	Key, Val string
}

func init() {
	UserAgent = "fetch/" + Version

	IsStderrTerm = term.IsTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = term.IsTerminal(int(os.Stdout.Fd()))
}
