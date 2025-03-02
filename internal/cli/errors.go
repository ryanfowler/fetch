package cli

import (
	"fmt"

	"github.com/ryanfowler/fetch/internal/core"
)

type unknownFlagError string

func (err unknownFlagError) Error() string {
	return fmt.Sprintf("unknown flag '%s'", string(err))
}

func (err unknownFlagError) PrintTo(p *core.Printer) {
	p.WriteString("unknown flag '")
	p.Set(core.Bold)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("'")
}

type exclusiveFlagsError struct {
	first, second string
}

func newExclusiveFlagsError(first, second string) exclusiveFlagsError {
	return exclusiveFlagsError{first: first, second: second}
}

func (err exclusiveFlagsError) Error() string {
	return fmt.Sprintf("flags '--%s' and '--%s' cannot be used together", err.first, err.second)
}

func (err exclusiveFlagsError) PrintTo(p *core.Printer) {
	p.WriteString("flags '")
	p.Set(core.Bold)
	p.WriteString("--")
	p.WriteString(err.first)
	p.Reset()
	p.WriteString("' and '")
	p.Set(core.Bold)
	p.WriteString("--")
	p.WriteString(err.second)
	p.Reset()
	p.WriteString("' cannot be used together")
}

type flagNoArgsError string

func (err flagNoArgsError) Error() string {
	return fmt.Sprintf("flag '%s' does not take any arguments", string(err))
}

func (err flagNoArgsError) PrintTo(p *core.Printer) {
	p.WriteString("flag '")
	p.Set(core.Bold)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("' does not take any arguments")
}

type argRequiredError string

func (err argRequiredError) Error() string {
	return fmt.Sprintf("argument required for flag '%s'", string(err))
}

func (err argRequiredError) PrintTo(p *core.Printer) {
	p.WriteString("argument required for flag '")
	p.Set(core.Bold)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("'")
}
