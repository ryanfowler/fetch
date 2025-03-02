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

type ValueError struct {
	isFile bool
	option string
	value  string
	usage  string
}

func NewValueError(option, value, usage string, isFile bool) *ValueError {
	return &ValueError{
		isFile: isFile,
		option: option,
		value:  value,
		usage:  usage,
	}
}

func (err *ValueError) Error() string {
	option := err.option
	if !err.isFile {
		option = "--" + option
	}
	msg := fmt.Sprintf("invalid value '%s' for option '%s'", err.value, option)
	if err.usage == "" {
		msg = fmt.Sprintf("%s: %s", msg, err.usage)
	}
	return msg
}

func (err *ValueError) PrintTo(p *Printer) {
	p.WriteString("invalid value '")
	p.Set(Yellow)
	p.WriteString(err.value)
	p.Reset()

	p.WriteString("' for option '")
	p.Set(Bold)
	if !err.isFile {
		p.WriteString("--")
	}
	p.WriteString(err.option)
	p.Reset()
	p.WriteString("'")

	if err.usage != "" {
		p.WriteString(": ")
		p.WriteString(err.usage)
	}
}
