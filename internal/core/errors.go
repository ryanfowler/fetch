package core

import (
	"fmt"
	"time"
)

// ErrorCategory identifies the stable class of an operation failure.
type ErrorCategory uint8

const (
	CategoryUnknown ErrorCategory = iota
	CategoryUsage
	CategoryNetwork
	CategoryRemote
	CategoryPartial
	CategoryCancelled
	CategoryUpdateNoOp
)

func (category ErrorCategory) String() string {
	switch category {
	case CategoryUsage:
		return "usage/configuration"
	case CategoryNetwork:
		return "network/runtime"
	case CategoryRemote:
		return "remote protocol/status"
	case CategoryPartial:
		return "partial result"
	case CategoryCancelled:
		return "broken pipe/cancelled"
	case CategoryUpdateNoOp:
		return "update declined/no-op"
	default:
		return "unknown"
	}
}

// CategoryError adds stable classification while preserving the underlying
// error for errors.Is/errors.As and for useful diagnostics.
type CategoryError struct {
	Category ErrorCategory
	Err      error
}

func (err CategoryError) Error() string {
	if err.Err == nil {
		return err.Category.String()
	}
	return err.Err.Error()
}

func (err CategoryError) Unwrap() error { return err.Err }

func (err CategoryError) Is(target error) bool {
	other, ok := target.(CategoryError)
	return ok && err.Category == other.Category
}

func NewCategoryError(category ErrorCategory, cause error) error {
	if cause == nil {
		return nil
	}
	return CategoryError{Category: category, Err: cause}
}

func NewUsageError(cause error) error      { return NewCategoryError(CategoryUsage, cause) }
func NewNetworkError(cause error) error    { return NewCategoryError(CategoryNetwork, cause) }
func NewRemoteError(cause error) error     { return NewCategoryError(CategoryRemote, cause) }
func NewPartialError(cause error) error    { return NewCategoryError(CategoryPartial, cause) }
func NewCancelledError(cause error) error  { return NewCategoryError(CategoryCancelled, cause) }
func NewUpdateNoOpError(cause error) error { return NewCategoryError(CategoryUpdateNoOp, cause) }

func CategoryOf(err error) ErrorCategory {
	for err != nil {
		if categorized, ok := err.(CategoryError); ok {
			return categorized.Category
		}
		if categorized, ok := err.(*CategoryError); ok && categorized != nil {
			return categorized.Category
		}
		unwrapped := unwrapError(err)
		if unwrapped == err {
			break
		}
		err = unwrapped
	}
	return CategoryUnknown
}

type errorUnwrapper interface{ Unwrap() error }

func unwrapError(err error) error {
	if unwrapped, ok := err.(errorUnwrapper); ok {
		return unwrapped.Unwrap()
	}
	return err
}

// ErrRequestTimedOut represents the error when the request times out.
type ErrRequestTimedOut struct {
	Timeout time.Duration
}

func (err ErrRequestTimedOut) Error() string {
	return fmt.Sprintf("request timed out after %s", err.Timeout)
}

// ErrConnectionTimedOut represents an exhausted connection-establishment
// budget. It intentionally has a separate top-level message from request
// body/response timeouts.
type ErrConnectionTimedOut struct {
	Timeout time.Duration
}

func (err ErrConnectionTimedOut) Error() string {
	return fmt.Sprintf("connection timed out after %s", err.Timeout)
}

// TimeoutError is the common budget timeout error. It unwraps to the legacy
// timeout type so existing retry and presentation code remains compatible.
type TimeoutError struct {
	Duration   time.Duration
	Phase      string
	Connection bool
}

func (err TimeoutError) Error() string {
	message := "request timed out"
	if err.Connection {
		message = "connection timed out"
	}
	if err.Phase != "" {
		message += " during " + err.Phase
	}
	return fmt.Sprintf("%s after %s", message, err.Duration)
}

func (err TimeoutError) Unwrap() error {
	if err.Connection {
		return ErrConnectionTimedOut{Timeout: err.Duration}
	}
	return ErrRequestTimedOut{Timeout: err.Duration}
}

func (err TimeoutError) Timeout() bool   { return true }
func (err TimeoutError) Temporary() bool { return true }

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
	if err.usage != "" {
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

type FileNotExistsError string

func (err FileNotExistsError) Error() string {
	return fmt.Sprintf("file '%s' does not exist", string(err))
}

func (err FileNotExistsError) PrintTo(p *Printer) {
	p.WriteString("file '")
	p.Set(Dim)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("' does not exist")
}
