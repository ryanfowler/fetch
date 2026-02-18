package core

import "strings"

// Color represents the options for enabling or disabling color output.
type Color int

const (
	ColorUnknown Color = iota
	ColorAuto
	ColorOn
	ColorOff
)

// Format represents the options for enabling or disabling formatting.
type Format int

const (
	FormatUnknown Format = iota
	FormatAuto
	FormatOff
	FormatOn
)

// HTTPVersion represents the options for the maximum allowed HTTP version.
type HTTPVersion int

const (
	HTTPDefault HTTPVersion = iota
	HTTP1
	HTTP2
	HTTP3
)

// String returns the HTTP version string (e.g. "HTTP/1.1").
func (v HTTPVersion) String() string {
	switch v {
	case HTTP1:
		return "HTTP/1.1"
	case HTTP2:
		return "HTTP/2.0"
	case HTTP3:
		return "HTTP/3.0"
	default:
		return ""
	}
}

// ImageSetting represents the options for displaying images.
type ImageSetting int

const (
	ImageUnknown ImageSetting = iota
	ImageAuto
	ImageNative
	ImageOff
)

// Verbosity represents how verbose the output should be.
type Verbosity int

const (
	VSilent Verbosity = iota
	VNormal
	VVerbose
	VExtraVerbose
	VDebug
)

// KeyVal represents a generic key & value struct.
type KeyVal[T any] struct {
	Key string
	Val T
}

// CutTrimmed splits s around the first instance of sep, returning the
// trimmed text before and after sep.
func CutTrimmed(s, sep string) (string, string, bool) {
	key, val, ok := strings.Cut(s, sep)
	return strings.TrimSpace(key), strings.TrimSpace(val), ok
}
