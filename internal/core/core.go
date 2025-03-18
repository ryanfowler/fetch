package core

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
)

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
)

// KeyVal represents a generic key & value struct.
type KeyVal struct {
	Key, Val string
}

// PointerTo returns a pointer to the value provided.
func PointerTo[T any](t T) *T {
	return &t
}
