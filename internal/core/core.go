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

// Verbosity represents how verbose the output should be.
type Verbosity int

const (
	VSilent Verbosity = iota
	VNormal
	VVerbose
	VExtraVerbose
)

type KeyVal struct {
	Key, Val string
}
