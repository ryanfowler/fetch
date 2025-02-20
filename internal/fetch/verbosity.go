package fetch

type Verbosity int

const (
	VSilent Verbosity = iota
	VNormal
	VVerbose
	VExtraVerbose
)
