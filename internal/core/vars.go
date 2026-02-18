package core

import (
	"encoding/json"
	"os"
	"runtime/debug"
)

// TerminalSize represents the dimensions of the terminal.
type TerminalSize struct {
	Cols     int // Number of columns (characters)
	Rows     int // Number of rows (characters)
	WidthPx  int // Width in pixels (0 if unavailable)
	HeightPx int // Height in pixels (0 if unavailable)
}

var packageManager string // set via ldflags to disable self-update (e.g. "Homebrew")

var (
	IsStdinTerm    bool
	IsStderrTerm   bool
	IsStdoutTerm   bool
	NoSelfUpdate   bool
	PackageManager string

	UserAgent string
	Version   string

	buildInfo *debug.BuildInfo
)

func init() {
	// Determine if stdin, stderr and stdout are TTYs.
	IsStdinTerm = isTerminal(int(os.Stdin.Fd()))
	IsStderrTerm = isTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = isTerminal(int(os.Stdout.Fd()))

	// Set whether self-update is disabled.
	PackageManager = packageManager
	NoSelfUpdate = PackageManager != ""

	// Set executable version and user-agent.
	Version = getVersion()
	UserAgent = "fetch/" + Version
}

// getVersion attempts to read the executable's BuildInfo, returning the version.
func getVersion() string {
	var ok bool
	buildInfo, ok = debug.ReadBuildInfo()
	if !ok || buildInfo.Main.Version == "" {
		return "v(dev)"
	}
	return buildInfo.Main.Version
}

// GetVCSRevision returns the git commit hash from Go's embedded build info.
func GetVCSRevision() string {
	if buildInfo == nil {
		return ""
	}
	for _, setting := range buildInfo.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return ""
}

// GetBuildInfo returns the JSON encoded build information for the executable.
func GetBuildInfo() []byte {
	type BuildInfo struct {
		Fetch    string            `json:"fetch"`
		Go       string            `json:"go,omitzero"`
		Settings map[string]string `json:"settings,omitzero"`
		Deps     map[string]string `json:"deps,omitzero"`
	}

	bi := BuildInfo{Fetch: Version}
	if buildInfo != nil {
		bi.Go = buildInfo.GoVersion

		if len(buildInfo.Deps) > 0 {
			bi.Deps = make(map[string]string, len(buildInfo.Deps))
			for _, dep := range buildInfo.Deps {
				bi.Deps[dep.Path] = dep.Version
			}
		}

		if len(buildInfo.Settings) > 0 {
			bi.Settings = make(map[string]string, len(buildInfo.Settings))
			for _, setting := range buildInfo.Settings {
				bi.Settings[setting.Key] = setting.Value
			}
		}
	}

	out, _ := json.Marshal(bi)
	return out
}
