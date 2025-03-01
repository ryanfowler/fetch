package core

import (
	"encoding/json"
	"os"
	"runtime/debug"

	"golang.org/x/term"
)

var (
	IsStderrTerm bool
	IsStdoutTerm bool

	UserAgent string
	Version   string

	buildInfo *debug.BuildInfo
)

func init() {
	// Determine if stderr and stdout are TTYs.
	IsStderrTerm = term.IsTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = term.IsTerminal(int(os.Stdout.Fd()))

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

// GetBuildInfo returns the JSON encoded build information for the executable.
func GetBuildInfo() []byte {
	type BuildInfo struct {
		Fetch    string            `json:"fetch"`
		Go       string            `json:"go,omitzero"`
		Deps     map[string]string `json:"deps,omitzero"`
		Settings map[string]string `json:"settings,omitzero"`
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
