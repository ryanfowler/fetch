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
	IsStderrTerm = term.IsTerminal(int(os.Stderr.Fd()))
	IsStdoutTerm = term.IsTerminal(int(os.Stdout.Fd()))

	Version = getVersion()
	UserAgent = "fetch/" + Version
}

func getVersion() string {
	var ok bool
	buildInfo, ok = debug.ReadBuildInfo()
	if !ok || buildInfo.Main.Version == "" {
		return "v(dev)"
	}
	return buildInfo.Main.Version
}

func GetVersions() []byte {
	type Versions struct {
		Fetch    string            `json:"fetch"`
		Go       string            `json:"go,omitzero"`
		Deps     map[string]string `json:"deps,omitzero"`
		Settings map[string]string `json:"settings,omitzero"`
	}

	vs := Versions{Fetch: Version}
	if buildInfo != nil {
		vs.Go = buildInfo.GoVersion

		if len(buildInfo.Deps) > 0 {
			vs.Deps = make(map[string]string, len(buildInfo.Deps))
			for _, dep := range buildInfo.Deps {
				vs.Deps[dep.Path] = dep.Version
			}
		}

		if len(buildInfo.Settings) > 0 {
			vs.Settings = make(map[string]string, len(buildInfo.Settings))
			for _, setting := range buildInfo.Settings {
				vs.Settings[setting.Key] = setting.Value
			}
		}
	}

	out, _ := json.Marshal(vs)
	return out
}
