package version

import runtimeDebug "runtime/debug"

var (
	Version string
	Commit  string
)

func init() {
	buildInfo, ok := runtimeDebug.ReadBuildInfo()
	if !ok {
		return
	}

	if Version == "" {
		Version = buildInfo.Main.Version
	}

	if Commit == "" {
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.revision" {
				Commit = setting.Value
				break
			}
		}
	}
}
