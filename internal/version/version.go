package version

import runtimeDebug "runtime/debug"

var (
	Version string
	Commit  string
)

func init() {
	if Version == "" {
		buildInfo, _ := runtimeDebug.ReadBuildInfo()
		Version = buildInfo.Main.Version
	}
}
