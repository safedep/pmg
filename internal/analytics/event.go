package analytics

const (
	eventRun           = "pmg_command_run"
	eventCommandNpm    = "pmg_command_npm"
	eventCommandBun    = "pmg_command_bun"
	eventCommandPnpm   = "pmg_command_pnpm"
	eventCommandYarn   = "pmg_command_yarn"
	eventCommandPip    = "pmg_command_pip"
	eventCommandPip3   = "pmg_command_pip3"
	eventCommandUv     = "pmg_command_uv"
	eventCommandPoetry = "pmg_command_poetry"

	eventCommandNpx  = "pmg_command_npx"
	eventCommandPnpx = "pmg_command_pnpx"

	eventPmgGenerateEnvDocker        = "pmg_command_generate_env_docker"
	eventPmgGenerateEnvGitHubActions = "pmg_command_generate_env_github_actions"
	eventPmgGenerateEnvGitLabCI      = "pmg_command_generate_env_gitlab_ci"
)

func TrackCommandRun() {
	TrackEvent(eventRun)
}

func TrackCommandNpm() {
	TrackEvent(eventCommandNpm)
}

func TrackCommandNpx() {
	TrackEvent(eventCommandNpx)
}

func TrackCommandPnpx() {
	TrackEvent(eventCommandPnpx)
}

func TrackCommandBun() {
	TrackEvent(eventCommandBun)
}

func TrackCommandPnpm() {
	TrackEvent(eventCommandPnpm)
}

func TrackCommandYarn() {
	TrackEvent(eventCommandYarn)
}

func TrackCommandPip() {
	TrackEvent(eventCommandPip)
}

func TrackCommandPip3() {
	TrackEvent(eventCommandPip3)
}

func TrackCommandUv() {
	TrackEvent(eventCommandUv)
}

func TrackCommandPoetry() {
	TrackEvent(eventCommandPoetry)
}

func TrackCommandGenerateEnvDocker() {
	TrackEvent(eventPmgGenerateEnvDocker)
}

func TrackCommandGenerateEnvGitHubActions() {
	TrackEvent(eventPmgGenerateEnvGitHubActions)
}

func TrackCommandGenerateEnvGitLabCI() {
	TrackEvent(eventPmgGenerateEnvGitLabCI)
}
