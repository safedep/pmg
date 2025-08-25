package analytics

const (
	eventRun           = "pmg_command_run"
	eventCommandNpm    = "pmg_command_npm"
	eventCommandBun    = "pmg_command_bun"
	eventCommandPnpm   = "pmg_command_pnpm"
	eventCommandPip    = "pmg_command_pip"
	eventCommandUv     = "pmg_command_uv"
	eventCommandPoetry = "pmg_command_poetry"

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

func TrackCommandBun() {
	TrackEvent(eventCommandBun)
}

func TrackCommandPnpm() {
	TrackEvent(eventCommandPnpm)
}

func TrackCommandPip() {
	TrackEvent(eventCommandPip)
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
