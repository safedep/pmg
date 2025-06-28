package analytics

const (
	eventRun         = "pmg_command_run"
	eventCommandNpm  = "pmg_command_npm"
	eventCommandPnpm = "pmg_command_pnpm"
	eventCommandPip  = "pmg_command_pip"

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

func TrackCommandPnpm() {
	TrackEvent(eventCommandPnpm)
}

func TrackCommandPip() {
	TrackEvent(eventCommandPip)
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
