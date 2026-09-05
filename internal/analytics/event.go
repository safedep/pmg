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
	eventCommandPipx   = "pmg_command_pipx"
	eventCommandUvx    = "pmg_command_uvx"
	eventCommandGo     = "pmg_command_go"
	eventCommandCargo  = "pmg_command_cargo"

	eventCommandNpx  = "pmg_command_npx"
	eventCommandPnpx = "pmg_command_pnpx"

	eventCommandAube = "pmg_command_aube"
	eventCommandAubr = "pmg_command_aubr"
	eventCommandAubx = "pmg_command_aubx"

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

func TrackCommandAube() {
	TrackEvent(eventCommandAube)
}

func TrackCommandAubr() {
	TrackEvent(eventCommandAubr)
}

func TrackCommandAubx() {
	TrackEvent(eventCommandAubx)
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

func TrackCommandPipx() {
	TrackEvent(eventCommandPipx)
}

func TrackCommandUvx() {
	TrackEvent(eventCommandUvx)
}

func TrackCommandGo() {
	TrackEvent(eventCommandGo)
}

func TrackCommandCargo() {
	TrackEvent(eventCommandCargo)
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
