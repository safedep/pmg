package util

import (
	"os"
	"path/filepath"
)

// DANGEROUS_FILES are credential and config files blocked by default.
// Users opt out via allow_read / allow_write (see GetMandatoryDenyPatterns).
var DANGEROUS_FILES = []string{
	".env",
	".env.*",
	".aws",
	".azure",
	".gcloud",
	".config/gcloud",
	".kube",
	".ssh",
	".gnupg",
	".docker/config.json",
	".netrc",
	".git-credentials",
	".pgpass",
	".config/gh",
}

// DANGEROUS_ENV_VARS are credential-bearing environment variables scrubbed from
// the child process by default when the sandbox is enabled (see ScrubEnv). This
// is an explicit, curated list of known secret names. There are deliberately
// no generic "*_TOKEN" / "*_SECRET" catch-alls here, because broad wildcards in
// the default would risk clipping legitimate build variables for every user.
// The matcher (ScrubEnv) does support glob patterns, so users who want broader
// coverage opt into it per profile via environment.deny.
//
// Matching is case-insensitive (see ScrubEnv). A package manager's own
// publishing token is intentionally left scrubbable here and re-allowed per
// ecosystem in the profile's environment.allow (e.g. npm re-allows NPM_TOKEN).
var DANGEROUS_ENV_VARS = []string{
	// Cloud providers
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_SECURITY_TOKEN",
	"AZURE_CLIENT_SECRET",
	"AZURE_CLIENT_ID",
	"AZURE_TENANT_ID",
	"ARM_CLIENT_SECRET",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"GOOGLE_CREDENTIALS",
	"GOOGLE_OAUTH_ACCESS_TOKEN",
	"GCP_SERVICE_ACCOUNT_KEY",
	"CLOUDSDK_AUTH_ACCESS_TOKEN",
	"DIGITALOCEAN_ACCESS_TOKEN",
	"DIGITALOCEAN_TOKEN",
	"CLOUDFLARE_API_TOKEN",
	"CLOUDFLARE_API_KEY",
	"HEROKU_API_KEY",
	"FLY_API_TOKEN",
	"RAILWAY_TOKEN",
	"VERCEL_TOKEN",
	"NETLIFY_AUTH_TOKEN",

	// Package registry / publishing tokens
	"NPM_TOKEN",
	"NPM_AUTH_TOKEN",
	"NODE_AUTH_TOKEN",
	"NPM_CONFIG__AUTH",
	"YARN_NPM_AUTH_TOKEN",
	"YARN_NPM_AUTH_IDENT",
	"BUN_AUTH_TOKEN",
	"TWINE_USERNAME",
	"TWINE_PASSWORD",
	"PYPI_TOKEN",
	"UV_PUBLISH_TOKEN",
	"FLIT_PASSWORD",
	"POETRY_PYPI_TOKEN_PYPI",
	"POETRY_HTTP_BASIC_PYPI_PASSWORD",
	"ANACONDA_API_TOKEN",
	"GEM_HOST_API_KEY",
	"RUBYGEMS_API_KEY",
	"CARGO_REGISTRY_TOKEN",
	"COMPOSER_AUTH",
	"HEX_API_KEY",
	"NUGET_API_KEY",
	"CONAN_LOGIN_PASSWORD",
	"CONAN_PASSWORD",
	"DENO_AUTH_TOKENS",
	"EXPO_TOKEN",
	"JFROG_ACCESS_TOKEN",
	"ARTIFACTORY_ACCESS_TOKEN",
	"ARTIFACTORY_API_KEY",
	"ARTIFACTORY_PASSWORD",

	// VCS / CI
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"GH_ENTERPRISE_TOKEN",
	"GITLAB_TOKEN",
	"CI_JOB_TOKEN",
	"CIRCLE_TOKEN",
	"BUILDKITE_AGENT_TOKEN",
	"BUILDKITE_API_TOKEN",
	"AZURE_DEVOPS_EXT_PAT",
	"SYSTEM_ACCESSTOKEN",

	// Secrets managers
	"VAULT_TOKEN",
	"CONSUL_HTTP_TOKEN",
	"NOMAD_TOKEN",
	"OP_SERVICE_ACCOUNT_TOKEN",
	"OP_CONNECT_TOKEN",
	"BW_SESSION",
	"BWS_ACCESS_TOKEN",
	"DOPPLER_TOKEN",
	"INFISICAL_TOKEN",

	// Infrastructure as code
	"TFE_TOKEN",
	"TF_API_TOKEN",
	"PULUMI_ACCESS_TOKEN",

	// Misc high-value
	"DOCKER_PASSWORD",
	"DOCKER_AUTH_CONFIG",
	"SNYK_TOKEN",
	"CODECOV_TOKEN",
	"SONAR_TOKEN",
	"SENTRY_AUTH_TOKEN",
	"DATADOG_API_KEY",
	"DD_API_KEY",
	"DD_APP_KEY",
	"NEW_RELIC_API_KEY",
	"SLACK_BOT_TOKEN",
	"STRIPE_SECRET_KEY",
	"STRIPE_API_KEY",
	"TWILIO_AUTH_TOKEN",
	"SENDGRID_API_KEY",
	"FIREBASE_TOKEN",
	"SUPABASE_SERVICE_ROLE_KEY",
	"SUPABASE_ACCESS_TOKEN",

	// AI providers
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"AZURE_OPENAI_API_KEY",
	"HUGGING_FACE_HUB_TOKEN",
	"HF_TOKEN",
	"GEMINI_API_KEY",
	"GOOGLE_API_KEY",
	"COHERE_API_KEY",
	"MISTRAL_API_KEY",
	"GROQ_API_KEY",
	"OPENROUTER_API_KEY",
	"DEEPSEEK_API_KEY",
	"XAI_API_KEY",
}

// ProtectedEnvVars are core process variables never scrubbed, regardless of
// deny patterns. They are matched case-insensitively as globs (see ScrubEnv),
// so "LC_*" covers the whole locale family. This is a safety net so that a
// profile opting into a broad deny glob (e.g. "*_TOKEN") cannot break process
// startup. The built-in DANGEROUS_ENV_VARS list never touches these names.
var ProtectedEnvVars = []string{
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"SHELL",
	"PWD",
	"OLDPWD",
	"TERM",
	"TMPDIR",
	"TEMP",
	"TMP",
	"LANG",
	"LC_*",
	"TZ",
	"DISPLAY",
	"HOSTNAME",
	"NODE_ENV",
}

// MandatoryDenyOptions configures GetMandatoryDenyPatterns. AllowRead and
// AllowWrite must be already expanded (post-ExpandVariables); the function
// does not call ExpandVariables itself.
type MandatoryDenyOptions struct {
	AllowGitConfig bool
	AllowRead      []string
	AllowWrite     []string
}

// MandatoryDenyResult splits mandatory denies by direction and reports the
// patterns the user opted out of (for audit logging by translators).
type MandatoryDenyResult struct {
	DenyRead        []string
	DenyWrite       []string
	SuppressedRead  []string
	SuppressedWrite []string
}

// GetMandatoryDenyPatterns returns mandatory deny patterns for both directions,
// suppressing any pattern the user has explicitly named in the corresponding
// allow list. Suppression is exact post-expansion byte-equal match — broad
// globs in user allow lists do not suppress.
//
// .git/hooks is never suppressed (arbitrary code execution risk).
// .git/config is emitted only when !AllowGitConfig and may be suppressed.
func GetMandatoryDenyPatterns(opts MandatoryDenyOptions) MandatoryDenyResult {
	allowReadSet := toSet(opts.AllowRead)
	allowWriteSet := toSet(opts.AllowWrite)

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}

	// Naming an absolute form (CWD or HOME) of a dangerous file also suppresses
	// the corresponding "**/<file>" glob on the same direction — otherwise the
	// glob deny would still block the user's explicit opt-out. The unnamed
	// absolute form remains mandatory.
	absToDangerous := make(map[string]string)
	for _, fileName := range DANGEROUS_FILES {
		absToDangerous[filepath.Clean(filepath.Join(cwd, fileName))] = fileName
		if home != "" {
			absToDangerous[filepath.Clean(filepath.Join(home, fileName))] = fileName
		}
	}

	readGlobAlsoSuppressed := make(map[string]bool)
	for entry := range allowReadSet {
		if fileName, ok := absToDangerous[entry]; ok {
			readGlobAlsoSuppressed[filepath.Clean(filepath.Join("**", fileName))] = true
		}
	}
	writeGlobAlsoSuppressed := make(map[string]bool)
	for entry := range allowWriteSet {
		if fileName, ok := absToDangerous[entry]; ok {
			writeGlobAlsoSuppressed[filepath.Clean(filepath.Join("**", fileName))] = true
		}
	}

	suppressible := []string{}

	for _, fileName := range DANGEROUS_FILES {
		suppressible = append(suppressible, filepath.Join(cwd, fileName))
		suppressible = append(suppressible, filepath.Join("**", fileName))
		if home != "" {
			suppressible = append(suppressible, filepath.Join(home, fileName))
		}
	}

	if !opts.AllowGitConfig {
		suppressible = append(suppressible, filepath.Join(cwd, ".git/config"))
		if home != "" {
			suppressible = append(suppressible, filepath.Join(home, ".git/config"))
		}
	}

	result := MandatoryDenyResult{}

	for _, pattern := range suppressible {
		cleaned := filepath.Clean(pattern)

		if allowReadSet[cleaned] || readGlobAlsoSuppressed[cleaned] {
			result.SuppressedRead = append(result.SuppressedRead, cleaned)
		} else {
			result.DenyRead = append(result.DenyRead, cleaned)
		}

		if allowWriteSet[cleaned] || writeGlobAlsoSuppressed[cleaned] {
			result.SuppressedWrite = append(result.SuppressedWrite, cleaned)
		} else {
			result.DenyWrite = append(result.DenyWrite, cleaned)
		}
	}

	// Git hooks can execute arbitrary code; never suppressible.
	gitHooks := []string{
		filepath.Join(cwd, ".git/hooks"),
		filepath.Join(cwd, ".git/hooks/**"),
	}
	if home != "" {
		gitHooks = append(gitHooks,
			filepath.Join(home, ".git/hooks"),
			filepath.Join(home, ".git/hooks/**"),
		)
	}
	for _, p := range gitHooks {
		cleaned := filepath.Clean(p)
		result.DenyRead = append(result.DenyRead, cleaned)
		result.DenyWrite = append(result.DenyWrite, cleaned)
	}

	return result
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[filepath.Clean(v)] = true
	}
	return m
}
