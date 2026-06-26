package config

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var skipDependencyCooldown bool

// sandboxAllowRaw holds the raw --sandbox-allow flag values before parsing.
var sandboxAllowRaw []string

// flagSpec declares a pmg flag once: how to bind it into cobra (bind) and the
// metadata used to reason about it (managed). configFlagSpecs is the single
// source of truth, so the cobra wiring and policy decisions cannot drift apart.
type flagSpec struct {
	name  string
	usage string

	// true when the globally managed config governs this value
	managed bool

	// bind registers the flag on fs. It owns the type, target field, and default
	// (read at bind time), keeping the flag tied to its config field with
	// compile-time safety rather than a stringly-typed key.
	bind func(fs *pflag.FlagSet, name, usage string)
}

var configFlagSpecs = []flagSpec{
	{
		name: "transitive", usage: "Resolve transitive dependencies", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.Transitive, name, globalConfig.Config.Transitive, usage)
		},
	},
	{
		name: "transitive-depth", usage: "Maximum depth of transitive dependencies to resolve", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.IntVar(&globalConfig.Config.TransitiveDepth, name, globalConfig.Config.TransitiveDepth, usage)
		},
	},
	{
		name: "include-dev-dependencies", usage: "Include dev dependencies in the dependency graph (slows down resolution)", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.IncludeDevDependencies, name, globalConfig.Config.IncludeDevDependencies, usage)
		},
	},
	{
		name: "dry-run", usage: "Dry run skips execution of package manager", managed: false,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.DryRun, name, globalConfig.DryRun, usage)
		},
	},
	{
		name: "paranoid", usage: "Enable high-security defaults (treat suspicious as malicious)", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.Paranoid, name, globalConfig.Config.Paranoid, usage)
		},
	},
	{
		name: "skip-event-log", usage: "Skip event logging", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.SkipEventLogging, name, globalConfig.Config.SkipEventLogging, usage)
		},
	},
	{
		name: "proxy-mode", usage: "Use proxy based interception", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.Proxy.Enabled, name, globalConfig.Config.Proxy.Enabled, usage)
		},
	},
	{
		name: "sandbox", usage: "Enable sandbox mode to isolate package manager processes (EXPERIMENTAL)", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.Sandbox.Enabled, name, globalConfig.Config.Sandbox.Enabled, usage)
		},
	},
	{
		name: "sandbox-enforce", usage: "Apply sandbox to all commands, not just install commands (requires --sandbox)", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&globalConfig.Config.Sandbox.EnforceAlways, name, globalConfig.Config.Sandbox.EnforceAlways, usage)
		},
	},
	{
		name: "sandbox-profile", usage: "Override sandbox policy profile (built-in name or path to custom YAML)", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.StringVar(&globalConfig.SandboxProfileOverride, name, globalConfig.SandboxProfileOverride, usage)
		},
	},
	{
		name: "sandbox-allow", usage: "Add runtime sandbox allow rule (type=value). Types: read, write, exec, net-connect, net-bind", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.StringArrayVar(&sandboxAllowRaw, name, nil, usage)
		},
	},
	{
		name: "skip-dependency-cooldown", usage: "Skip dependency cooldown enforcement", managed: true,
		bind: func(fs *pflag.FlagSet, name, usage string) {
			fs.BoolVar(&skipDependencyCooldown, name, false, usage)
		},
	},
}

// ApplyCobraFlags binds the config flags onto cmd as persistent flags. Defaults
// are read from the current global configuration, allowing runtime overrides.
func ApplyCobraFlags(cmd *cobra.Command) {
	fs := cmd.PersistentFlags()
	for _, f := range configFlagSpecs {
		f.bind(fs, f.name, f.usage)
	}
}

// ChangedConfigFlagArgs returns the explicitly supplied root config flags in a
// form that can be passed to a re-execed PMG process.
func ChangedConfigFlagArgs(cmd *cobra.Command) []string {
	var args []string
	for _, spec := range configFlagSpecs {
		flag := cmd.Flags().Lookup(spec.name)
		if flag == nil || !flag.Changed {
			continue
		}

		name := "--" + spec.name
		if flag.Value.Type() == "bool" {
			args = append(args, name+"="+flag.Value.String())
			continue
		}

		for _, value := range changedFlagValues(flag) {
			args = append(args, name, value)
		}
	}
	return args
}

func changedFlagValues(flag *pflag.Flag) []string {
	if value, ok := flag.Value.(pflag.SliceValue); ok {
		return value.GetSlice()
	}
	return []string{flag.Value.String()}
}

// RejectManagedFlagOverrides fails when the active config is a locked global
// config and the user explicitly set a flag whose value that config governs.
// Operational flags (managed == false) are unaffected, and an unlocked managed
// config allows flag overrides. Call it after flag parsing.
func RejectManagedFlagOverrides(cmd *cobra.Command) error {
	if !Get().IsLocked() {
		return nil
	}

	var offending []string
	for _, f := range configFlagSpecs {
		if f.managed && cmd.Flags().Changed(f.name) {
			offending = append(offending, "--"+f.name)
		}
	}

	if len(offending) == 0 {
		return nil
	}

	return managedError(fmt.Sprintf("these flags cannot override the globally managed configuration (%s): %s",
		globalConfig.configFilePath, strings.Join(offending, ", ")))
}

// FinalizeDependencyCooldownOverride disables dependency cooldown in the global
// config when --skip-dependency-cooldown is set. Must be called after cobra
// flag parsing is complete.
func FinalizeDependencyCooldownOverride() {
	if skipDependencyCooldown {
		globalConfig.Config.DependencyCooldown.Enabled = false
	}
}

// FinalizeSandboxAllowOverrides parses the raw --sandbox-allow flag values
// and stores the validated overrides in the global config. This must be called
// after cobra flag parsing is complete (e.g., in PersistentPreRun).
func FinalizeSandboxAllowOverrides() error {
	if len(sandboxAllowRaw) == 0 {
		return nil
	}

	overrides, err := parseSandboxAllowOverrides(sandboxAllowRaw)
	if err != nil {
		return fmt.Errorf("failed to parse --sandbox-allow flags: %w", err)
	}

	globalConfig.SandboxAllowOverrides = overrides
	return nil
}
