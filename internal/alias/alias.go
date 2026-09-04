package alias

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

// LegacyRcFileName is the pre-XDG alias file in $HOME. RcFileName is a suffix
// of it, so the shell rc scan that looks for RcFileName matches both layouts.
const (
	RcFileName       = "pmg.rc"
	LegacyRcFileName = ".pmg.rc"
)

// AliasManager manages shell aliases for package managers.
type AliasManager struct {
	config        AliasConfig
	rcFileManager RcFileManager
}

// AliasConfig holds configuration for alias management.
type AliasConfig struct {
	RcFileName      string
	PackageManagers []string
	Shells          []Shell
}

// RcFileManager handles creation and removal of RC files.
type RcFileManager interface {
	Create(aliases []string) (string, error)
	Remove() error
	GetRcPath() string
}

// DefaultRcFileManager implements RcFileManager for managing the RC file.
type defaultRcFileManager struct {
	RcPath       string
	LegacyRcPath string
}

var _ RcFileManager = &defaultRcFileManager{}

// NewDefaultRcFileManager creates a new DefaultRcFileManager writing rcFileName
// under configDir. An existing ~/.pmg.rc from a pre-XDG install keeps being
// used until `pmg setup remove` clears it, so upgrades do not silently move the
// file a user's shell rc already sources.
func NewDefaultRcFileManager(configDir, rcFileName string) (*defaultRcFileManager, error) {
	homeDir, err := config.UserHomeDir()
	if err != nil {
		return nil, err
	}

	legacyRcPath := filepath.Join(homeDir, LegacyRcFileName)
	rcPath := filepath.Join(configDir, rcFileName)
	if _, err := os.Stat(legacyRcPath); err == nil {
		rcPath = legacyRcPath
	}

	return &defaultRcFileManager{
		RcPath:       rcPath,
		LegacyRcPath: legacyRcPath,
	}, nil
}

// Create creates the RC file with the given aliases.
func (m *defaultRcFileManager) Create(aliases []string) (string, error) {
	rcPath := m.GetRcPath()
	if err := os.MkdirAll(filepath.Dir(rcPath), 0o755); err != nil {
		return "", fmt.Errorf("failed to create alias file directory: %w", err)
	}

	f, err := os.Create(rcPath)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warnf("failed to close rc file %s: %v", rcPath, err)
		}
	}()

	for _, alias := range aliases {
		if _, err := f.WriteString(alias); err != nil {
			return "", fmt.Errorf("failed to write alias: %w", err)
		}
	}
	return rcPath, nil
}

// Remove deletes the RC file, including a legacy copy left by an older layout.
func (m *defaultRcFileManager) Remove() error {
	var errs []error
	for _, rcPath := range []string{m.RcPath, m.LegacyRcPath} {
		if err := os.Remove(rcPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("could not delete %s: %w", rcPath, err))
		}
	}
	return errors.Join(errs...)
}

// GetRcPath returns the full path to the RC file.
func (m *defaultRcFileManager) GetRcPath() string {
	return m.RcPath
}

// DefaultConfig returns the default configuration for alias management.
func DefaultConfig() AliasConfig {
	var shells []Shell

	fishShell, _ := NewFishShell()
	zshShell, _ := NewZshShell()
	bashShell, _ := NewBashShell()

	shells = append(shells, fishShell, zshShell, bashShell)

	return AliasConfig{
		RcFileName:      RcFileName,
		PackageManagers: []string{"npm", "pip", "pip3", "pipx", "pnpm", "bun", "uv", "uvx", "yarn", "poetry", "npx", "pnpx", "aube", "aubr", "aubx"},
		Shells:          shells,
	}
}

// New creates a new AliasManager with the given configuration and RC file manager.
func New(config AliasConfig, rcFileManager RcFileManager) *AliasManager {
	return &AliasManager{
		config:        config,
		rcFileManager: rcFileManager,
	}
}

// Install creates the RC file with aliases and sources it in shell configurations.
func (a *AliasManager) Install() error {
	aliases := a.buildAliases()
	_, err := a.rcFileManager.Create(aliases)
	if err != nil {
		return fmt.Errorf("failed to create alias file: %w", err)
	}

	err = a.sourceRcFile()
	if err != nil {
		return fmt.Errorf("failed to update shell configs: %w", err)
	}

	return nil
}

// Remove deletes the RC file and removes source lines from shell configurations.
func (a *AliasManager) Remove() error {
	if err := a.rcFileManager.Remove(); err != nil {
		log.Warnf("Warning: %v", err)
	}

	if err := a.removeSourceLinesFromShells(); err != nil {
		return fmt.Errorf("failed to clean shell configs: %w", err)
	}

	return nil
}

// GetRcPath returns the path to the alias RC file managed by AliasManager.
func (a *AliasManager) GetRcPath() string {
	return a.rcFileManager.GetRcPath()
}

// IsInstalled checks if the PMG aliases are sourced in any of the shell config files.
func (a *AliasManager) IsInstalled() (bool, error) {
	homeDir, err := config.UserHomeDir()
	if err != nil {
		return false, err
	}

	for _, shell := range a.config.Shells {
		for _, configPath := range shell.CandidateRcFiles(homeDir) {
			data, err := os.ReadFile(configPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}

				log.Warnf("Warning: could not read %s (%s)", configPath, err)
				continue
			}

			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.Contains(trimmed, aliasSourceMarker) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// buildAliases creates the alias strings for all configured package managers.
func (a *AliasManager) buildAliases() []string {
	aliases := make([]string, 0, len(a.config.PackageManagers))
	for _, pm := range a.config.PackageManagers {
		aliases = append(aliases, fmt.Sprintf("alias %s='pmg %s'\n", pm, pm))
	}
	return aliases
}

// sourceRcFile adds source lines to all shell configuration files.
func (a *AliasManager) sourceRcFile() error {
	homeDir, err := config.UserHomeDir()
	if err != nil {
		return err
	}

	primary := PrimaryShellName()
	for _, shell := range a.config.Shells {
		files, err := shell.InstallRcFiles(homeDir, shell.Name() == primary)
		if err != nil {
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		for _, configPath := range files {
			if err := a.addSourceLine(configPath, shell.Source(a.rcFileManager.GetRcPath())); err != nil {
				log.Warnf("Warning: skipping %s (%s)", configPath, err)
			}
		}
	}

	return nil
}

// removeSourceLinesFromShells removes source lines from all shell configuration files.
func (a *AliasManager) removeSourceLinesFromShells() error {
	homeDir, err := config.UserHomeDir()
	if err != nil {
		return err
	}

	for _, shell := range a.config.Shells {
		for _, configPath := range shell.CandidateRcFiles(homeDir) {
			if err := RewriteFileDroppingLines(configPath, dropAliasSourceLine); err != nil {
				log.Warnf("Warning: failed to update %s: %s", configPath, err)
			}
		}
	}

	return nil
}

// dropAliasSourceLine reports whether a shell rc line is one pmg wrote to
// source its alias file.
func dropAliasSourceLine(line string) bool {
	return strings.Contains(line, aliasSourceMarker) ||
		strings.TrimSpace(line) == strings.TrimSpace(commentForRemovingShellSource)
}

// addSourceLine adds a source line to the specified shell configuration file.
func (a *AliasManager) addSourceLine(configPath, sourceLine string) error {
	// Read existing content - only proceed if file exists
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err // file doesn't exist or can't read, skip
	}

	if strings.Contains(string(data), sourceLine) {
		return nil // already sourced, skip
	}

	// A marker line pointing at a different rc path is stale: an earlier
	// install used another layout, or the user deleted the file it names. The
	// `[ -f ]` guard makes such a line a silent no-op, so leaving it in place
	// while skipping the write would break aliases without any visible error.
	if strings.Contains(string(data), aliasSourceMarker) {
		if err := RewriteFileDroppingLines(configPath, dropAliasSourceLine); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Warnf("failed to close config file %s: %v", configPath, err)
		}
	}()

	_, err = fmt.Fprintf(f, "\n%s", sourceLine)
	return err
}
