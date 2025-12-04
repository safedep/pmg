package alias

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
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
	HomeDir    string
	RcFileName string
}

var _ RcFileManager = &defaultRcFileManager{}

// NewDefaultRcFileManager creates a new DefaultRcFileManager.
func NewDefaultRcFileManager(rcFileName string) (*defaultRcFileManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	return &defaultRcFileManager{
		HomeDir:    homeDir,
		RcFileName: rcFileName,
	}, nil
}

// Create creates the RC file with the given aliases.
func (m *defaultRcFileManager) Create(aliases []string) (string, error) {
	rcPath := m.GetRcPath()
	f, err := os.Create(rcPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, alias := range aliases {
		if _, err := f.WriteString(alias); err != nil {
			return "", fmt.Errorf("failed to write alias: %w", err)
		}
	}
	return rcPath, nil
}

// Remove deletes the RC file.
func (m *defaultRcFileManager) Remove() error {
	rcPath := m.GetRcPath()
	if err := os.Remove(rcPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not delete %s: %w", rcPath, err)
	}
	return nil
}

// GetRcPath returns the full path to the RC file.
func (m *defaultRcFileManager) GetRcPath() string {
	return filepath.Join(m.HomeDir, m.RcFileName)
}

// DefaultConfig returns the default configuration for alias management.
func DefaultConfig() AliasConfig {
	var shells []Shell

	fishShell, _ := NewFishShell()
	zshShell, _ := NewZshShell()
	bashShell, _ := NewBashShell()

	shells = append(shells, fishShell, zshShell, bashShell)

	return AliasConfig{
		RcFileName:      ".pmg.rc",
		PackageManagers: []string{"npm", "pip", "pip3", "pnpm", "bun", "uv", "yarn", "poetry"},
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
	rcPath, err := a.rcFileManager.Create(aliases)
	if err != nil {
		return fmt.Errorf("failed to create alias file: %w", err)
	}

	err = a.sourceRcFile()
	if err != nil {
		return fmt.Errorf("failed to update shell configs: %w", err)
	}

	fmt.Println("✅ PMG aliases installed successfully!")
	fmt.Printf("📁 Created: %s\n", rcPath)
	fmt.Println("💡 Restart your terminal or source your shell to use the new aliases")

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

	fmt.Println("✅ PMG config removed. Existing aliases need a shell restart.")
	return nil
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
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	for _, shell := range a.config.Shells {
		configPath := filepath.Join(homeDir, shell.Path())
		if err := a.addSourceLine(configPath, shell.Source(a.rcFileManager.GetRcPath())); err != nil {
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
		}
	}

	return nil
}

// removeSourceLinesFromShells removes source lines from all shell configuration files.
func (a *AliasManager) removeSourceLinesFromShells() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	for _, shell := range a.config.Shells {
		configPath := filepath.Join(homeDir, shell.Path())

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		// Get original file permissions
		info, err := os.Stat(configPath)
		if err != nil {
			continue
		}

		// Create temp file
		tempFile, err := os.CreateTemp(filepath.Dir(configPath), ".tmp-"+filepath.Base(configPath))
		if err != nil {
			continue
		}
		tempPath := tempFile.Name()

		// Write filtered content
		scanner := bufio.NewScanner(bytes.NewReader(data))
		writer := bufio.NewWriter(tempFile)

		for scanner.Scan() {
			line := scanner.Text()

			// Skip source lines and comment
			if strings.Contains(line, a.config.RcFileName) ||
				strings.TrimSpace(line) == strings.TrimSpace(commentForRemovingShellSource) {
				continue
			}

			writer.WriteString(line + "\n")
		}

		writer.Flush()
		tempFile.Close()

		// Replace original file
		os.Chmod(tempPath, info.Mode())
		if err := os.Rename(tempPath, configPath); err != nil {
			os.Remove(tempPath) // cleanup on failure
			log.Warnf("Warning: failed to update %s: %s", configPath, err)
		}
	}

	return nil
}

// addSourceLine adds a source line to the specified shell configuration file.
func (a *AliasManager) addSourceLine(configPath, sourceLine string) error {
	// Read existing content - only proceed if file exists
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err // file doesn't exist or can't read, skip
	}

	if strings.Contains(string(data), a.config.RcFileName) {
		return nil // already sourced, skip
	}

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = fmt.Fprintf(f, "\n%s", sourceLine)
	return err
}
