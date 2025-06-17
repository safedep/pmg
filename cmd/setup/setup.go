package setup

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const pmgComment = "# Added by pmg setup"

func NewSetupCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Adds aliases to existing shell config files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetup()
		},
	}
}

func runSetup() error {
	if _, err := exec.LookPath("pmg"); err != nil {
		return fmt.Errorf("pmg not found in PATH")
	}

	configFile, shell, err := getShellConfig()
	if err != nil {
		return err
	}

	existingAliases, err := getExistingAliases(configFile)
	if err != nil {
		return fmt.Errorf("failed to read existing aliases: %w", err)
	}

	aliases := generateAliases(shell)
	newAliases := filterNewAliases(aliases, existingAliases)

	if len(newAliases) == 0 {
		fmt.Printf("✅ All aliases already exist in %s\n", configFile)
		return nil
	}

	if err := addAliasesToFile(configFile, newAliases); err != nil {
		return fmt.Errorf("failed to add aliases: %w", err)
	}

	fmt.Printf("✅ Added %d aliases to %s\n", len(newAliases), configFile)
	fmt.Printf("Restart terminal or run: source %s\n", configFile)
	return nil
}

func getShellConfig() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("failed to get home directory")
	}

	shell := filepath.Base(os.Getenv("SHELL"))
	if shell == "" {
		shell = "bash"
	}

	var configFile string
	switch shell {
	case "bash":
		bashProfile := filepath.Join(home, ".bash_profile")
		bashrc := filepath.Join(home, ".bashrc")

		if _, err := os.Stat(bashProfile); err == nil {
			configFile = bashProfile
		} else if _, err := os.Stat(bashrc); err == nil {
			configFile = bashrc
		} else {
			return "", "", fmt.Errorf("no bash config found (.bash_profile or .bashrc)")
		}
	case "zsh":
		configFile = filepath.Join(home, ".zshrc")
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			return "", "", fmt.Errorf("no zsh config found (.zshrc)")
		}
	case "fish":
		configFile = filepath.Join(home, ".config", "fish", "config.fish")
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			return "", "", fmt.Errorf("no fish config found (.config/fish/config.fish)")
		}
	default:
		return "", "", fmt.Errorf("unsupported shell: %s", shell)
	}

	return configFile, shell, nil
}

func getExistingAliases(configFile string) (map[string]bool, error) {
	aliases := make(map[string]bool)

	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, pmgComment) && strings.HasPrefix(line, "alias ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				aliasName := strings.Split(parts[1], "=")[0]
				aliases[aliasName] = true
			}
		}
	}

	return aliases, scanner.Err()
}

func generateAliases(shell string) []string {
	packageManagers := []string{"npm", "pip", "pnpm"}
	aliases := make([]string, len(packageManagers))

	for i, pm := range packageManagers {
		if shell == "fish" {
			aliases[i] = fmt.Sprintf("alias %s 'pmg %s' %s", pm, pm, pmgComment)
		} else {
			aliases[i] = fmt.Sprintf(`alias %s="pmg %s" %s`, pm, pm, pmgComment)
		}
	}

	return aliases
}

func filterNewAliases(aliases []string, existing map[string]bool) []string {
	var newAliases []string

	for _, alias := range aliases {
		if strings.HasPrefix(alias, "alias ") {
			parts := strings.Fields(alias)
			if len(parts) >= 2 {
				aliasName := strings.Split(parts[1], "=")[0]
				if strings.Contains(alias, "'") { // fish syntax
					aliasName = parts[1]
				}
				if !existing[aliasName] {
					newAliases = append(newAliases, alias)
				}
			}
		}
	}

	return newAliases
}

func addAliasesToFile(configFile string, aliases []string) error {
	file, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Add newline if file doesn't end with one
	if stat, err := file.Stat(); err == nil && stat.Size() > 0 {
		file.Seek(-1, 2)
		lastByte := make([]byte, 1)
		file.Read(lastByte)
		if lastByte[0] != '\n' {
			file.WriteString("\n")
		}
		file.Seek(0, 2)
	}

	for _, alias := range aliases {
		if _, err := file.WriteString(alias + "\n"); err != nil {
			return err
		}
	}

	return nil
}
