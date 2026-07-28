package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type systemAccount struct {
	Name    string
	UID     uint32
	GID     uint32
	HomeDir string
}

type npmTrust struct {
	binary string
}

func (n npmTrust) Current(account systemAccount) (string, bool, error) {
	output, err := n.run(account, "config", "get", "cafile", "--location=user")
	if err != nil {
		return "", false, err
	}
	value := strings.TrimSpace(output)
	switch value {
	case "", "null", "undefined":
		return "", false, nil
	default:
		return value, true, nil
	}
}

func (n npmTrust) Set(account systemAccount, path string) error {
	_, err := n.run(account, "config", "set", "cafile="+path, "--location=user")
	return err
}

func (n npmTrust) Remove(account systemAccount) error {
	_, err := n.run(account, "config", "delete", "cafile", "--location=user")
	return err
}

func (n npmTrust) run(account systemAccount, args ...string) (string, error) {
	binary, err := exec.LookPath(n.binary)
	if err != nil {
		return "", fmt.Errorf("find npm executable %q: %w", n.binary, err)
	}

	cmd := exec.Command(binary, args...)
	cmd.Env = accountEnvironment(account)
	cmd.Dir = account.HomeDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: account.UID,
			Gid: account.GID,
		},
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run npm as %s: %w: %s", account.Name, err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func accountEnvironment(account systemAccount) []string {
	blocked := map[string]struct{}{
		"HOME":                    {},
		"USER":                    {},
		"LOGNAME":                 {},
		"XDG_CONFIG_HOME":         {},
		"NPM_CONFIG_CAFILE":       {},
		"npm_config_cafile":       {},
		"NPM_CONFIG_USERCONFIG":   {},
		"npm_config_userconfig":   {},
		"NPM_CONFIG_GLOBALCONFIG": {},
		"npm_config_globalconfig": {},
	}

	env := make([]string, 0, len(os.Environ())+4)
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if _, skip := blocked[key]; !skip {
			env = append(env, item)
		}
	}
	return append(env,
		"HOME="+account.HomeDir,
		"USER="+account.Name,
		"LOGNAME="+account.Name,
		"XDG_CONFIG_HOME="+filepath.Join(account.HomeDir, ".config"),
	)
}
