package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/safedep/pmg/proxy/certmanager"
)

const defaultCAStateDir = "/var/lib/pmg-ebpf-poc"

type caCommandOptions struct {
	proxyUser      string
	npmUser        string
	npmBin         string
	proxyConfigDir string
	bundlePath     string
	statePath      string
	proxyStatePath string
}

type caState struct {
	ProxyUser      string `json:"proxy_user"`
	NPMUser        string `json:"npm_user"`
	NPMBin         string `json:"npm_bin"`
	ProxyConfigDir string `json:"proxy_config_dir"`
	BundlePath     string `json:"bundle_path"`
	PreviousNPMCA  string `json:"previous_npm_ca,omitempty"`
	PreviousNPMSet bool   `json:"previous_npm_ca_set"`
	CAFingerprint  string `json:"ca_fingerprint"`
	CACreated      bool   `json:"ca_created"`
	ProxyStatePath string `json:"proxy_state_path"`
}

type caStatus struct {
	CAValid       bool
	KeyModeValid  bool
	BundleValid   bool
	NPMConfigured bool
	Fingerprint   string
}

func runCACommand(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		return printCAUsage(out)
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		return printCAUsage(out)
	}

	switch args[0] {
	case "install":
		opts, err := parseCAOptions("install", args[1:])
		if err != nil {
			return err
		}
		if err := requireRoot(); err != nil {
			return err
		}
		state, err := installCA(opts)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out,
			"Persistent CA: %s\nPrivate key owner: %s\nPublic npm bundle: %s\nnpm user: %s\nFingerprint: %s\n",
			certmanager.CACertPath(state.ProxyConfigDir), state.ProxyUser, state.BundlePath,
			state.NPMUser, state.CAFingerprint); err != nil {
			return err
		}
		return nil

	case "status":
		opts, err := parseCAOptions("status", args[1:])
		if err != nil {
			return err
		}
		if err := requireRoot(); err != nil {
			return err
		}
		status, err := inspectCA(opts)
		if err != nil {
			return err
		}
		if err := printCAStatus(out, status); err != nil {
			return err
		}
		if !status.CAValid || !status.KeyModeValid || !status.BundleValid || !status.NPMConfigured {
			return errors.New("CA setup is unhealthy")
		}
		return nil

	case "remove":
		opts, err := parseCAOptions("remove", args[1:])
		if err != nil {
			return err
		}
		if err := requireRoot(); err != nil {
			return err
		}
		if err := removeCA(opts); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, "CA setup removed"); err != nil {
			return err
		}
		return nil

	default:
		return fmt.Errorf("unknown CA command %q, expected install, status, or remove", args[0])
	}
}

func printCAUsage(out io.Writer) error {
	_, err := fmt.Fprintln(out, `Usage:
  pmgwatch ca install --npm-user <user> [--proxy-user pmg-proxy]
  pmgwatch ca status
  pmgwatch ca remove

install generates or reuses the proxy CA and configures the selected user's npm cafile.
status verifies the CA files, ownership, public bundle, and npm configuration.
remove restores the previous npm cafile and deletes POC-owned CA files.`)
	return err
}

func parseCAOptions(name string, args []string) (caCommandOptions, error) {
	var opts caCommandOptions
	flags := flag.NewFlagSet("ca "+name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.proxyUser, "proxy-user", "pmg-proxy", "user running the PMG proxy")
	flags.StringVar(&opts.npmUser, "npm-user", defaultNPMUser(), "user whose npm configuration PMG manages")
	flags.StringVar(&opts.npmBin, "npm-bin", "npm", "npm executable used to manage trust")
	flags.StringVar(&opts.proxyConfigDir, "proxy-config-dir", "", "PMG proxy config directory")
	flags.StringVar(&opts.bundlePath, "bundle", filepath.Join(defaultCAStateDir, "npm-ca-bundle.pem"), "public CA bundle for npm")
	flags.StringVar(&opts.statePath, "state", filepath.Join(defaultCAStateDir, "ca-state.json"), "CA setup state")
	flags.StringVar(&opts.proxyStatePath, "proxy-state", "", "PMG proxy state file used to guard removal")
	if err := flags.Parse(args); err != nil {
		return caCommandOptions{}, err
	}
	if flags.NArg() != 0 {
		return caCommandOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if name == "install" && opts.npmUser == "" {
		return caCommandOptions{}, errors.New("--npm-user is required when SUDO_USER is not set")
	}
	return opts, nil
}

func installCA(opts caCommandOptions) (*caState, error) {
	proxyAccount, err := lookupSystemAccount(opts.proxyUser)
	if err != nil {
		return nil, fmt.Errorf("resolve proxy user: %w", err)
	}
	npmAccount, err := lookupSystemAccount(opts.npmUser)
	if err != nil {
		return nil, fmt.Errorf("resolve npm user: %w", err)
	}
	resolveCAPaths(&opts, proxyAccount)
	if err := ensureProxyStopped(opts.proxyStatePath); err != nil {
		return nil, err
	}

	npm := npmTrust{binary: opts.npmBin}
	state, err := loadCAState(opts.statePath)
	switch {
	case err == nil:
		if err := state.matches(opts); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		previous, present, readErr := npm.Current(npmAccount)
		if readErr != nil {
			return nil, readErr
		}
		state = &caState{
			ProxyUser:      opts.proxyUser,
			NPMUser:        opts.npmUser,
			NPMBin:         opts.npmBin,
			ProxyConfigDir: opts.proxyConfigDir,
			BundlePath:     opts.bundlePath,
			PreviousNPMCA:  previous,
			PreviousNPMSet: present,
			ProxyStatePath: opts.proxyStatePath,
		}
	default:
		return nil, err
	}

	ca, created, err := ensurePersistentCA(opts.proxyConfigDir, proxyAccount)
	if err != nil {
		return nil, err
	}
	state.CACreated = state.CACreated || created
	if err := writeClientBundle(opts.bundlePath, ca.Certificate); err != nil {
		return nil, err
	}
	if err := npm.Set(npmAccount, opts.bundlePath); err != nil {
		return nil, errors.Join(err, restoreNPM(npm, npmAccount, state))
	}
	effective, present, err := npm.Current(npmAccount)
	if err != nil {
		return nil, errors.Join(err, restoreNPM(npm, npmAccount, state))
	}
	if !present || effective != opts.bundlePath {
		setupErr := fmt.Errorf("npm cafile is %q after setup, expected %q", effective, opts.bundlePath)
		return nil, errors.Join(setupErr, restoreNPM(npm, npmAccount, state))
	}

	state.CAFingerprint = certificateFingerprint(ca)
	if err := saveCAState(opts.statePath, state); err != nil {
		return nil, errors.Join(err, restoreNPM(npm, npmAccount, state))
	}

	return state, nil
}

func inspectCA(opts caCommandOptions) (caStatus, error) {
	state, err := loadCAState(opts.statePath)
	if err != nil {
		return caStatus{}, err
	}
	opts = state.options(opts.statePath)
	proxyAccount, err := lookupSystemAccount(opts.proxyUser)
	if err != nil {
		return caStatus{}, err
	}
	npmAccount, err := lookupSystemAccount(opts.npmUser)
	if err != nil {
		return caStatus{}, err
	}

	status := caStatus{}
	ca, err := certmanager.LoadCA(opts.proxyConfigDir)
	if err == nil && !ca.IsExpired(0) {
		status.Fingerprint = certificateFingerprint(ca)
		status.CAValid = status.Fingerprint == state.CAFingerprint
	}

	keyInfo, keyErr := os.Stat(certmanager.CAKeyPath(opts.proxyConfigDir))
	if keyErr == nil {
		keyStat, ok := keyInfo.Sys().(*syscall.Stat_t)
		status.KeyModeValid = ok && keyInfo.Mode().Perm() == 0o600 &&
			keyStat.Uid == proxyAccount.UID && keyStat.Gid == proxyAccount.GID
	}
	if status.CAValid {
		bundle, bundleErr := os.ReadFile(opts.bundlePath)
		status.BundleValid = bundleErr == nil && bytes.Contains(bundle, ca.Certificate)
	}

	effective, present, npmErr := (npmTrust{binary: opts.npmBin}).Current(npmAccount)
	if npmErr != nil {
		return caStatus{}, npmErr
	}
	status.NPMConfigured = present && effective == opts.bundlePath

	return status, nil
}

func removeCA(opts caCommandOptions) error {
	state, err := loadCAState(opts.statePath)
	if err != nil {
		return err
	}
	opts = state.options(opts.statePath)
	if err := ensureProxyStopped(opts.proxyStatePath); err != nil {
		return err
	}

	npmAccount, err := lookupSystemAccount(opts.npmUser)
	if err != nil {
		return err
	}
	npm := npmTrust{binary: opts.npmBin}
	effective, present, err := npm.Current(npmAccount)
	if err != nil {
		return err
	}
	if !present || effective != opts.bundlePath {
		return fmt.Errorf("npm cafile changed to %q after setup; refusing to overwrite it", effective)
	}
	if state.PreviousNPMSet {
		if err := npm.Set(npmAccount, state.PreviousNPMCA); err != nil {
			return err
		}
	} else if err := npm.Remove(npmAccount); err != nil {
		return err
	}

	paths := []string{opts.bundlePath}
	if state.CACreated {
		paths = append(paths,
			certmanager.CACertPath(opts.proxyConfigDir),
			certmanager.CAKeyPath(opts.proxyConfigDir),
		)
	}
	paths = append(paths, opts.statePath)
	for _, path := range paths {
		if err := removeFile(path); err != nil {
			return err
		}
	}
	return nil
}

func ensurePersistentCA(dir string, account systemAccount) (*certmanager.Certificate, bool, error) {
	created := false
	ca, err := certmanager.LoadCA(dir)
	if err != nil {
		status, inspectErr := certmanager.InspectCA(dir)
		if inspectErr != nil {
			return nil, false, inspectErr
		}
		if status.CertPresent || status.KeyPresent {
			return nil, false, fmt.Errorf("persisted CA is incomplete or unreadable: %w", err)
		}
		ca, err = certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
		if err != nil {
			return nil, false, fmt.Errorf("generate CA: %w", err)
		}
		if err := certmanager.SaveCA(dir, ca); err != nil {
			return nil, false, fmt.Errorf("save CA: %w", err)
		}
		created = true
	}
	if ca.IsExpired(0) {
		return nil, false, errors.New("persisted CA is expired")
	}

	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{dir, 0o700},
		{certmanager.CACertPath(dir), 0o644},
		{certmanager.CAKeyPath(dir), 0o600},
	} {
		if err := os.Chmod(item.path, item.mode); err != nil {
			return nil, false, fmt.Errorf("chmod %s: %w", item.path, err)
		}
		if err := os.Chown(item.path, int(account.UID), int(account.GID)); err != nil {
			return nil, false, fmt.Errorf("chown %s: %w", item.path, err)
		}
	}
	return ca, created, nil
}

func writeClientBundle(path string, caPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	if err := os.WriteFile(path, certmanager.MergeWithSystemCA(caPEM), 0o644); err != nil {
		return fmt.Errorf("write npm CA bundle: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod npm CA bundle: %w", err)
	}
	return nil
}

func saveCAState(path string, state *caState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal CA state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create CA state directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write CA state: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod CA state: %w", err)
	}
	return nil
}

func loadCAState(path string) (*caState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA state %q: %w", path, err)
	}
	var state caState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse CA state %q: %w", path, err)
	}
	return &state, nil
}

func (s *caState) matches(opts caCommandOptions) error {
	if s.ProxyUser != opts.proxyUser || s.NPMUser != opts.npmUser ||
		s.NPMBin != opts.npmBin || s.ProxyConfigDir != opts.proxyConfigDir ||
		s.BundlePath != opts.bundlePath {
		return errors.New("existing CA state was created with different options; remove it before changing setup")
	}
	return nil
}

func (s *caState) options(statePath string) caCommandOptions {
	return caCommandOptions{
		proxyUser:      s.ProxyUser,
		npmUser:        s.NPMUser,
		npmBin:         s.NPMBin,
		proxyConfigDir: s.ProxyConfigDir,
		bundlePath:     s.BundlePath,
		statePath:      statePath,
		proxyStatePath: s.ProxyStatePath,
	}
}

func resolveCAPaths(opts *caCommandOptions, proxy systemAccount) {
	if opts.proxyConfigDir == "" {
		opts.proxyConfigDir = filepath.Join(proxy.HomeDir, ".config", "safedep", "pmg")
	}
	if opts.proxyStatePath == "" {
		opts.proxyStatePath = filepath.Join(proxy.HomeDir, "state", "proxy.json")
	}
}

func ensureProxyStopped(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read proxy state: %w", err)
	}
	var state struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse proxy state: %w", err)
	}
	if state.PID <= 0 {
		return nil
	}
	process, err := os.FindProcess(state.PID)
	if err == nil && process.Signal(syscall.Signal(0)) == nil {
		return fmt.Errorf("proxy pid %d is still running; stop it before changing the CA setup", state.PID)
	}
	return nil
}

func printCAStatus(out io.Writer, status caStatus) error {
	rows := []struct {
		name string
		ok   bool
	}{
		{"Persistent CA", status.CAValid},
		{"Private key access", status.KeyModeValid},
		{"Public npm bundle", status.BundleValid},
		{"npm cafile", status.NPMConfigured},
	}
	for _, row := range rows {
		result := "FAIL"
		if row.ok {
			result = "PASS"
		}
		if _, err := fmt.Fprintf(out, "%-20s %s\n", row.name, result); err != nil {
			return err
		}
	}
	if status.Fingerprint != "" {
		if _, err := fmt.Fprintf(out, "%-20s %s\n", "Fingerprint", status.Fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func certificateFingerprint(ca *certmanager.Certificate) string {
	sum := sha256.Sum256(ca.X509Cert.Raw)
	return hex.EncodeToString(sum[:])
}

func lookupSystemAccount(name string) (systemAccount, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return systemAccount{}, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return systemAccount{}, fmt.Errorf("parse uid %q: %w", account.Uid, err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return systemAccount{}, fmt.Errorf("parse gid %q: %w", account.Gid, err)
	}
	return systemAccount{
		Name:    account.Username,
		UID:     uint32(uid),
		GID:     uint32(gid),
		HomeDir: account.HomeDir,
	}, nil
}

func defaultNPMUser() string {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		return name
	}
	return ""
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("run this command as root")
	}
	return nil
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func restoreNPM(npm npmTrust, account systemAccount, state *caState) error {
	if state.PreviousNPMSet {
		return npm.Set(account, state.PreviousNPMCA)
	}
	return npm.Remove(account)
}
