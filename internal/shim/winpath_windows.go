//go:build windows

package shim

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/fsutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// userEnvironmentKey is the HKCU subkey that holds the per-user PATH. Tests
// point it at a scratch key. There is intentionally no env var or flag.
var userEnvironmentKey = `Environment`

// machineEnvironmentRoot and machineEnvironmentKey locate the machine PATH.
// Tests point them at a scratch key under HKCU.
var (
	machineEnvironmentRoot = registry.LOCAL_MACHINE
	machineEnvironmentKey  = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
)

const pathValueName = "Path"

// registryPathEntries returns the PATH a new process receives: the machine
// entries, then the user entries, with %VAR% references expanded. It reads
// the registry rather than the process environment, because the shell that
// ran `pmg setup install` still carries the PATH from before it.
func registryPathEntries() ([]string, error) {
	machine, err := readExpandedPath(machineEnvironmentRoot, machineEnvironmentKey)
	if err != nil {
		return nil, err
	}
	user, err := readExpandedPath(registry.CURRENT_USER, userEnvironmentKey)
	if err != nil {
		return nil, err
	}
	return append(machine, user...), nil
}

func readExpandedPath(root registry.Key, keyPath string) ([]string, error) {
	key, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", keyPath, err)
	}
	defer key.Close()

	value, _, err := key.GetStringValue(pathValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read PATH under %s: %w", keyPath, err)
	}

	expanded, err := registry.ExpandString(value)
	if err != nil {
		return nil, fmt.Errorf("failed to expand PATH under %s: %w", keyPath, err)
	}
	return splitPath(expanded), nil
}

func splitPath(value string) []string {
	var entries []string
	for _, entry := range strings.Split(value, ";") {
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procSendMessageTimeoutW = user32.NewProc("SendMessageTimeoutW")
)

// registerUserPath prepends dir to the user PATH in the registry. It writes
// the registry directly rather than through setx, which truncates a value at
// 1024 characters and would corrupt a developer's PATH.
func registerUserPath(dir string) error {
	entries, expand, err := readUserPath()
	if err != nil {
		return err
	}
	if containsPath(entries, dir) {
		return nil
	}
	return writeUserPath(append([]string{dir}, entries...), expand)
}

// unregisterUserPath removes every entry that names dir from the user PATH.
func unregisterUserPath(dir string) error {
	entries, expand, err := readUserPath()
	if err != nil {
		return err
	}
	if !containsPath(entries, dir) {
		return nil
	}

	kept := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !fsutil.SamePath(entry, dir) {
			kept = append(kept, entry)
		}
	}
	if len(kept) == 0 {
		// The shim entry was the only one. Before the install there was no
		// value, so leave none behind.
		return deleteUserPath()
	}
	return writeUserPath(kept, expand)
}

func deleteUserPath() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, userEnvironmentKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open HKCU\\%s for writing: %w", userEnvironmentKey, err)
	}
	defer key.Close()

	if err := key.DeleteValue(pathValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("failed to delete the user PATH: %w", err)
	}
	broadcastEnvironmentChange()
	return nil
}

func userPathContains(dir string) (bool, error) {
	entries, _, err := readUserPath()
	if err != nil {
		return false, err
	}
	return containsPath(entries, dir), nil
}

func containsPath(entries []string, dir string) bool {
	for _, entry := range entries {
		if fsutil.SamePath(entry, dir) {
			return true
		}
	}
	return false
}

// readUserPath returns the raw PATH entries and whether the value is
// REG_EXPAND_SZ. The raw form keeps %USERPROFILE% style references that
// other tools wrote, so a write does not flatten them.
func readUserPath() (entries []string, expand bool, err error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, userEnvironmentKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open HKCU\\%s: %w", userEnvironmentKey, err)
	}
	defer key.Close()

	value, valueType, err := key.GetStringValue(pathValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to read the user PATH: %w", err)
	}

	return splitPath(value), valueType == registry.EXPAND_SZ, nil
}

func writeUserPath(entries []string, expand bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, userEnvironmentKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open HKCU\\%s for writing: %w", userEnvironmentKey, err)
	}
	defer key.Close()

	value := strings.Join(entries, ";")
	if expand {
		err = key.SetExpandStringValue(pathValueName, value)
	} else {
		err = key.SetStringValue(pathValueName, value)
	}
	if err != nil {
		return fmt.Errorf("failed to write the user PATH: %w", err)
	}

	broadcastEnvironmentChange()
	return nil
}

// broadcastEnvironmentChange tells every top-level window that the
// environment changed, so a new shell started from Explorer sees the PATH
// without a sign-out. A failure only delays that until the next sign-in.
func broadcastEnvironmentChange() {
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001a
		smtoAbortIfHung = 0x0002
		timeoutMillis   = 5000
	)

	section, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		log.Warnf("failed to broadcast the PATH change: %v", err)
		return
	}

	// Find keeps Call from panicking on a build with no user32.dll, such as
	// Nano Server.
	if err := procSendMessageTimeoutW.Find(); err != nil {
		log.Warnf("failed to broadcast the PATH change: %v", err)
		return
	}

	r1, _, callErr := procSendMessageTimeoutW.Call(hwndBroadcast, wmSettingChange, 0,
		uintptr(unsafe.Pointer(section)), smtoAbortIfHung, timeoutMillis, 0)
	// LazyProc.Call is not the syscall form the compiler recognises, so the
	// pointer needs an explicit hold until the call returns.
	runtime.KeepAlive(section)
	if r1 == 0 {
		log.Warnf("failed to broadcast the PATH change: %v", callErr)
	}
}
