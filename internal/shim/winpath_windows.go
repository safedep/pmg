//go:build windows

package shim

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
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

// registryPathHalves returns the two halves of the PATH a new process
// receives, machine first. The caller keeps them apart because PMG can
// reorder the user half and nothing else.
func registryPathHalves() (machine, user []string, err error) {
	machine, err = readExpandedPath(machineEnvironmentRoot, machineEnvironmentKey)
	if err != nil {
		return nil, nil, err
	}
	user, err = readExpandedPath(registry.CURRENT_USER, userEnvironmentKey)
	if err != nil {
		return nil, nil, err
	}
	return machine, user, nil
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

	// ExpandString reads %VAR% from this process's environment. A machine
	// PATH that names a per-user variable therefore expands to this user's
	// value, which is what a shell for this user would get.
	expanded, err := registry.ExpandString(value)
	if err != nil {
		return nil, fmt.Errorf("failed to expand PATH under %s: %w", keyPath, err)
	}
	// SplitList, not a plain split on the separator, because it also strips
	// the quotes a PATH entry may carry. A quoted entry would otherwise read
	// as a directory that does not exist.
	return filepath.SplitList(expanded), nil
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
	if len(entries) > 0 && fsutil.SamePath(entries[0], dir) {
		return nil
	}

	// The shim directory has to be first, or a manager on an entry ahead of
	// it wins. A per-user installer that prepends its own directory, as the
	// python.org installer does, would otherwise shadow the shims until the
	// user edited PATH by hand. A re-run of `pmg setup install` fixes it.
	kept := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !fsutil.SamePath(entry, dir) {
			kept = append(kept, entry)
		}
	}
	return writeUserPath(append([]string{dir}, kept...), expand)
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
	return slices.ContainsFunc(entries, func(entry string) bool { return fsutil.SamePath(entry, dir) })
}

// registerMachinePath puts dir first on the machine PATH, ahead of every
// directory a machine-wide installer added, and moves it there when a later
// installer pushed it back. The caller vouches that dir is writable by
// administrators only. The value keeps its type.
func registerMachinePath(dir string) error {
	entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	if err != nil {
		return err
	}
	if len(entries) > 0 && sameMachineEntry(entries[0], dir) {
		return nil
	}
	kept := slices.DeleteFunc(slices.Clone(entries), func(e string) bool { return sameMachineEntry(e, dir) })
	return writeRawPath(machineEnvironmentRoot, machineEnvironmentKey, append([]string{dir}, kept...), expand)
}

// appendMachinePath adds dir to the end of the machine PATH when it is not
// on it yet. Nothing moves.
func appendMachinePath(dir string) error {
	entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(entries, func(e string) bool { return sameMachineEntry(e, dir) }) {
		return nil
	}
	return writeRawPath(machineEnvironmentRoot, machineEnvironmentKey, append(slices.Clone(entries), dir), expand)
}

// unregisterMachinePath removes dir from the machine PATH. The value itself
// is never deleted, because the machine PATH is not PMG's to remove.
func unregisterMachinePath(dir string) error {
	entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(entries), func(e string) bool { return sameMachineEntry(e, dir) })
	if len(kept) == len(entries) {
		return nil
	}
	return writeRawPath(machineEnvironmentRoot, machineEnvironmentKey, kept, expand)
}

func machinePathContains(dir string) (bool, error) {
	entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(entries, func(e string) bool { return sameMachineEntry(e, dir) }), nil
}

// sameMachineEntry expands a raw entry first, so an administrator who wrote
// %ProgramFiles%\safedep\pmg\bin by hand is not given a duplicate.
func sameMachineEntry(raw, dir string) bool {
	expanded, err := registry.ExpandString(raw)
	if err != nil {
		expanded = raw
	}
	return fsutil.SamePath(strings.Trim(expanded, `"`), dir)
}

// readUserPath returns the raw PATH entries and whether the value is
// REG_EXPAND_SZ. The raw form keeps %USERPROFILE% style references that
// other tools wrote, so a write does not flatten them.
func readUserPath() (entries []string, expand bool, err error) {
	return readRawPath(registry.CURRENT_USER, userEnvironmentKey)
}

func readRawPath(root registry.Key, keyPath string) (entries []string, expand bool, err error) {
	key, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open %s: %w", keyPath, err)
	}
	defer key.Close()

	value, valueType, err := key.GetStringValue(pathValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to read PATH under %s: %w", keyPath, err)
	}

	return splitRawPath(value), valueType == registry.EXPAND_SZ, nil
}

// splitRawPath keeps each entry exactly as the registry holds it, quotes and
// all, so a read, edit and write-back does not rewrite entries PMG does not
// own.
func splitRawPath(value string) []string {
	var entries []string
	for _, entry := range strings.Split(value, ";") {
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

func writeUserPath(entries []string, expand bool) error {
	return writeRawPath(registry.CURRENT_USER, userEnvironmentKey, entries, expand)
}

func writeRawPath(root registry.Key, keyPath string, entries []string, expand bool) error {
	key, err := registry.OpenKey(root, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", keyPath, err)
	}
	defer key.Close()

	value := strings.Join(entries, ";")
	if expand {
		err = key.SetExpandStringValue(pathValueName, value)
	} else {
		err = key.SetStringValue(pathValueName, value)
	}
	if err != nil {
		return fmt.Errorf("failed to write PATH under %s: %w", keyPath, err)
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
