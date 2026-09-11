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

const pathValueName = "Path"

// pathScope is one registry PATH value, the user's or the machine's. Both
// are read, edited and written the same way. Tests point root and key at a
// scratch key. There is intentionally no env var or flag for that.
type pathScope struct {
	root registry.Key
	key  string
	// The user PATH had no value before PMG's install, so removing the last
	// entry leaves none behind. The machine PATH is not PMG's to delete.
	deleteWhenEmpty bool
}

var (
	userPath    = pathScope{root: registry.CURRENT_USER, key: `Environment`, deleteWhenEmpty: true}
	machinePath = pathScope{root: registry.LOCAL_MACHINE, key: `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`}
)

// registryPathHalves returns the two halves of the PATH a new process
// receives, machine first. The caller keeps them apart because the remedy
// for a shadowed manager depends on which half named it.
func registryPathHalves() (machine, user []string, err error) {
	machine, err = machinePath.expanded()
	if err != nil {
		return nil, nil, err
	}
	user, err = userPath.expanded()
	if err != nil {
		return nil, nil, err
	}
	return machine, user, nil
}

// expanded returns the entries as a shell for this user would see them.
// ExpandString reads %VAR% from this process's environment, and SplitList
// strips the quotes a PATH entry may carry.
func (s pathScope) expanded() ([]string, error) {
	entries, _, err := s.read()
	if err != nil {
		return nil, err
	}
	value, err := registry.ExpandString(strings.Join(entries, ";"))
	if err != nil {
		return nil, fmt.Errorf("failed to expand PATH under %s: %w", s.key, err)
	}
	return filepath.SplitList(value), nil
}

// prepend puts dir first, and moves it there when a later installer pushed
// it back. The shim directory has to be first, or a manager on an entry
// ahead of it wins. It writes the registry directly rather than through
// setx, which truncates a value at 1024 characters and would corrupt a
// developer's PATH.
func (s pathScope) prepend(dir string) error {
	entries, expand, err := s.read()
	if err != nil {
		return err
	}
	if len(entries) > 0 && sameEntry(entries[0], dir) {
		return nil
	}
	return s.write(append([]string{dir}, without(entries, dir)...), expand)
}

// append adds dir at the end when it is not on the PATH yet. Nothing moves.
func (s pathScope) append(dir string) error {
	entries, expand, err := s.read()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(entries, func(e string) bool { return sameEntry(e, dir) }) {
		return nil
	}
	return s.write(append(slices.Clone(entries), dir), expand)
}

// remove drops every entry that names dir.
func (s pathScope) remove(dir string) error {
	entries, expand, err := s.read()
	if err != nil {
		return err
	}
	kept := without(entries, dir)
	if len(kept) == len(entries) {
		return nil
	}
	if len(kept) == 0 && s.deleteWhenEmpty {
		return s.deleteValue()
	}
	return s.write(kept, expand)
}

func (s pathScope) contains(dir string) (bool, error) {
	entries, _, err := s.read()
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(entries, func(e string) bool { return sameEntry(e, dir) }), nil
}

// read returns the raw entries and whether the value is REG_EXPAND_SZ. The
// raw form keeps %USERPROFILE% style references that other tools wrote, so
// a write does not flatten them.
func (s pathScope) read() (entries []string, expand bool, err error) {
	key, err := registry.OpenKey(s.root, s.key, registry.QUERY_VALUE)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open %s: %w", s.key, err)
	}
	defer key.Close()

	value, valueType, err := key.GetStringValue(pathValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to read PATH under %s: %w", s.key, err)
	}
	return splitRawPath(value), valueType == registry.EXPAND_SZ, nil
}

func (s pathScope) write(entries []string, expand bool) error {
	key, err := registry.OpenKey(s.root, s.key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", s.key, err)
	}
	defer key.Close()

	value := strings.Join(entries, ";")
	if expand {
		err = key.SetExpandStringValue(pathValueName, value)
	} else {
		err = key.SetStringValue(pathValueName, value)
	}
	if err != nil {
		return fmt.Errorf("failed to write PATH under %s: %w", s.key, err)
	}

	broadcastEnvironmentChange()
	return nil
}

func (s pathScope) deleteValue() error {
	key, err := registry.OpenKey(s.root, s.key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", s.key, err)
	}
	defer key.Close()

	if err := key.DeleteValue(pathValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("failed to delete PATH under %s: %w", s.key, err)
	}
	broadcastEnvironmentChange()
	return nil
}

// sameEntry expands a raw entry first, so %ProgramFiles%\safedep\pmg\bin
// written by hand matches the directory it names and is not duplicated.
func sameEntry(raw, dir string) bool {
	expanded, err := registry.ExpandString(raw)
	if err != nil {
		expanded = raw
	}
	return fsutil.SamePath(strings.Trim(expanded, `"`), dir)
}

func without(entries []string, dir string) []string {
	return slices.DeleteFunc(slices.Clone(entries), func(e string) bool { return sameEntry(e, dir) })
}

// splitRawPath keeps each entry exactly as the registry holds it, quotes and
// all, so a read, edit and write-back does not rewrite entries PMG does not
// own.
func splitRawPath(value string) []string {
	var entries []string
	for entry := range strings.SplitSeq(value, ";") {
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
