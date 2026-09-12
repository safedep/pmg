package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/safedep/pmg/internal/fsutil"
)

const pathValueName = "Path"

// registryPathScope is one registry PATH value, the user's or the machine's.
// Both are read, edited and written the same way. Tests point root and key at
// a scratch key through RedirectUserPathForTest and RedirectMachinePathForTest.
type registryPathScope struct {
	root registry.Key
	key  string
	// The user PATH had no value before PMG's install, so removing the last
	// entry leaves none behind. The machine PATH is not PMG's to delete.
	deleteWhenEmpty bool
}

var (
	// UserPath is HKCU\Environment, the PATH every new shell of this user gets.
	UserPath = registryPathScope{root: registry.CURRENT_USER, key: `Environment`, deleteWhenEmpty: true}
	// MachinePath is the machine PATH every account inherits, ahead of the user
	// PATH.
	MachinePath = registryPathScope{root: registry.LOCAL_MACHINE, key: `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`}
)

// Prepend puts dir first, and moves it there when a later installer pushed it
// back. The shim directory has to be first, or a manager on an entry ahead of
// it wins. It writes the registry directly rather than through setx, which
// truncates a value at 1024 characters and would corrupt a developer's PATH.
func (s registryPathScope) Prepend(dir string) error {
	entries, expand, err := s.read()
	if err != nil {
		return err
	}
	if len(entries) > 0 && sameEntry(entries[0], dir) {
		return nil
	}
	return s.write(append([]string{dir}, without(entries, dir)...), expand)
}

// Append adds dir at the end when it is not on the PATH yet. Nothing moves.
func (s registryPathScope) Append(dir string) error {
	entries, expand, err := s.read()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(entries, func(e string) bool { return sameEntry(e, dir) }) {
		return nil
	}
	return s.write(append(slices.Clone(entries), dir), expand)
}

// Remove drops every entry that names dir.
func (s registryPathScope) Remove(dir string) error {
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

func (s registryPathScope) Contains(dir string) (bool, error) {
	entries, _, err := s.read()
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(entries, func(e string) bool { return sameEntry(e, dir) }), nil
}

// Entries returns the raw PATH entries, with the quotes and %VAR% references
// other tools wrote left intact.
func (s registryPathScope) Entries() ([]string, error) {
	entries, _, err := s.read()
	return entries, err
}

// expanded returns the entries as a shell for this user would see them.
// ExpandString reads %VAR% from this process's environment, and SplitList
// strips the quotes a PATH entry may carry.
func (s registryPathScope) expanded() ([]string, error) {
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

// read returns the raw entries and whether the value is REG_EXPAND_SZ. The
// raw form keeps %USERPROFILE% style references that other tools wrote, so a
// write does not flatten them.
func (s registryPathScope) read() (entries []string, expand bool, err error) {
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

func (s registryPathScope) write(entries []string, expand bool) error {
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

func (s registryPathScope) deleteValue() error {
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

// ShellPath on Windows is the machine half then the user half, plus the
// process PATH, which alone shows a directory a shell profile added.
type ShellPath struct {
	// Entries is the machine PATH then the user PATH, the whole value a new
	// shell gets.
	Entries []string

	machine []string
	user    []string
	process []string
}

func NewShellPath() (ShellPath, error) {
	machine, err := MachinePath.expanded()
	if err != nil {
		return ShellPath{}, err
	}
	user, err := UserPath.expanded()
	if err != nil {
		return ShellPath{}, err
	}
	process := filepath.SplitList(os.Getenv("PATH"))
	return ShellPath{
		Entries: append(append([]string{}, machine...), user...),
		machine: machine,
		user:    user,
		process: process,
	}, nil
}

// LookPath resolves name the way a shell would and reports the PATH source
// that held the winning directory. A directory only the process PATH holds
// was added by a shell profile: `fnm env | Invoke-Expression` in $PROFILE
// prepends a directory the registry never sees. Every shim directory is on
// the registry PATH, so a shim never reads as profile-added. Anything else
// takes the registry answer, so a shell started before the install does not
// report a registered shim directory as absent.
func (p ShellPath) LookPath(name string) (string, PathOrigin, error) {
	if resolved, err := lookPathIn(name, p.process); err == nil &&
		!fsutil.PathWithinAny(resolved, p.machine) && !fsutil.PathWithinAny(resolved, p.user) {
		return resolved, PathOriginProfile, nil
	}
	resolved, err := lookPathIn(name, p.Entries)
	if err != nil {
		return "", PathOriginUnknown, err
	}
	return resolved, originOf(resolved, p.machine, p.user), nil
}

// originOf names the PATH half that holds the directory of path. Windows
// searches the machine half first, so it wins a directory in both.
func originOf(path string, machine, user []string) PathOrigin {
	if fsutil.PathWithinAny(path, machine) {
		return PathOriginMachine
	}
	if fsutil.PathWithinAny(path, user) {
		return PathOriginUser
	}
	return PathOriginUnknown
}

// lookPathIn resolves a name over the given PATH entries with the PATHEXT
// rule, so the answer matches what a shell would run.
func lookPathIn(name string, entries []string) (string, error) {
	exts := pathExtensions()
	for _, dir := range entries {
		for _, ext := range exts {
			// The extension is lower-cased as exec.LookPath does, so a
			// resolved path reads `npm.cmd` rather than `npm.CMD`.
			candidate := filepath.Join(dir, name+strings.ToLower(ext))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// pathExtensions drops an empty entry, which a trailing semicolon in PATHEXT
// leaves behind. An empty extension would match a file with no extension,
// such as the sh script npm ships next to npm.cmd, which cmd.exe cannot run.
func pathExtensions() []string {
	value := os.Getenv("PATHEXT")
	if value == "" {
		value = ".COM;.EXE;.BAT;.CMD"
	}

	exts := make([]string, 0, 4)
	for _, ext := range strings.Split(value, ";") {
		if ext != "" {
			exts = append(exts, ext)
		}
	}
	return exts
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

// RedirectUserPathForTest creates a scratch key under HKCU, points the user
// PATH scope at it, and returns a func that restores the scope and deletes
// the key. There is no env var or flag for it; production never calls it.
func RedirectUserPathForTest(key string) (restore func(), err error) {
	if err := createScratchKey(key); err != nil {
		return nil, err
	}
	orig := UserPath
	UserPath.key = key
	return func() {
		UserPath = orig
		deleteScratchKey(key)
	}, nil
}

// RedirectMachinePathForTest creates a scratch key under HKCU, points the
// machine PATH scope at it, and returns a func that restores the scope and
// deletes the key. HKLM needs elevation, and the code does not care which
// root it opens.
func RedirectMachinePathForTest(key string) (restore func(), err error) {
	if err := createScratchKey(key); err != nil {
		return nil, err
	}
	orig := MachinePath
	MachinePath.root, MachinePath.key = registry.CURRENT_USER, key
	return func() {
		MachinePath = orig
		deleteScratchKey(key)
	}, nil
}

func createScratchKey(key string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	return k.Close()
}

func deleteScratchKey(key string) {
	// Best-effort: a scratch key that outlives the test is harmless.
	_ = registry.DeleteKey(registry.CURRENT_USER, key)
}

// WriteMachinePathForTest seeds the machine PATH scope with value as a
// REG_EXPAND_SZ, so a test can set the PATH a machine installer left behind.
// It is for tests that redirected the scope to a scratch key.
func WriteMachinePathForTest(value string) error {
	return MachinePath.write([]string{value}, true)
}
