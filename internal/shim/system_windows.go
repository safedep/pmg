//go:build windows

package shim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultSystemBinDir is the machine-wide shim directory. Program Files
// inherits an ACL that only administrators can write, which is what makes
// the directory safe at the front of the machine PATH. The known folder is
// asked, not the environment, which the caller's shell controls.
func defaultSystemBinDir() string {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "safedep", "pmg", "bin")
}

// Windows has no profile.d. The machine PATH carries the shim directory.
func defaultSystemProfilePath() string { return "" }

// installSystemPath puts the shim directory first on the machine PATH, and
// the binary's directory on it too, so `pmg` itself resolves in every
// terminal. The shims are checked first: a file a standard user can write
// must not be the first `npm` on the machine PATH, where an elevated process
// would run it. The binary's directory passed the same checks in
// validateSystemExecutable.
func installSystemPath(binDir, pmgBin string) error {
	if err := validateSystemShimDir(binDir); err != nil {
		return err
	}
	if err := registerMachinePath(binDir); err != nil {
		return err
	}
	return appendMachinePath(filepath.Dir(pmgBin))
}

// removeSystemPath takes the shim directory off the machine PATH. The
// binary's directory stays, as /usr/local/bin does on Linux: the binary is
// still there, and the entry may predate PMG.
func removeSystemPath(binDir, _ string) error { return unregisterMachinePath(binDir) }

func systemPathInstalled(binDir string) bool {
	found, err := machinePathContains(binDir)
	return err == nil && found
}

// validateSystemExecutable rejects a binary a standard user could replace.
// Every system shim runs this path as whichever user typed the command, so
// the file and its directory must be writable by administrators only, no
// ancestor may let a standard user swap a path component, and every user
// must be able to run the file. Symbolic links and junctions are resolved
// first, so the checks apply to the file that runs.
func validateSystemExecutable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}
	if !systemExecutableOwnershipCheck {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("failed to resolve pmg executable %s: %w", path, err)
	}
	if err := requireAdminOnlyWritable(resolved); err != nil {
		return err
	}
	if err := requireProtectedDir(filepath.Dir(resolved)); err != nil {
		return err
	}
	return requireExecutableByAll(resolved)
}

// validateSystemShimDir applies the binary's rules to the shim directory
// and every shim in it. A shim overwritten in place keeps the DACL it had,
// so the files are checked one by one, not through the directory.
func validateSystemShimDir(dir string) error {
	if !systemExecutableOwnershipCheck {
		return nil
	}
	if err := requireProtectedDir(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to list the shim directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := requireAdminOnlyWritable(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// requireProtectedDir checks the directory itself and then every ancestor
// up to the volume root. An ancestor a standard user can delete from, or
// rename, lets them replace a protected directory with their own.
func requireProtectedDir(dir string) error {
	if err := requireAdminOnlyWritable(dir); err != nil {
		return err
	}
	for parent := filepath.Dir(dir); parent != dir; dir, parent = parent, filepath.Dir(parent) {
		if err := requireNotReplaceable(parent); err != nil {
			return err
		}
	}
	return nil
}

func requireAdminOnlyWritable(path string) error {
	sd, err := securityDescriptor(path)
	if err != nil {
		return err
	}
	return validateAdminOnlyWritable(sd, path)
}

func requireNotReplaceable(path string) error {
	sd, err := securityDescriptor(path)
	if err != nil {
		return err
	}
	return validateNotReplaceable(sd, path)
}

func requireExecutableByAll(path string) error {
	sd, err := securityDescriptor(path)
	if err != nil {
		return err
	}
	return validateExecutableByAll(sd, path)
}

func securityDescriptor(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("failed to read the security descriptor of %s: %w", path, err)
	}
	return sd, nil
}

const fileDeleteChild = 0x40

// writeRights let an account change or replace a file, or add to and delete
// from a directory. Adding to the binary's directory counts, because a DLL
// planted next to pmg.exe loads with it.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// replaceRights let an account rename or delete an entry of a directory, or
// take the directory over. Adding entries is not among them: the root of a
// volume lets every user create a folder, and that swaps nothing that
// exists.
const replaceRights = fileDeleteChild | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

const executeRights = windows.FILE_EXECUTE | windows.GENERIC_ALL | windows.GENERIC_EXECUTE

// validateAdminOnlyWritable checks the owner and every allow entry. The owner
// can rewrite the DACL, so an owner outside the administrator set fails
// even when the DACL is tight today. Inherit-only entries on a directory
// count, because they shape the files created inside it.
func validateAdminOnlyWritable(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	if err := requireAdministrativeOwner(sd, path); err != nil {
		return err
	}
	aces, err := daclAces(sd, path)
	if err != nil {
		return err
	}
	for _, ace := range aces {
		sid := aceSid(ace)
		if !isAllow(ace) || isAdministrativeSid(sid) || isCreatorOwnerTemplate(ace, sid) || ace.Mask&writeRights == 0 {
			continue
		}
		return fmt.Errorf("%s is writable by %s, so a standard user could replace it", path, sidName(sid))
	}
	return nil
}

// validateNotReplaceable is the ancestor rule. Only entries that apply to
// the directory itself matter, so inherit-only ones are skipped.
func validateNotReplaceable(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	if err := requireAdministrativeOwner(sd, path); err != nil {
		return err
	}
	aces, err := daclAces(sd, path)
	if err != nil {
		return err
	}
	for _, ace := range aces {
		sid := aceSid(ace)
		if !isAllow(ace) || isInheritOnly(ace) || isAdministrativeSid(sid) || ace.Mask&replaceRights == 0 {
			continue
		}
		return fmt.Errorf("%s lets %s rename or delete its entries, so a standard user could replace a protected directory under it", path, sidName(sid))
	}
	return nil
}

// validateExecutableByAll requires an allow entry that lets every user run
// the file, with no deny entry for them ahead of it. Windows reads the DACL
// in order and a deny wins over a later allow, so the walk stops at the
// first entry that decides.
func validateExecutableByAll(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	aces, err := daclAces(sd, path)
	if err != nil {
		return err
	}
	for _, ace := range aces {
		if isInheritOnly(ace) || !isEveryoneSid(aceSid(ace)) || ace.Mask&executeRights == 0 {
			continue
		}
		if isAllow(ace) {
			return nil
		}
		return fmt.Errorf("pmg executable %s denies execution to %s", path, sidName(aceSid(ace)))
	}
	return fmt.Errorf("pmg executable %s is not executable by all users", path)
}

func requireAdministrativeOwner(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("failed to read the owner of %s: %w", path, err)
	}
	if owner == nil {
		return fmt.Errorf("%s has no owner", path)
	}
	if !isAdministrativeSid(owner) {
		return fmt.Errorf("%s must be owned by Administrators, SYSTEM or TrustedInstaller, not %s", path, sidName(owner))
	}
	return nil
}

// daclAces returns every entry of the DACL. A missing DACL means full
// access for everyone, so it is an error, and so is an entry that cannot be
// read, because a check that skips entries is no check.
func daclAces(sd *windows.SECURITY_DESCRIPTOR, path string) ([]*windows.ACCESS_ALLOWED_ACE, error) {
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil, fmt.Errorf("failed to read the DACL of %s: %w", path, err)
	}
	if dacl == nil {
		return nil, fmt.Errorf("%s has no DACL, which grants every user full access", path)
	}
	aces := make([]*windows.ACCESS_ALLOWED_ACE, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, fmt.Errorf("failed to read entry %d of the DACL of %s: %w", i, path, err)
		}
		aces = append(aces, ace)
	}
	return aces, nil
}

// Allow and deny entries share one layout. Object-specific types do not
// occur on files.
func isAllow(ace *windows.ACCESS_ALLOWED_ACE) bool {
	return ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE
}

func isInheritOnly(ace *windows.ACCESS_ALLOWED_ACE) bool {
	return ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
}

func aceSid(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}

// isCreatorOwnerTemplate matches the inherit-only CREATOR OWNER entry that
// Program Files carries. It grants nothing on the directory itself and
// becomes an entry for whoever creates a file inside, which under Program
// Files is an administrator.
func isCreatorOwnerTemplate(ace *windows.ACCESS_ALLOWED_ACE, sid *windows.SID) bool {
	return isInheritOnly(ace) && sid.IsWellKnown(windows.WinCreatorOwnerSid)
}

// trustedInstallerSid has no well-known constant. It owns most of Program
// Files on a stock machine.
const trustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func isAdministrativeSid(sid *windows.SID) bool {
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	return sid.String() == trustedInstallerSid
}

// isEveryoneSid matches the groups every interactive user belongs to.
func isEveryoneSid(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinWorldSid) ||
		sid.IsWellKnown(windows.WinAuthenticatedUserSid) ||
		sid.IsWellKnown(windows.WinBuiltinUsersSid)
}

func sidName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
