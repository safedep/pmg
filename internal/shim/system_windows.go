//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultSystemBinDir is the machine-wide shim directory. Program Files
// inherits an ACL that only administrators can write, which is what makes
// the directory safe at the front of the machine PATH.
func defaultSystemBinDir() string {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "safedep", "pmg", "bin")
}

// Windows has no profile.d. The machine PATH carries the shim directory.
func defaultSystemProfilePath() string { return "" }

// installSystemPath puts the shim directory first on the machine PATH. The
// directory is checked first: a directory a standard user can write must not
// sit ahead of Program Files, where an elevated process would find a planted
// binary.
func installSystemPath(binDir string) error {
	if err := requireAdminOnlyWritable(binDir); err != nil {
		return err
	}
	return registerMachinePath(binDir)
}

func removeSystemPath(binDir string) error { return unregisterMachinePath(binDir) }

func systemPathInstalled(binDir string) bool {
	found, err := machinePathContains(binDir)
	return err == nil && found
}

// validateSystemExecutable rejects a binary a standard user could replace.
// Every system shim runs this path as whichever user typed the command, so
// the file and its directory must be writable by administrators only, and
// the file must be executable by everyone.
func validateSystemExecutable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}
	if !systemExecutableOwnershipCheck {
		return nil
	}
	if err := requireAdminOnlyWritable(path); err != nil {
		return err
	}
	if err := requireAdminOnlyWritable(filepath.Dir(path)); err != nil {
		return err
	}
	return requireExecutableByAll(path)
}

func requireAdminOnlyWritable(path string) error {
	sd, err := securityDescriptor(path)
	if err != nil {
		return err
	}
	return validateAdminOnlyWritable(sd, path)
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

// writeRights are the rights that let an account change or replace a file,
// or add to and delete from a directory.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

const fileDeleteChild = 0x40

const executeRights = windows.FILE_EXECUTE | windows.GENERIC_ALL | windows.GENERIC_EXECUTE

// validateAdminOnlyWritable checks the owner and every allow ACE. The owner
// can rewrite the DACL, so an owner outside the administrator set fails
// even when the DACL is tight today. Inherit-only ACEs on a directory count,
// because they shape the files created inside it.
func validateAdminOnlyWritable(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("failed to read the owner of %s: %w", path, err)
	}
	if !isAdministrativeSid(owner) {
		return fmt.Errorf("%s must be owned by Administrators, SYSTEM or TrustedInstaller, not %s", path, sidName(owner))
	}

	for _, ace := range allowAces(sd, path) {
		sid := aceSid(ace)
		if isAdministrativeSid(sid) || isCreatorOwnerTemplate(ace, sid) || ace.Mask&writeRights == 0 {
			continue
		}
		return fmt.Errorf("%s is writable by %s, so a standard user could replace it", path, sidName(sid))
	}
	return nil
}

// isCreatorOwnerTemplate matches the inherit-only CREATOR OWNER entry that
// Program Files carries. It grants nothing on the directory itself and
// becomes an entry for whoever creates a file inside, which under Program
// Files is an administrator.
func isCreatorOwnerTemplate(ace *windows.ACCESS_ALLOWED_ACE, sid *windows.SID) bool {
	return ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 && sid.IsWellKnown(windows.WinCreatorOwnerSid)
}

// validateExecutableByAll requires one allow ACE that lets every user run
// the file, or every shim exits 127 for a standard user.
func validateExecutableByAll(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	for _, ace := range allowAces(sd, path) {
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if isEveryoneSid(aceSid(ace)) && ace.Mask&executeRights != 0 {
			return nil
		}
	}
	return fmt.Errorf("pmg executable %s is not executable by all users", path)
}

func allowAces(sd *windows.SECURITY_DESCRIPTOR, path string) []*windows.ACCESS_ALLOWED_ACE {
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil
	}
	var aces []*windows.ACCESS_ALLOWED_ACE
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			aces = append(aces, ace)
		}
	}
	return aces
}

func aceSid(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
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
