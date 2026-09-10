//go:build windows

// Package winacl reads and writes the Windows access control of the paths a
// system install owns. One invariant makes it small: every file PMG relies
// on in a system path is written by PMG with a protected DACL and validated
// on its own. Inheritance therefore never reaches anything PMG runs, and the
// checks look only at entries that apply to the object itself.
package winacl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessIsElevated reports whether UAC elevated this process. Only an
// elevated process can write Program Files and the machine PATH.
func ProcessIsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// The DACL PMG writes, in SDDL. Administrators own the object. SYSTEM and
// Administrators have full control, Users read and execute. PAI blocks
// inheritance, so a user-writable entry on a parent never reaches the
// object. It is the stock Program Files ACL without TrustedInstaller and
// CREATOR OWNER.
//
// Grammar and aliases: https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format
// (BA Administrators, SY SYSTEM, BU Users, A allow, OICI object and
// container inherit, FA file all access). 0x1200a9 is FILE_GENERIC_READ |
// FILE_GENERIC_EXECUTE, the "Read & execute" that icacls prints as (RX):
// https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
const (
	protectedDirSDDL  = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	protectedFileSDDL = "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
)

// Protect replaces the owner and the DACL of a path PMG created or fully
// manages, so a directory a standard user pre-created under ProgramData, or a
// file that kept an old DACL when it was overwritten, ends up
// administrator-only. No-op without elevation, where the owner write would
// fail, and per-user artifacts keep the ACL they inherited by design.
func Protect(path string) error {
	if !ProcessIsElevated() {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	sddl := protectedFileSDDL
	if info.IsDir() {
		sddl = protectedDirSDDL
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("failed to build the security descriptor for %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("failed to read the owner for %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("failed to read the DACL for %s: %w", path, err)
	}

	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("failed to set administrator ownership on %s: %w", path, err)
	}
	return nil
}

// RequireNotReparsePoint rejects a symbolic link or a junction at path. A
// reparse point in a PMG-owned path would send every write, and every ACL
// change, to a target a standard user chose. A missing path passes.
func RequireNotReparsePoint(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is a link or a junction, which PMG does not follow in a system path", path)
	}
	return nil
}

// RequireTrustedExisting accepts a path that does not exist, and otherwise
// requires that it is a plain file or directory that only administrators
// can write. Setup calls it before it reads a managed file, because a
// protected owner set afterwards does not make the contents trustworthy.
func RequireTrustedExisting(path string) error {
	if err := RequireNotReparsePoint(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return RequireAdminOnlyWritable(path)
}

// RequireProtectedDir checks the directory itself and then every ancestor
// up to the volume root. An ancestor a standard user can delete from, or
// rename, lets them replace a protected directory with their own.
func RequireProtectedDir(dir string) error {
	if err := RequireAdminOnlyWritable(dir); err != nil {
		return err
	}
	for parent := filepath.Dir(dir); parent != dir; dir, parent = parent, filepath.Dir(parent) {
		if err := requireNoOutsiderRights(parent, replaceRights, "rename or delete its entries"); err != nil {
			return err
		}
	}
	return nil
}

// RequireAdminOnlyWritable requires an administrative owner and no allow
// entry that gives a standard user write rights.
func RequireAdminOnlyWritable(path string) error {
	return requireNoOutsiderRights(path, writeRights, "write it")
}

// RequireExecutableByAll requires that every user can run the file.
func RequireExecutableByAll(path string) error {
	sd, err := securityDescriptor(path)
	if err != nil {
		return err
	}
	return validateExecutableByAll(sd, path)
}

func requireNoOutsiderRights(path string, mask windows.ACCESS_MASK, verb string) error {
	sd, err := securityDescriptor(path)
	if err != nil {
		return err
	}
	return validateNoOutsiderRights(sd, path, mask, verb)
}

func securityDescriptor(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("failed to read the security descriptor of %s: %w", path, err)
	}
	return sd, nil
}

// FILE_DELETE_CHILD from winnt.h, which x/sys does not carry:
// https://learn.microsoft.com/windows/win32/fileio/file-access-rights-constants
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

// validateNoOutsiderRights checks the owner and every allow entry that
// applies to the object itself. The owner can rewrite the DACL, so an owner
// outside the administrator set fails even when the DACL is tight today.
func validateNoOutsiderRights(sd *windows.SECURITY_DESCRIPTOR, path string, mask windows.ACCESS_MASK, verb string) error {
	if err := requireAdministrativeOwner(sd, path); err != nil {
		return err
	}
	aces, err := daclAces(sd, path)
	if err != nil {
		return err
	}
	for _, ace := range aces {
		sid := aceSid(ace)
		if !isAllow(ace) || isInheritOnly(ace) || isAdministrativeSid(sid) || ace.Mask&mask == 0 {
			continue
		}
		return fmt.Errorf("%s lets %s %s, so a standard user could replace what PMG runs", path, sidName(sid), verb)
	}
	return nil
}

// validateExecutableByAll requires an allow entry that lets every user run
// the file, and no deny entry that takes execution from anyone outside the
// administrator set. A deny for one group means the shims exit 127 for its
// members, which is an outage, not a policy.
func validateExecutableByAll(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	aces, err := daclAces(sd, path)
	if err != nil {
		return err
	}
	allowed := false
	for _, ace := range aces {
		sid := aceSid(ace)
		if isInheritOnly(ace) || ace.Mask&executeRights == 0 {
			continue
		}
		if !isAllow(ace) && !isAdministrativeSid(sid) {
			return fmt.Errorf("pmg executable %s denies execution to %s", path, sidName(sid))
		}
		if isAllow(ace) && isEveryoneSid(sid) {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("pmg executable %s is not executable by all users", path)
	}
	return nil
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
// access for everyone, so it is an error. So is an entry that cannot be
// read, and so is an entry of a type this code does not evaluate, such as
// a callback or conditional entry, because a check that skips entries is
// no check. Types: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header
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
		if t := ace.Header.AceType; t != windows.ACCESS_ALLOWED_ACE_TYPE && t != windows.ACCESS_DENIED_ACE_TYPE {
			return nil, fmt.Errorf("%s carries an access control entry of type %d, which PMG does not evaluate", path, t)
		}
		aces = append(aces, ace)
	}
	return aces, nil
}

// Allow and deny entries share one layout, and the SID follows the header
// in memory: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-access_allowed_ace
func isAllow(ace *windows.ACCESS_ALLOWED_ACE) bool {
	return ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE
}

func isInheritOnly(ace *windows.ACCESS_ALLOWED_ACE) bool {
	return ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
}

func aceSid(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}

// trustedInstallerSid has no well-known constant. It is the service SID of
// TrustedInstaller, S-1-5-80 followed by the SHA-1 of the service name, and
// it owns most of Program Files on a stock machine:
// https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
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
