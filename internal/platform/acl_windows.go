package platform

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The trust checks for a Windows system install. The threat model includes
// a standard user before or after installation. Administrators and SYSTEM
// are trusted, standard users are not. Every PMG-written object carries the
// exact PMG security descriptor. ACL reads and writes use one handle that
// does not follow links, so what was checked is what is written.
//
// The PMG descriptor, in SDDL. Administrators own the object. SYSTEM and
// Administrators have full control, Users read and execute. P blocks
// inheritance, so an entry on a parent never reaches the object.
//
// Grammar and aliases: https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-string-format
// BA Administrators, SY SYSTEM, BU Users, A allow, OICI object and container
// inherit, FA FILE_ALL_ACCESS. 0x1200a9 is FILE_GENERIC_READ |
// FILE_GENERIC_EXECUTE, the "Read & execute" that icacls prints as (RX):
// https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
const (
	protectedDirSDDL  = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	protectedFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
)

// writeRights let an account change, replace or remove an object, or, on a
// directory, remove or rename what is inside it. FILE_DELETE_CHILD is
// 0x40 in winnt.h, which x/sys does not carry:
// https://learn.microsoft.com/windows/win32/fileio/file-access-rights-constants
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// descriptor is the PMG descriptor parsed once, with its DACL entries.
type descriptor struct {
	owner *windows.SID
	dacl  *windows.ACL
	aces  []*windows.ACCESS_ALLOWED_ACE
}

var (
	fileDescriptor = sync.OnceValues(func() (descriptor, error) { return parseDescriptor(protectedFileSDDL) })
	dirDescriptor  = sync.OnceValues(func() (descriptor, error) { return parseDescriptor(protectedDirSDDL) })
)

// object is an open handle to a file or directory, with the facts the
// checks need. Every check and every write goes through it, so what was
// checked is what is written.
type object struct {
	handle windows.Handle
	path   string
	isDir  bool
}

// open opens path without following a link or a junction and refuses one.
// FILE_FLAG_OPEN_REPARSE_POINT opens the reparse point itself rather than
// its target, and FILE_FLAG_BACKUP_SEMANTICS lets a directory be opened:
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
func open(path string, access uint32) (*object, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	handle, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("%s is a link or a junction, which PMG does not follow in a system path", path)
	}
	return &object{
		handle: handle,
		path:   path,
		isDir:  info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0,
	}, nil
}

func (o *object) close() { windows.CloseHandle(o.handle) }

func (o *object) security(what windows.SECURITY_INFORMATION) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetSecurityInfo(o.handle, windows.SE_FILE_OBJECT, what)
	if err != nil {
		return nil, fmt.Errorf("failed to read the security descriptor of %s: %w", o.path, err)
	}
	return sd, nil
}

func (o *object) expected() (descriptor, error) {
	if o.isDir {
		return dirDescriptor()
	}
	return fileDescriptor()
}

// SetSecurityInfo needs an owner SID that the caller may assign.
// The elevation check avoids a partial security update.
func protect(path string) error {
	if !IsPrivileged() {
		return fmt.Errorf("cannot protect %s: the process is not elevated", path)
	}
	o, err := open(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		return err
	}
	defer o.close()

	sd, err := o.security(windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if err := requireAdministrativeOwner(sd, path); err != nil {
		return fmt.Errorf("%w. Delete it and run the install again", err)
	}
	want, err := o.expected()
	if err != nil {
		return err
	}
	err = windows.SetSecurityInfo(o.handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		want.owner, nil, want.dacl, nil)
	if err != nil {
		return fmt.Errorf("failed to protect %s: %w", path, err)
	}
	return nil
}

func requireProtected(path string) error {
	o, err := open(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer o.close()

	sd, err := o.security(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	want, err := o.expected()
	if err != nil {
		return err
	}
	if err := compare(sd, want); err != nil {
		return fmt.Errorf("%s does not carry the PMG security descriptor: %w", path, err)
	}
	return nil
}

// An administrator or MDM can create a managed configuration with inherited entries.
// This check accepts that file when only trusted principals control it.
func requireSystemControlled(path string) error {
	o, err := open(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer o.close()

	sd, err := o.security(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return validateAdministrativeControl(sd, path)
}

// A missing path has no handle to inspect before its creation.
func requireNotReparsePoint(path string) error {
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

func requireTrustedSystemFile(path string) error {
	o, err := open(path, windows.READ_CONTROL)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer o.close()
	if o.isDir {
		return fmt.Errorf("%s is not a regular file", path)
	}
	sd, err := o.security(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	want, err := fileDescriptor()
	if err != nil {
		return err
	}
	if err := compare(sd, want); err != nil {
		return fmt.Errorf("%s does not carry the PMG security descriptor: %w", path, err)
	}
	return nil
}

func parseDescriptor(sddl string) (descriptor, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return descriptor{}, fmt.Errorf("failed to build the PMG descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return descriptor{}, fmt.Errorf("failed to read the owner of the PMG descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return descriptor{}, fmt.Errorf("failed to read the DACL of the PMG descriptor: %w", err)
	}
	entries, err := aces(dacl)
	if err != nil {
		return descriptor{}, fmt.Errorf("failed to read the PMG descriptor: %w", err)
	}
	return descriptor{owner: owner, dacl: dacl, aces: entries}, nil
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
		return fmt.Errorf("%s is owned by %s, not by Administrators or SYSTEM", path, accountName(owner))
	}
	return nil
}

// validateAdministrativeControl is the owner rule plus: no allow entry that
// applies to the object gives a principal outside Administrators and SYSTEM
// a write or delete right. Deny entries only take rights away and are
// skipped. An entry of a type this code does not evaluate fails.
func validateAdministrativeControl(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	if err := requireAdministrativeOwner(sd, path); err != nil {
		return err
	}
	entries, err := daclEntries(sd)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, ace := range entries {
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := aceSid(ace)
		if isAdministrativeSid(sid) || ace.Mask&writeRights == 0 {
			continue
		}
		return fmt.Errorf("%s lets %s write or delete it", path, accountName(sid))
	}
	return nil
}

// compare checks owner, the DACL, the protected control bit, and the DACL
// entries as a set. Every entry PMG writes is an allow entry, so order
// carries no meaning for access, and Explorer rewrites the order when an
// administrator opens the security tab.
func compare(got *windows.SECURITY_DESCRIPTOR, want descriptor) error {
	owner, _, err := got.Owner()
	if err != nil {
		return fmt.Errorf("failed to read its owner: %w", err)
	}
	if owner == nil {
		return errors.New("it has no owner")
	}
	if !owner.Equals(want.owner) {
		return fmt.Errorf("the owner is %s, not Administrators", owner)
	}

	entries, err := daclEntries(got)
	if err != nil {
		return err
	}

	control, _, err := got.Control()
	if err != nil {
		return fmt.Errorf("failed to read its control flags: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("its DACL inherits from the parent")
	}

	if len(entries) != len(want.aces) {
		return fmt.Errorf("its DACL has %d entries, not %d", len(entries), len(want.aces))
	}
	matched := make([]bool, len(entries))
	for i, wanted := range want.aces {
		if !matchAce(entries, matched, wanted) {
			return fmt.Errorf("DACL entry %d of the PMG descriptor is missing or changed", i+1)
		}
	}
	return nil
}

// matchAce marks and reports the first unmatched entry equal to wanted.
func matchAce(entries []*windows.ACCESS_ALLOWED_ACE, matched []bool, wanted *windows.ACCESS_ALLOWED_ACE) bool {
	for i, entry := range entries {
		if !matched[i] && sameAce(entry, wanted) {
			matched[i] = true
			return true
		}
	}
	return false
}

// daclEntries returns the DACL entries. A missing DACL grants everyone full
// access and fails. An entry of a type this code does not evaluate, such as
// a callback or conditional entry, fails, because a check that skips
// entries is no check. Types: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header
func daclEntries(sd *windows.SECURITY_DESCRIPTOR) ([]*windows.ACCESS_ALLOWED_ACE, error) {
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil, fmt.Errorf("failed to read its DACL: %w", err)
	}
	if dacl == nil {
		return nil, errors.New("it has no DACL, which grants every user full access")
	}
	entries, err := aces(dacl)
	if err != nil {
		return nil, err
	}
	for _, ace := range entries {
		if t := ace.Header.AceType; t != windows.ACCESS_ALLOWED_ACE_TYPE && t != windows.ACCESS_DENIED_ACE_TYPE {
			return nil, fmt.Errorf("its DACL carries an entry of type %d, which PMG does not evaluate", t)
		}
	}
	return entries, nil
}

func aces(dacl *windows.ACL) ([]*windows.ACCESS_ALLOWED_ACE, error) {
	out := make([]*windows.ACCESS_ALLOWED_ACE, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, fmt.Errorf("failed to read DACL entry %d: %w", i+1, err)
		}
		out = append(out, ace)
	}
	return out, nil
}

// sameAce compares type, flags, mask and SID. Every entry PMG writes is an
// allow entry, so the SID sits at SidStart for both sides:
// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-access_allowed_ace
func sameAce(a, b *windows.ACCESS_ALLOWED_ACE) bool {
	if a.Header.AceType != b.Header.AceType || a.Header.AceFlags != b.Header.AceFlags || a.Mask != b.Mask {
		return false
	}
	if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return false
	}
	return aceSid(a).Equals(aceSid(b))
}

// Allow and deny entries share one layout, and the SID follows the header.
func aceSid(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}

func isAdministrativeSid(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid)
}

func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
