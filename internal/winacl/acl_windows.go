//go:build windows

// Package winacl applies and verifies the one security descriptor that PMG
// puts on every object of a Windows system install. PMG owns those objects,
// so it does not evaluate arbitrary ACLs. An object either carries the
// exact PMG descriptor or it is not trusted.
package winacl

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessIsElevated reports whether UAC elevated this process. Only an
// elevated process can write Program Files and the machine PATH.
func ProcessIsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

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

// Protect replaces the owner and the DACL of path with the PMG descriptor.
// SetNamedSecurityInfo needs the owner SID in the caller's token with the
// owner right, which an elevated administrator token has and a standard
// token does not, so the call is refused without elevation rather than left
// to fail half way.
func Protect(path string) error {
	if !ProcessIsElevated() {
		return fmt.Errorf("cannot protect %s: the process is not elevated", path)
	}
	isDir, err := isDirectory(path)
	if err != nil {
		return err
	}
	want, err := expected(isDir)
	if err != nil {
		return err
	}
	owner, _, err := want.Owner()
	if err != nil {
		return fmt.Errorf("failed to read the owner of the PMG descriptor: %w", err)
	}
	dacl, _, err := want.DACL()
	if err != nil {
		return fmt.Errorf("failed to read the DACL of the PMG descriptor: %w", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("failed to protect %s: %w", path, err)
	}
	return nil
}

// RequireProtected requires that path is not a reparse point and carries
// the PMG descriptor exactly: owner, protected DACL, and the same entries in
// the same order.
func RequireProtected(path string) error {
	if err := RequireNotReparsePoint(path); err != nil {
		return err
	}
	isDir, err := isDirectory(path)
	if err != nil {
		return err
	}
	got, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("failed to read the security descriptor of %s: %w", path, err)
	}
	want, err := expected(isDir)
	if err != nil {
		return err
	}
	if err := compare(got, want); err != nil {
		return fmt.Errorf("%s does not carry the PMG security descriptor: %w", path, err)
	}
	return nil
}

// RequireNotReparsePoint rejects a symbolic link or a junction at path. A
// reparse point in a PMG-owned path would send every write, and every
// descriptor change, to a target a standard user chose. A missing path
// passes.
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
// requires a regular file that carries the PMG descriptor. Setup calls it
// before it reads a managed file, because a descriptor set afterwards does
// not make the contents trustworthy.
func RequireTrustedExisting(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return RequireProtected(path)
}

func isDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	return info.IsDir(), nil
}

func expected(isDir bool) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := protectedFileSDDL
	if isDir {
		sddl = protectedDirSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("failed to build the PMG descriptor: %w", err)
	}
	return sd, nil
}

// compare checks owner, the protected control bit, and every DACL entry in
// order. SetNamedSecurityInfo does not reorder explicit entries, so order
// is stable. A missing DACL grants everyone full access and fails.
func compare(got, want *windows.SECURITY_DESCRIPTOR) error {
	gotOwner, _, err := got.Owner()
	if err != nil || gotOwner == nil {
		return errors.New("it has no owner")
	}
	wantOwner, _, _ := want.Owner()
	if !gotOwner.Equals(wantOwner) {
		return fmt.Errorf("the owner is %s, not Administrators", gotOwner)
	}

	gotAces, err := aces(got)
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

	wantAces, _ := aces(want)
	if len(gotAces) != len(wantAces) {
		return fmt.Errorf("its DACL has %d entries, not %d", len(gotAces), len(wantAces))
	}
	for i := range wantAces {
		if !sameAce(gotAces[i], wantAces[i]) {
			return fmt.Errorf("DACL entry %d differs", i+1)
		}
	}
	return nil
}

func aces(sd *windows.SECURITY_DESCRIPTOR) ([]*windows.ACCESS_ALLOWED_ACE, error) {
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil, fmt.Errorf("failed to read its DACL: %w", err)
	}
	if dacl == nil {
		return nil, errors.New("it has no DACL, which grants every user full access")
	}
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
	return (*windows.SID)(unsafe.Pointer(&a.SidStart)).Equals((*windows.SID)(unsafe.Pointer(&b.SidStart)))
}
