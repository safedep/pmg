//go:build windows

package fsutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// ProcessIsElevated reports whether UAC elevated this process. Only an
// elevated process can write Program Files and the machine PATH.
func ProcessIsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// Administrators own the object. SYSTEM and Administrators have full
// control, Users read and execute. PAI blocks inheritance, so a
// user-writable entry on a parent never reaches the object.
const (
	protectedDirSDDL  = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	protectedFileSDDL = "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
)

// ForceRootOwned is the Windows form of the Unix helper. It replaces the
// owner and the DACL of a path pmg created or fully manages, so a directory a
// standard user pre-created under ProgramData, or a file that kept an old
// DACL when it was overwritten, ends up administrator-only. The mode has no
// Windows meaning. No-op without elevation, where the owner write would
// fail, and per-user artifacts keep the ACL they inherited by design.
func ForceRootOwned(path string, _ os.FileMode) error {
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
