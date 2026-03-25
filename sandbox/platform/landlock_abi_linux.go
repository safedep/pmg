//go:build linux
// +build linux

package platform

import (
	"fmt"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// landlockABI represents the detected Landlock ABI version and its feature capabilities.
// Each boolean flag indicates whether the corresponding Landlock feature is available
// at the detected ABI version.
type landlockABI struct {
	Version     int  // 1-6, 0 if unsupported
	HasRefer    bool // V2+: rename across directories (atomic writes)
	HasTruncate bool // V3+: file truncation
	HasNetwork  bool // V4+: TCP port filtering
	HasIoctlDev bool // V5+: device ioctl (PTY terminal ops)
	HasScoping  bool // V6+: signal isolation
}

// newLandlockABI constructs a landlockABI with feature flags derived from the version number.
// Version <= 0 means all flags are false (unsupported). Versions > 6 have all flags set
// to true since we assume forward compatibility for known features.
func newLandlockABI(version int) *landlockABI {
	return &landlockABI{
		Version:     version,
		HasRefer:    version >= 2,
		HasTruncate: version >= 3,
		HasNetwork:  version >= 4,
		HasIoctlDev: version >= 5,
		HasScoping:  version >= 6,
	}
}

// detectABI probes the running kernel for Landlock support and returns the detected
// ABI version with feature flags. Returns an error if Landlock is not supported
// by the kernel. The version is capped at 6 for feature flag purposes since we
// do not know about features beyond V6, though the raw version is preserved.
func landlockDetectABI() (*landlockABI, error) {
	version, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return nil, fmt.Errorf("landlock not supported: %w", err)
	}

	if version <= 0 {
		return nil, fmt.Errorf("landlock not supported: ABI version %d", version)
	}

	return newLandlockABI(version), nil
}
