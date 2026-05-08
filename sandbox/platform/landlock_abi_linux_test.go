//go:build linux
// +build linux

package platform

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLandlockABI_FeatureFlags(t *testing.T) {
	tests := []struct {
		version     int
		hasRefer    bool
		hasTruncate bool
		hasNetwork  bool
		hasIoctlDev bool
		hasScoping  bool
	}{
		{version: 0, hasRefer: false, hasTruncate: false, hasNetwork: false, hasIoctlDev: false, hasScoping: false},
		{version: 1, hasRefer: false, hasTruncate: false, hasNetwork: false, hasIoctlDev: false, hasScoping: false},
		{version: 2, hasRefer: true, hasTruncate: false, hasNetwork: false, hasIoctlDev: false, hasScoping: false},
		{version: 3, hasRefer: true, hasTruncate: true, hasNetwork: false, hasIoctlDev: false, hasScoping: false},
		{version: 4, hasRefer: true, hasTruncate: true, hasNetwork: true, hasIoctlDev: false, hasScoping: false},
		{version: 5, hasRefer: true, hasTruncate: true, hasNetwork: true, hasIoctlDev: true, hasScoping: false},
		{version: 6, hasRefer: true, hasTruncate: true, hasNetwork: true, hasIoctlDev: true, hasScoping: true},
	}

	for _, tt := range tests {
		t.Run(
			func() string {
				return "version_" + string(rune('0'+tt.version))
			}(),
			func(t *testing.T) {
				abi := newLandlockABI(tt.version)
				assert.Equal(t, tt.version, abi.Version, "Version mismatch")
				assert.Equal(t, tt.hasRefer, abi.HasRefer, "HasRefer mismatch for V%d", tt.version)
				assert.Equal(t, tt.hasTruncate, abi.HasTruncate, "HasTruncate mismatch for V%d", tt.version)
				assert.Equal(t, tt.hasNetwork, abi.HasNetwork, "HasNetwork mismatch for V%d", tt.version)
				assert.Equal(t, tt.hasIoctlDev, abi.HasIoctlDev, "HasIoctlDev mismatch for V%d", tt.version)
				assert.Equal(t, tt.hasScoping, abi.HasScoping, "HasScoping mismatch for V%d", tt.version)
			},
		)
	}
}

func TestNewLandlockABI_HighVersion(t *testing.T) {
	for _, version := range []int{7, 8, 10, 100} {
		abi := newLandlockABI(version)
		// High versions should be capped at 6 but all flags should be true
		assert.Equal(t, version, abi.Version, "Version should be preserved as-is")
		assert.True(t, abi.HasRefer, "HasRefer should be true for V%d", version)
		assert.True(t, abi.HasTruncate, "HasTruncate should be true for V%d", version)
		assert.True(t, abi.HasNetwork, "HasNetwork should be true for V%d", version)
		assert.True(t, abi.HasIoctlDev, "HasIoctlDev should be true for V%d", version)
		assert.True(t, abi.HasScoping, "HasScoping should be true for V%d", version)
	}
}

func TestNewLandlockABI_NegativeVersion(t *testing.T) {
	abi := newLandlockABI(-1)
	assert.Equal(t, -1, abi.Version)
	assert.False(t, abi.HasRefer)
	assert.False(t, abi.HasTruncate)
	assert.False(t, abi.HasNetwork)
	assert.False(t, abi.HasIoctlDev)
	assert.False(t, abi.HasScoping)
}

func TestDetectABI_Integration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Landlock is only available on Linux")
	}

	abi, err := landlockDetectABI()
	if err != nil {
		// Landlock may not be available on this kernel (requires Linux 5.13+)
		t.Skipf("Landlock not available on this system: %v", err)
	}

	assert.NotNil(t, abi)
	assert.Greater(t, abi.Version, 0, "Landlock ABI version should be > 0 when supported")

	// If we got here, basic feature flags should be consistent
	if abi.Version >= 2 {
		assert.True(t, abi.HasRefer)
	}
	if abi.Version >= 3 {
		assert.True(t, abi.HasTruncate)
	}
	if abi.Version >= 4 {
		assert.True(t, abi.HasNetwork)
	}
	if abi.Version >= 5 {
		assert.True(t, abi.HasIoctlDev)
	}
	if abi.Version >= 6 {
		assert.True(t, abi.HasScoping)
	}
}
