package config

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setBlockedPackagesForTest(t *testing.T, pkgs []BlockedPackage) {
	t.Helper()
	orig := Get().Config.Block.Packages
	Get().Config.Block.Packages = pkgs
	require.NoError(t, PreprocessPackageRefs(&Get().Config))
	t.Cleanup(func() {
		Get().Config.Block.Packages = orig
		assert.NoError(t, PreprocessPackageRefs(&Get().Config))
	})
}

func TestFindBlockedPackageRef(t *testing.T) {
	cases := []struct {
		name        string
		blocked     []BlockedPackage
		ecosystem   packagev1.Ecosystem
		pkg         string
		version     string
		wantBlocked bool
		wantReason  string
	}{
		{
			name:        "version-less entry blocks any version",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "left-pad",
			version:     "1.3.0",
			wantBlocked: true,
			wantReason:  "deprecated",
		},
		{
			name:        "version-pinned entry blocks that version",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/lodash@4.17.20", Reason: "CVE"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "lodash",
			version:     "4.17.20",
			wantBlocked: true,
			wantReason:  "CVE",
		},
		{
			name:        "version-pinned entry does not block other versions",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/lodash@4.17.20", Reason: "CVE"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "lodash",
			version:     "4.17.21",
			wantBlocked: false,
		},
		{
			name:        "different ecosystem does not match",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_PYPI,
			pkg:         "left-pad",
			version:     "1.3.0",
			wantBlocked: false,
		},
		{
			name:        "invalid purl never matches",
			blocked:     []BlockedPackage{{Purl: "not-a-purl", Reason: "x"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "not-a-purl",
			version:     "1.0.0",
			wantBlocked: false,
		},
		{
			name:        "empty blocklist matches nothing",
			blocked:     nil,
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "anything",
			version:     "1.0.0",
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBlockedPackagesForTest(t, tc.blocked)

			got, ok := FindBlockedPackageRef(tc.ecosystem, tc.pkg, tc.version)
			assert.Equal(t, tc.wantBlocked, ok)
			if tc.wantBlocked {
				assert.Equal(t, tc.wantReason, got.Reason)
			}
		})
	}
}
