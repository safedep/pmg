package config

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func TestIsTrustedPackageVersion(t *testing.T) {
	tests := []struct {
		name            string
		trustedPackages []TrustedPackage
		pkgVersion      *packagev1.PackageVersion
		want            bool
	}{
		{
			name:            "nil package version returns false",
			trustedPackages: []TrustedPackage{},
			pkgVersion:      nil,
			want:            false,
		},
		{
			name:            "empty trusted packages list returns false",
			trustedPackages: []TrustedPackage{},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "exact match with version returns true",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "trusted by team",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "match without version in trusted package returns true",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/express",
					Reason: "all versions trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "version mismatch returns false",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/express@4.17.0",
					Reason: "old version trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "name mismatch returns false",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/react@18.0.0",
					Reason: "trusted package",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "ecosystem mismatch returns false",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:pypi/requests@2.28.0",
					Reason: "trusted package",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "requests",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "2.28.0",
			},
			want: false,
		},
		{
			name: "pypi package exact match returns true",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:pypi/requests@2.28.0",
					Reason: "trusted http library",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "requests",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
				},
				Version: "2.28.0",
			},
			want: true,
		},
		{
			name: "multiple trusted packages finds correct match",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/lodash@4.17.21",
					Reason: "utility library",
				},
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "web framework",
				},
				{
					Purl:   "pkg:pypi/requests@2.28.0",
					Reason: "http library",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "multiple trusted packages no match returns false",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/lodash@4.17.21",
					Reason: "utility library",
				},
				{
					Purl:   "pkg:npm/react@18.0.0",
					Reason: "ui library",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "invalid purl in trusted packages skips and returns false",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "invalid-purl-format",
					Reason: "malformed",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "invalid purl skipped but valid match found",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "invalid-purl-format",
					Reason: "malformed",
				},
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "valid trusted package",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "package version without version field matches versionless trusted package",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/express",
					Reason: "all versions trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "",
			},
			want: true,
		},
		{
			name: "package version without version field does not match versioned trusted package",
			trustedPackages: []TrustedPackage{
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "specific version trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pre-process trusted packages to populate pre-parsed fields
			cfg := &Config{TrustedPackages: tt.trustedPackages}
			_ = preprocessTrustedPackages(cfg)

			got := isTrustedPackageVersion(cfg.TrustedPackages, tt.pkgVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}
