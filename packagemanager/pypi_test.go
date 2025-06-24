package packagemanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPipParsePackageInfo(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		pkgName string
		version string
		extras  []string
		wantErr bool
	}{
		{
			name:    "simple package name",
			input:   "fastapi",
			pkgName: "fastapi",
			version: "",
			extras:  nil,
			wantErr: false,
		},
		{
			name:    "package with exact version & extra",
			input:   "fastapi[all]==0.115.7",
			pkgName: "fastapi",
			version: "==0.115.7",
			extras:  []string{"all"},
			wantErr: false,
		},
		{
			name:    "package with version range",
			input:   "requests>=2.0,<3.0",
			pkgName: "requests",
			version: ">=2.0,<3.0",
			extras:  nil,
			wantErr: false,
		},
		{
			name:    "package with exclusion",
			input:   "pydantic!=1.8,!=1.8.1",
			pkgName: "pydantic",
			version: "!=1.8,!=1.8.1",
			wantErr: false,
		},
		{
			name:    "package with compatible release",
			input:   "django~=3.1.0",
			pkgName: "django",
			version: "~=3.1.0",
			extras:  nil,
			wantErr: false,
		},
		{
			name:    "package with greater than with empty extra",
			input:   "numpy[]>1.20.0",
			pkgName: "numpy",
			version: ">1.20.0",
			extras:  nil,
			wantErr: false,
		},
		{
			name:    "package with less than",
			input:   "pandas<2.0.0",
			pkgName: "pandas",
			version: "<2.0.0",
			extras:  nil,
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			pkgName: "",
			version: "",
			extras:  nil,
			wantErr: true,
		},
		{
			name:    "only version specifier",
			input:   "==1.0.0",
			pkgName: "",
			version: "",
			extras:  nil,
			wantErr: true,
		},
		{
			name:    "package with whitespace",
			input:   "  requests  ==  2.0.0  ",
			pkgName: "requests",
			version: "==  2.0.0",
			extras:  nil,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgName, version, extras, err := pipParsePackageInfo(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.pkgName, pkgName)
				assert.Equal(t, tc.version, version)
				assert.Equal(t, tc.extras, extras)
			}
		})
	}
}

func TestPipParseCommand(t *testing.T) {
	pm, err := NewPipPackageManager(DefaultPipPackageManagerConfig())
	assert.NoError(t, err)

	cases := []struct {
		name             string
		args             []string
		expectedManifest bool
		expectedFiles    []string
		expectedTargets  int
	}{
		{
			name:             "pip install with -r flag",
			args:             []string{"install", "-r", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip install with -r flag with different filename",
			args:             []string{"install", "-r", "requirements-dev.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements-dev.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip install with --requirement flag",
			args:             []string{"install", "--requirement", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip install with combined -r flag",
			args:             []string{"install", "-rrequirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip install without args",
			args:             []string{"install"},
			expectedManifest: false,
			expectedFiles:    nil,
			expectedTargets:  0,
		},
		{
			name:             "pip install with explicit package",
			args:             []string{"install", "django"},
			expectedManifest: false,
			expectedFiles:    nil,
			expectedTargets:  1,
		},
		{
			name:             "pip install with mixed args",
			args:             []string{"install", "django", "-r", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  1,
		},
		{
			name:             "pip install with multiple -r flags",
			args:             []string{"install", "-r", "requirements.txt", "-r", "dev-requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt", "dev-requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "non-install command",
			args:             []string{"list"},
			expectedManifest: false,
			expectedFiles:    nil,
			expectedTargets:  0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := pm.ParseCommand(tc.args)
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedManifest, parsed.IsManifestInstall, "IsManifestInstall mismatch")
			assert.Equal(t, tc.expectedFiles, parsed.ManifestFiles, "ManifestFiles mismatch")
			assert.Equal(t, tc.expectedTargets, len(parsed.InstallTargets), "InstallTargets count mismatch")

			// Test helper methods
			assert.Equal(t, tc.expectedManifest, parsed.HasManifestInstall(), "HasManifestInstall mismatch")

			expectedShouldExtract := tc.expectedManifest && tc.expectedTargets == 0
			assert.Equal(t, expectedShouldExtract, parsed.ShouldExtractFromManifest(), "ShouldExtractFromManifest mismatch")
		})
	}
}

func TestPipConvertCompatibleRelease(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard version",
			input:    "~=3.1.0",
			expected: ">=3.1.0,<3.2.0",
		},
		{
			name:     "single digit minor",
			input:    "~=2.1.5",
			expected: ">=2.1.5,<2.2.0",
		},
		{
			name:     "double digit minor",
			input:    "~=1.10.0",
			expected: ">=1.10.0,<1.11.0",
		},
		{
			name:     "invalid format",
			input:    "~=1",
			expected: "",
		},
		{
			name:     "missing prefix",
			input:    "3.1.0",
			expected: "3.1.0",
		},
		{
			name:     "extra segments",
			input:    "~=2.1.5.2",
			expected: ">=2.1.5.2,<2.1.6",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := pipConvertCompatibleRelease(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
