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
			pkgName, version, extras, err := pypiParsePackageInfo(tc.input)
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
	pm, err := NewPypiPackageManager(DefaultPipPackageManagerConfig())
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

func TestPip3ParseCommand(t *testing.T) {
	pm, err := NewPypiPackageManager(DefaultPip3PackageManagerConfig())
	assert.NoError(t, err)

	cases := []struct {
		name             string
		args             []string
		expectedManifest bool
		expectedFiles    []string
		expectedTargets  int
	}{
		{
			name:             "pip3 install with -r flag",
			args:             []string{"install", "-r", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip3 install with -r flag with different filename",
			args:             []string{"install", "-r", "requirements-dev.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements-dev.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip3 install with --requirement flag",
			args:             []string{"install", "--requirement", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip3 install with combined -r flag",
			args:             []string{"install", "-rrequirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
		},
		{
			name:             "pip3 install without args",
			args:             []string{"install"},
			expectedManifest: false,
			expectedFiles:    nil,
			expectedTargets:  0,
		},
		{
			name:             "pip3 install with explicit package",
			args:             []string{"install", "django"},
			expectedManifest: false,
			expectedFiles:    nil,
			expectedTargets:  1,
		},
		{
			name:             "pip3 install with mixed args",
			args:             []string{"install", "django", "-r", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  1,
		},
		{
			name:             "pip3 install with multiple -r flags",
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
			result := pypiConvertCompatibleRelease(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPypiConvertPoetryVersionConstraints(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		// Basic functionality tests
		{
			name:     "empty string",
			input:    "",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "package name only",
			input:    "pendulum",
			expected: "pendulum",
			wantErr:  false,
		},
		{
			name:     "inequality constraints",
			input:    "pendulum>=2.0.0",
			expected: "pendulum>=2.0.0",
			wantErr:  false,
		},
		{
			name:     "empty package name",
			input:    "@^1.0.0",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "whitespace handling",
			input:    "  pendulum@^2.0.5  ",
			expected: "pendulum>=2.0.5,<3.0.0",
			wantErr:  false,
		},

		// Caret constraint tests
		{
			name:     "caret basic major version",
			input:    "pendulum@^2.0.5",
			expected: "pendulum>=2.0.5,<3.0.0",
			wantErr:  false,
		},
		{
			name:     "caret with major version 0",
			input:    "requests@^0.2.3",
			expected: "requests>=0.2.3,<0.3.0",
			wantErr:  false,
		},
		{
			name:     "caret with major and minor version 0",
			input:    "numpy@^0.0.5",
			expected: "numpy>=0.0.5,<0.0.6",
			wantErr:  false,
		},
		{
			name:     "caret with two parts",
			input:    "flask@^1.1",
			expected: "flask>=1.1.0,<2.0.0",
			wantErr:  false,
		},
		{
			name:     "caret with one part",
			input:    "pytest@^7",
			expected: "pytest>=7.0.0,<8.0.0",
			wantErr:  false,
		},
		{
			name:     "caret with zero major & two parts",
			input:    "package@^0.5",
			expected: "package>=0.5.0,<0.6.0",
			wantErr:  false,
		},
		{
			name:     "caret invalid version",
			input:    "invalid@^abc.def",
			expected: "",
			wantErr:  true,
		},

		// Tilde constraint tests
		{
			name:     "tilde basic three parts",
			input:    "pendulum@~2.0.5",
			expected: "pendulum>=2.0.5,<2.1.0",
			wantErr:  false,
		},
		{
			name:     "tilde with two parts",
			input:    "requests@~1.2",
			expected: "requests>=1.2.0,<1.3.0",
			wantErr:  false,
		},
		{
			name:     "tilde with one part",
			input:    "numpy@~2",
			expected: "numpy>=2.0.0,<3.0.0",
			wantErr:  false,
		},
		{
			name:     "tilde with zero major",
			input:    "package@~0.5.2",
			expected: "package>=0.5.2,<0.6.0",
			wantErr:  false,
		},
		{
			name:     "tilde invalid version",
			input:    "invalid@~abc.def",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "tilde without @ separator",
			input:    "requests~1.2.0",
			expected: "requests>=1.2.0,<1.3.0",
			wantErr:  false,
		},

		// With extras
		{
			name:     "caret with extras using @ format",
			input:    "fastapi[all]@^0.68.0",
			expected: "fastapi[all]>=0.68.0,<0.69.0",
			wantErr:  false,
		},
		{
			name:     "caret with extras without @ separator",
			input:    "django[mysql,redis]^3.0",
			expected: "django[mysql,redis]>=3.0.0,<4.0.0",
			wantErr:  false,
		},
		{
			name:     "tilde with multiple extras",
			input:    "uvicorn[standard,dev]~0.15.0",
			expected: "uvicorn[standard,dev]>=0.15.0,<0.16.0",
			wantErr:  false,
		},
		{
			name:     "empty extras with caret",
			input:    "numpy[]^1.20.0",
			expected: "numpy[]>=1.20.0,<2.0.0",
			wantErr:  false,
		},

		// Standard constraint pass-through tests (no Poetry operators)
		{
			name:     "standard python format",
			input:    "pendulum>=2.0.0",
			expected: "pendulum>=2.0.0",
			wantErr:  false,
		},
		{
			name:     "standard exact version",
			input:    "django==3.2.0",
			expected: "django==3.2.0",
			wantErr:  false,
		},
		{
			name:     "standard with extras",
			input:    "fastapi[all]>=0.68.0",
			expected: "fastapi[all]>=0.68.0",
			wantErr:  false,
		},
		{
			name:     "complex version range",
			input:    "requests>=2.0,<3.0",
			expected: "requests>=2.0,<3.0",
			wantErr:  false,
		},

		// Wildcard constraint tests
		{
			name:     "wildcard all versions",
			input:    "requests@*",
			expected: "requests>=0.0.0",
			wantErr:  false,
		},
		{
			name:     "wildcard major version",
			input:    "django@1.*",
			expected: "django>=1.0.0,<2.0.0",
			wantErr:  false,
		},
		{
			name:     "wildcard minor version",
			input:    "flask@1.2.*",
			expected: "flask>=1.2.0,<1.3.0",
			wantErr:  false,
		},
		{
			name:     "wildcard without @ separator",
			input:    "numpy@2.*",
			expected: "numpy>=2.0.0,<3.0.0",
			wantErr:  false,
		},
		{
			name:     "wildcard with extras",
			input:    "fastapi[all]@1.*",
			expected: "fastapi[all]>=1.0.0,<2.0.0",
			wantErr:  false,
		},
		{
			name:     "wildcard with extras without @ separator",
			input:    "uvicorn[standard]@0.*",
			expected: "uvicorn[standard]>=0.0.0,<1.0.0",
			wantErr:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pypiConvertPoetryVersionConstraints(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestPypiConvertCaretConstraint(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard major version",
			input:    "1.2.3",
			expected: ">=1.2.3,<2.0.0",
		},
		{
			name:     "major version zero",
			input:    "0.2.3",
			expected: ">=0.2.3,<0.3.0",
		},
		{
			name:     "major and minor version zero",
			input:    "0.0.3",
			expected: ">=0.0.3,<0.0.4",
		},
		{
			name:     "two parts",
			input:    "1.2",
			expected: ">=1.2.0,<2.0.0",
		},
		{
			name:     "one part",
			input:    "7",
			expected: ">=7.0.0,<8.0.0",
		},
		{
			name:     "zero major two parts",
			input:    "0.5",
			expected: ">=0.5.0,<0.6.0",
		},
		{
			name:     "double digit versions",
			input:    "10.15.22",
			expected: ">=10.15.22,<11.0.0",
		},
		{
			name:     "invalid version",
			input:    "abc.def",
			expected: "",
		},
		{
			name:     "empty version",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := pypiConvertCaretConstraint(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPypiConvertTildeConstraint(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "three parts",
			input:    "1.2.3",
			expected: ">=1.2.3,<1.3.0",
		},
		{
			name:     "two parts",
			input:    "1.2",
			expected: ">=1.2.0,<1.3.0",
		},
		{
			name:     "one part",
			input:    "2",
			expected: ">=2.0.0,<3.0.0",
		},
		{
			name:     "zero major version",
			input:    "0.5.2",
			expected: ">=0.5.2,<0.6.0",
		},
		{
			name:     "double digit versions",
			input:    "10.15.22",
			expected: ">=10.15.22,<10.16.0",
		},
		{
			name:     "large version numbers",
			input:    "99.99.99",
			expected: ">=99.99.99,<99.100.0",
		},
		{
			name:     "invalid version",
			input:    "abc.def",
			expected: "",
		},
		{
			name:     "empty version",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := pypiConvertTildeConstraint(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUvParseCommand(t *testing.T) {
	pm, err := NewPypiPackageManager(DefaultUvPackageManagerConfig())
	assert.NoError(t, err)

	cases := []struct {
		name             string
		args             []string
		expectedManifest bool
		expectedFiles    []string
		expectedTargets  int
		expectedPackages []string
		wantErr          bool
	}{
		{
			name:             "uv add simple package",
			args:             []string{"add", "flask"},
			expectedManifest: false,
			expectedFiles:    []string{""},
			expectedTargets:  1,
			expectedPackages: []string{"flask"},
			wantErr:          false,
		},
		{
			name:             "uv add multiple packages",
			args:             []string{"add", "flask", "requests"},
			expectedManifest: false,
			expectedFiles:    []string{""},
			expectedTargets:  2,
			expectedPackages: []string{
				"flask",
				"requests",
			},
			wantErr: false,
		},
		{
			name:             "uv pip install simple package",
			args:             []string{"pip", "install", "fastapi"},
			expectedManifest: false,
			expectedFiles:    []string{""},
			expectedTargets:  2,
			expectedPackages: []string{"fastapi"},
			wantErr:          false,
		},
		{
			name:             "uv pip install multiple packages",
			args:             []string{"pip", "install", "flask", "requests"},
			expectedManifest: false,
			expectedFiles:    []string{""},
			expectedTargets:  2,
			expectedPackages: []string{
				"flask",
				"requests",
			},
			wantErr: false,
		},
		{
			name:             "uv pip install from manifest file",
			args:             []string{"pip", "install", "-r", "requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt"},
			expectedTargets:  0,
			expectedPackages: []string{},
			wantErr:          false,
		},
		{
			name:             "uv pip install from multiple manifest files",
			args:             []string{"pip", "install", "-r", "requirements.txt", "-r", "dev-requirements.txt"},
			expectedManifest: true,
			expectedFiles:    []string{"requirements.txt", "dev-requirements.txt"},
			expectedTargets:  0,
			expectedPackages: []string{},
			wantErr:          false,
		},
		{
			name:             "uv sync",
			args:             []string{"sync"},
			expectedManifest: true,
			expectedFiles:    []string{"uv.lock"},
			expectedTargets:  0,
			expectedPackages: []string{},
			wantErr:          false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pm.ParseCommand(tc.args)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedManifest, result.HasManifestInstall(), "HasManifestInstall mismatch")

			expectedShouldExtract := tc.expectedManifest && tc.expectedTargets == 0
			assert.Equal(t, expectedShouldExtract, result.ShouldExtractFromManifest(), "ShouldExtractFromManifest mismatch")

			assert.Equal(t, len(tc.expectedPackages), len(result.InstallTargets), "Number of install targets mismatch")

			for i, expectedPkg := range tc.expectedPackages {
				if i < len(result.InstallTargets) {
					target := result.InstallTargets[i]
					assert.Equal(t, expectedPkg, target.PackageVersion.Package.Name, "Package name mismatch for package %d", i)
				}
			}
		})
	}
}

func TestPypiConvertWildcardConstraint(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "all versions wildcard",
			input:    "*",
			expected: ">=0.0.0",
		},
		{
			name:     "major version wildcard",
			input:    "1.*",
			expected: ">=1.0.0,<2.0.0",
		},
		{
			name:     "minor version wildcard",
			input:    "2.5.*",
			expected: ">=2.5.0,<2.6.0",
		},
		{
			name:     "zero major version wildcard",
			input:    "0.*",
			expected: ">=0.0.0,<1.0.0",
		},
		{
			name:     "zero minor version wildcard",
			input:    "1.0.*",
			expected: ">=1.0.0,<1.1.0",
		},
		{
			name:     "high version numbers",
			input:    "12.34.*",
			expected: ">=12.34.0,<12.35.0",
		},
		{
			name:     "invalid wildcard format",
			input:    "1.2.3.*",
			expected: "",
		},
		{
			name:     "invalid non-numeric parts",
			input:    "abc.*",
			expected: "",
		},
		{
			name:     "wildcard without dot",
			input:    "1*",
			expected: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := pypiConvertWildcardConstraint(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
