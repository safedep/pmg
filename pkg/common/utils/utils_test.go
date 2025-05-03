package utils

import (
	"strings"
	"testing"
)

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "caret version",
			version:  "^1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "tilde version",
			version:  "~1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "exact version",
			version:  "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "asterisk version",
			version:  "*",
			expected: "latest",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "",
		},
		{
			name:     "both caret and tilde",
			version:  "^~1.2.3",
			expected: "1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CleanVersion(tt.version)
			if result != tt.expected {
				t.Errorf("CleanVersion(%q) = %q, want %q", tt.version, result, tt.expected)
			}
		})
	}
}

func TestParsePackageInfo(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantPackage   string
		wantVersion   string
		wantErr       bool
		errorContains string
	}{
		{
			name:        "simple package",
			input:       "express",
			wantPackage: "express",
			wantVersion: "",
			wantErr:     false,
		},
		{
			name:        "package with version",
			input:       "express@4.17.1",
			wantPackage: "express",
			wantVersion: "4.17.1",
			wantErr:     false,
		},
		{
			name:        "scoped package",
			input:       "@angular/core",
			wantPackage: "@angular/core",
			wantVersion: "",
			wantErr:     false,
		},
		{
			name:        "scoped package with version",
			input:       "@angular/core@12.0.0",
			wantPackage: "@angular/core",
			wantVersion: "12.0.0",
			wantErr:     false,
		},
		{
			name:        "package with caret version",
			input:       "react@^17.0.2",
			wantPackage: "react",
			wantVersion: "^17.0.2",
			wantErr:     false,
		},
		{
			name:        "package with tilde version",
			input:       "lodash@~4.17.21",
			wantPackage: "lodash",
			wantVersion: "~4.17.21",
			wantErr:     false,
		},
		{
			name:          "empty input",
			input:         "",
			wantPackage:   "",
			wantVersion:   "",
			wantErr:       true,
			errorContains: "package info cannot be empty",
		},
		{
			name:          "invalid format with multiple @",
			input:         "pkg@1.0.0@2.0.0",
			wantPackage:   "",
			wantVersion:   "",
			wantErr:       true,
			errorContains: "invalid format",
		},
		{
			name:        "package with spaces",
			input:       "  express@4.17.1  ",
			wantPackage: "express",
			wantVersion: "4.17.1",
			wantErr:     false,
		},
		{
			name:        "scoped package with spaces",
			input:       "  @types/node@14.14.31  ",
			wantPackage: "@types/node",
			wantVersion: "14.14.31",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packageName, version, err := ParsePackageInfo(tt.input)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePackageInfo(%q) expected error, got nil", tt.input)
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("ParsePackageInfo(%q) error = %v, want error containing %q", tt.input, err, tt.errorContains)
				}
				return
			}
			if err != nil {
				t.Errorf("ParsePackageInfo(%q) unexpected error: %v", tt.input, err)
				return
			}

			// Check package name
			if packageName != tt.wantPackage {
				t.Errorf("ParsePackageInfo(%q) package = %q, want %q", tt.input, packageName, tt.wantPackage)
			}

			// Check version
			if version != tt.wantVersion {
				t.Errorf("ParsePackageInfo(%q) version = %q, want %q", tt.input, version, tt.wantVersion)
			}
		})
	}
}
