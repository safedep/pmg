package cargo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsExactVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"1.0.219", true},
		{"0.1.0-alpha.1", true},
		{"1.2.3+build.5", true},
		{"1.0.0-rc-1", true},
		{"1.0", false},
		{"1-2.0.0", false},
		{"^1.0.3", false},
		{"~1.2", false},
		{">=1.0, <2.0", false},
		{"*", false},
		{"latest", false},
		{"", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, IsExactVersion(tc.version), "version %q", tc.version)
	}
}

func TestIsCrateName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"serde", true},
		{"serde_json", true},
		{"foo-bar", true},
		{"Inflector", true},
		{"x-1", true},
		{"_private", true},
		{"", false},
		{"-foo", false},
		{"foo.bar", false},
		{"../foo", false},
		{"https://github.com/x/y", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, IsCrateName(tc.name), "name %q", tc.name)
	}
}
