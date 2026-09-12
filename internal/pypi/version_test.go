package pypi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePypiVersion(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
	}{
		{input: "0!1.0", want: "1.0"},
		{input: "000!1.0", want: "1.0"},
		{input: "1.0", want: "1.0"},
		{input: "1.0.0", want: "1.0.0"},
		{input: "01!002.00", want: "1!2.0"},
		{input: "1.0RC1", want: "1.0rc1"},
		{input: "1.0alpha", want: "1.0a0"},
		{input: "1.0_beta_02", want: "1.0b2"},
		{input: "1.0c1", want: "1.0rc1"},
		{input: "1.0preview1", want: "1.0rc1"},
		{input: "1.0pre1", want: "1.0rc1"},
		{input: "1.0-01", want: "1.0.post1"},
		{input: "1.0R02", want: "1.0.post2"},
		{input: "1.0rev", want: "1.0.post0"},
		{input: "1.0.post", want: "1.0.post0"},
		{input: "1.0DEV", want: "1.0.dev0"},
		{input: "V01.0RC01.POST02.DEV03+LOCAL_004-ABC", want: "1.0rc1.post2.dev3+local.4.abc"},
		{input: " 1.0\n", want: "1.0"},
		{input: "999999999999999999999999999!1.0", want: "999999999999999999999999999!1.0"},
		{input: "1.0_1"},
		{input: "1.0final"},
		{input: "1.0rc1rc2"},
		{input: "1.0.dev1.post1"},
		{input: "1!2!1.0"},
		{input: "1.0+local..1"},
		{input: "1.0+"},
		{input: ""},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, valid := NormalizeVersion(tt.input)
			assert.Equal(t, tt.want != "", valid)
			assert.Equal(t, tt.want, got)
			if valid {
				again, ok := NormalizeVersion(got)
				require.True(t, ok)
				assert.Equal(t, got, again)
			}
		})
	}
}
