package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPypiFilenameVersionNormalization(t *testing.T) {
	for _, version := range []struct {
		raw  string
		want string
	}{
		{raw: "0!1.0", want: "1.0"},
		{raw: "1.0RC1", want: "1.0rc1"},
		{raw: "1.0.0", want: "1.0.0"},
	} {
		for _, suffix := range []string{".tar.gz", "-1local-py3-none-any.whl", "-py3-none-any.whl.metadata"} {
			filename := "demo-" + version.raw + suffix
			t.Run(filename, func(t *testing.T) {
				info, err := parseFilename(filename)
				require.NoError(t, err)
				assert.Equal(t, "demo", info.GetName())
				assert.Equal(t, version.want, info.GetVersion())
			})
		}
	}
}
