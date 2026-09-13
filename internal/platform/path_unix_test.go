//go:build unix

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSystemProfileQuotesTheDirectory(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want string
	}{
		{
			name: "plain path",
			dir:  "/opt/safedep/pmg/bin",
			want: "export PATH='/opt/safedep/pmg/bin':\"$PATH\"\n",
		},
		{
			name: "path with a dollar sign stays literal",
			dir:  "/opt/$HOME/bin",
			want: "export PATH='/opt/$HOME/bin':\"$PATH\"\n",
		},
		{
			name: "single quote in the path is escaped",
			dir:  "/opt/a'b/bin",
			want: "export PATH='/opt/a'\"'\"'b/bin':\"$PATH\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pmg.sh")
			require.NoError(t, WriteSystemProfile(path, tt.dir))

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Contains(t, string(data), tt.want)
		})
	}
}
