package alias

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectShell(t *testing.T) {
	cases := []struct {
		name          string
		shellEnvValue string
		want          string
		wantErr       error
	}{
		{
			name:          "bash full path",
			shellEnvValue: "/bin/bash",
			want:          "bash",
			wantErr:       nil,
		},
		{
			name:          "zsh full path",
			shellEnvValue: "/bin/zsh",
			want:          "zsh",
			wantErr:       nil,
		},
		{
			name:          "bash only name",
			shellEnvValue: "bash",
			want:          "bash",
			wantErr:       nil,
		},
		{
			name:          "when shell env is not set",
			shellEnvValue: "",
			want:          "",
			wantErr:       fmt.Errorf("SHELL environment variable not set"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SHELL", tc.shellEnvValue)
			got, err := DetectShell()

			if tc.wantErr != nil {
				assert.ErrorContains(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
