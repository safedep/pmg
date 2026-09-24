package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPythonCommand(t *testing.T) {
	cases := []struct {
		name     string
		python   PythonCommand
		wantArgs []string
		wantText string
	}{
		{"no fixed args", PythonCommand{Name: "python3"}, []string{"python3", "-m", "venv", "dir"}, "python3"},
		{"fixed args first", PythonCommand{Name: "py", Args: []string{"-3"}}, []string{"py", "-3", "-m", "venv", "dir"}, "py -3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixed := append([]string(nil), tc.python.Args...)
			assert.Equal(t, tc.wantArgs, tc.python.Command("-m", "venv", "dir").Args)
			assert.Equal(t, tc.wantText, tc.python.String())
			assert.Equal(t, fixed, tc.python.Args)
		})
	}
}

func TestPythonCommandsIsNotEmpty(t *testing.T) {
	assert.NotEmpty(t, PythonCommands())
}
