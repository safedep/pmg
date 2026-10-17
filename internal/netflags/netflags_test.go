package netflags

import (
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parse(t *testing.T, configMode string, args ...string) (*pflag.FlagSet, string, []string, []string) {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	mode := configMode
	var allow, deny []string
	AddModeFlag(fs, &mode, "sandbox.network_mode")
	AddRuleFlags(fs, &allow, &deny)
	require.NoError(t, fs.Parse(args))
	return fs, mode, allow, deny
}

func TestWidening(t *testing.T) {
	cases := []struct {
		name       string
		configMode string
		args       []string
		want       []string
	}{
		{"nothing set", "enforce", nil, nil},
		{"a deny rule narrows", "enforce", []string{"--network-deny", "evil.example:443"}, nil},
		{"enforce over audit narrows", "audit", []string{"--network-mode", "enforce"}, nil},
		{"enforce over enforce stands", "enforce", []string{"--network-mode", "enforce"}, nil},
		{"audit over empty is the default", "", []string{"--network-mode", "audit"}, nil},
		{"an allow rule widens", "enforce", []string{"--network-allow", "pastebin.com:443"}, []string{"--network-allow"}},
		{"audit over enforce widens", "enforce", []string{"--network-mode", "audit"}, []string{"--network-mode=audit"}},
		{"an empty mode over enforce widens", "enforce", []string{"--network-mode="}, []string{"--network-mode="}},
		{"both", "enforce", []string{"--network-allow", "a:1", "--network-mode", "audit"}, []string{"--network-allow", "--network-mode=audit"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, mode, _, _ := parse(t, tc.configMode, tc.args...)
			assert.Equal(t, tc.want, Widening(fs, mode))
		})
	}
}

func TestArgsRepeatsOnlyWhatChanged(t *testing.T) {
	fs, mode, allow, deny := parse(t, "audit")
	assert.Empty(t, Args(fs, mode, allow, deny))

	fs, mode, allow, deny = parse(t, "audit", "--network-mode", "enforce", "--network-allow", "a:1", "--network-allow", "b:2", "--network-deny", "*:*")
	assert.Equal(t, []string{"--network-mode", "enforce", "--network-allow", "a:1", "--network-allow", "b:2", "--network-deny", "*:*"}, Args(fs, mode, allow, deny))
}

func TestCheckRule(t *testing.T) {
	require.NoError(t, CheckRule(Allow, "registry.npmjs.org:443"))
	require.NoError(t, CheckRule(Deny, "*:*"))

	err := CheckRule(Allow, "registry.npmjs.org")
	var usefulErr usefulerror.UsefulError
	require.ErrorAs(t, err, &usefulErr)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
	assert.Contains(t, err.Error(), `--network-allow "registry.npmjs.org"`)
}
