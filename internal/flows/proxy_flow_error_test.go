package flows

import (
	"context"
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/internal/runerror"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingParsePackageManager struct {
	err error
}

func (f failingParsePackageManager) Name() string { return "npm" }
func (f failingParsePackageManager) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}
func (f failingParsePackageManager) ParseCommand([]string) (*packagemanager.ParsedCommand, error) {
	return nil, f.err
}

func TestRunProxyClassifiesParseFailure(t *testing.T) {
	cause := errors.New("private parse detail")
	err := RunProxy(context.Background(), failingParsePackageManager{err: cause}, []string{"install"})

	require.ErrorIs(t, err, cause)
	info := runerror.From(err)
	require.NotNil(t, info)
	assert.Equal(t, runerror.ReasonCommandParseFailed, info.Reason)
	assert.Equal(t, "failed to parse command: private parse detail", info.Message)
}
