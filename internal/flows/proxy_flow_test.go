package flows

import (
	"strings"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupEnvForProxy_SetsGoProxy(t *testing.T) {
	flow := &proxyFlow{}
	env := flow.setupEnvForProxy("127.0.0.1:8080", "/tmp/pmg-ca.crt")

	var goProxy string
	for _, item := range env {
		if strings.HasPrefix(item, "GOPROXY=") {
			goProxy = item
			break
		}
	}

	assert.Equal(t, "GOPROXY=https://proxy.golang.org,direct", goProxy)
}

func TestRequireGoProxyCATrustForOS_ReturnsActionableErrorOffDarwin(t *testing.T) {
	flow := &proxyFlow{
		pm: testPackageManager{
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
		},
	}

	err := flow.requireGoProxyCATrustForOS("linux")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported on macOS")
	assert.Contains(t, err.Error(), "Current OS: linux")
}

func TestRequireGoProxyCATrustForOS_SkipsNonGoEcosystems(t *testing.T) {
	flow := &proxyFlow{
		pm: testPackageManager{
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
		},
	}

	err := flow.requireGoProxyCATrustForOS("linux")
	require.NoError(t, err)
}

type testPackageManager struct {
	ecosystem packagev1.Ecosystem
}

func (m testPackageManager) Name() string {
	return "test"
}

func (m testPackageManager) ParseCommand(_ []string) (*packagemanager.ParsedCommand, error) {
	return &packagemanager.ParsedCommand{}, nil
}

func (m testPackageManager) Ecosystem() packagev1.Ecosystem {
	return m.ecosystem
}
