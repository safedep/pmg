package flows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

	assert.Equal(t, "GOPROXY=https://proxy.golang.org,http://127.0.0.1:8080,direct", goProxy)
}
