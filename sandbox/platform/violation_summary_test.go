package platform

import (
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
)

func TestSummarizeViolation(t *testing.T) {
	tests := []struct {
		kind   sandbox.ViolationKind
		target string
		want   string
	}{
		{sandbox.ViolationKindFSRead, "/tmp/.env", "read access denied: /tmp/.env"},
		{sandbox.ViolationKindFSWrite, "/tmp/out", "write access denied: /tmp/out"},
		{sandbox.ViolationKindFSDeleteOrRename, "/tmp/x", "rename or unlink denied: /tmp/x"},
		{sandbox.ViolationKindExec, "/usr/bin/curl", "process execution denied: /usr/bin/curl"},
		{sandbox.ViolationKindNetworkConnect, "203.0.113.9:443", "direct network access blocked by network_via_proxy_only (203.0.113.9:443) — traffic must flow through the PMG proxy (a tool may have ignored HTTP_PROXY/HTTPS_PROXY)"},
		{sandbox.ViolationKindGenericDeny, "/tmp/x", "sandbox denied access to /tmp/x"},
		{sandbox.ViolationKindGenericDeny, "", "sandbox denied an operation"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, summarizeViolation(tc.kind, tc.target))
	}
}
