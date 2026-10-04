package setup

import (
	"errors"
	"testing"

	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/stretchr/testify/assert"
)

func TestEvaluateEnforceCheck(t *testing.T) {
	cases := []struct {
		name       string
		newErr     error
		probe      netenforce.ProbeResult
		wantStatus doctor.CheckStatus
		wantText   string
	}{
		{"not available on this platform", errors.New("not linux"), netenforce.ProbeResult{}, doctor.StatusPass, "Linux only"},
		{"host can enforce", nil, netenforce.ProbeResult{Supported: true, KernelVersion: "6.8.0", CgroupPath: "/sys/fs/cgroup"}, doctor.StatusPass, "kernel 6.8.0"},
		{"host misses a requirement", nil, netenforce.ProbeResult{Missing: []string{"CAP_BPF is not in the effective capability set (run as root)"}}, doctor.StatusWarn, "CAP_BPF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evaluateEnforceCheck(tc.newErr, tc.probe)
			assert.Equal(t, tc.wantStatus, res.Status)
			assert.Contains(t, res.Message, tc.wantText)
		})
	}
}
