package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
)

// stubProbe is a minimal probe used by tests.
type stubProbe struct {
	name   string
	result pmgsandbox.ProbeResult
}

func (s *stubProbe) Name() string                                 { return s.name }
func (s *stubProbe) Run(_ context.Context) pmgsandbox.ProbeResult { return s.result }

func newStub(name string, status pmgsandbox.ProbeStatus) pmgsandbox.Probe {
	return &stubProbe{
		name: name,
		result: pmgsandbox.ProbeResult{
			Name:    name,
			Status:  status,
			Summary: name + " summary",
			Detail:  name + " detail",
			Fixes:   []pmgsandbox.ProbeFix{{Description: name + " fix", Command: "do thing", Docs: "https://example/" + name}},
		},
	}
}

func TestFilterByDriver(t *testing.T) {
	all := []pmgsandbox.Probe{
		newStub("driver.seatbelt.available", pmgsandbox.ProbeStatusOK),
		newStub("driver.bwrap.available", pmgsandbox.ProbeStatusOK),
		newStub("driver.landlock.abi", pmgsandbox.ProbeStatusOK),
		newStub("linux.apparmor.userns", pmgsandbox.ProbeStatusWarn),
		newStub("canary.seatbelt", pmgsandbox.ProbeStatusOK),
		newStub("canary.bubblewrap", pmgsandbox.ProbeStatusOK),
		newStub("canary.landlock", pmgsandbox.ProbeStatusOK),
	}

	cases := []struct {
		driver string
		want   []string
	}{
		{"", []string{
			"driver.seatbelt.available", "driver.bwrap.available", "driver.landlock.abi",
			"linux.apparmor.userns", "canary.seatbelt", "canary.bubblewrap", "canary.landlock",
		}},
		{"seatbelt", []string{"driver.seatbelt.available", "canary.seatbelt"}},
		{"bubblewrap", []string{"driver.bwrap.available", "linux.apparmor.userns", "canary.bubblewrap"}},
		{"landlock", []string{"driver.landlock.abi", "linux.apparmor.userns", "canary.landlock"}},
	}

	for _, tc := range cases {
		t.Run("driver="+tc.driver, func(t *testing.T) {
			got := filterByDriver(all, tc.driver)
			names := make([]string, 0, len(got))
			for _, p := range got {
				names = append(names, p.Name())
			}
			assert.Equal(t, tc.want, names)
		})
	}
}

func TestExitCodeForResults(t *testing.T) {
	cases := []struct {
		name    string
		results []pmgsandbox.ProbeResult
		want    int
	}{
		{"all ok", []pmgsandbox.ProbeResult{{Status: pmgsandbox.ProbeStatusOK}, {Status: pmgsandbox.ProbeStatusOK}}, 0},
		{"warn is ok", []pmgsandbox.ProbeResult{{Status: pmgsandbox.ProbeStatusOK}, {Status: pmgsandbox.ProbeStatusWarn}}, 0},
		{"skipped is ok", []pmgsandbox.ProbeResult{{Status: pmgsandbox.ProbeStatusSkipped}}, 0},
		{"fail trips", []pmgsandbox.ProbeResult{{Status: pmgsandbox.ProbeStatusOK}, {Status: pmgsandbox.ProbeStatusFail}}, ExitCodeProbeFailure},
		{"empty is ok", nil, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, exitCodeForResults(tc.results))
		})
	}
}

func TestRenderHuman_ContainsKeySubstrings(t *testing.T) {
	results := []pmgsandbox.ProbeResult{
		{
			Name:    "driver.seatbelt.available",
			Status:  pmgsandbox.ProbeStatusOK,
			Summary: "sandbox-exec ready",
		},
		{
			Name:    "canary.seatbelt",
			Status:  pmgsandbox.ProbeStatusFail,
			Summary: "canary blocked",
			Detail:  "policy denied read",
			Fixes:   []pmgsandbox.ProbeFix{{Description: "Update seatbelt policy", Command: "pmg fix --last", Docs: "https://docs/seatbelt"}},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, renderHuman(&buf, results))
	out := buf.String()

	assert.Contains(t, out, "STATUS")
	assert.Contains(t, out, "Seatbelt driver")
	assert.Contains(t, out, "Seatbelt canary")
	assert.Contains(t, out, "sandbox-exec ready")
	assert.Contains(t, out, "Update seatbelt policy")
	assert.NotContains(t, out, "driver.seatbelt.available")

	assert.Contains(t, out, "policy denied read")
	assert.Contains(t, out, "pmg fix --last")
	assert.Contains(t, out, "https://docs/seatbelt")
}

func TestRunDoctor_JSONRoundtrip(t *testing.T) {
	factory := func() []pmgsandbox.Probe {
		return []pmgsandbox.Probe{
			newStub("driver.seatbelt.available", pmgsandbox.ProbeStatusOK),
			newStub("canary.seatbelt", pmgsandbox.ProbeStatusFail),
		}
	}

	var buf bytes.Buffer
	opts := &doctorOptions{jsonOut: true}
	err := runDoctor(context.Background(), &buf, opts, factory)

	require.Error(t, err)
	_, ok := err.(*doctorFailError)
	require.True(t, ok, "expected doctorFailError, got %T", err)

	var report jsonReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	require.Len(t, report.Results, 2)
	assert.Equal(t, "driver.seatbelt.available", report.Results[0].Name)
	assert.Equal(t, "ok", report.Results[0].Status)
	assert.Equal(t, "canary.seatbelt", report.Results[1].Name)
	assert.Equal(t, "fail", report.Results[1].Status)
	assert.Equal(t, "canary.seatbelt fix", report.Results[1].Fixes[0].Description)
}

func TestRunDoctor_HumanSuccess(t *testing.T) {
	factory := func() []pmgsandbox.Probe {
		return []pmgsandbox.Probe{newStub("driver.seatbelt.available", pmgsandbox.ProbeStatusOK)}
	}

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, &doctorOptions{}, factory)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Seatbelt driver")
}

func TestRunDoctor_UnknownDriver(t *testing.T) {
	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, &doctorOptions{driver: "bogus"}, platform.DefaultProbes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown driver")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
}

func TestDoctorCommandRejectsUnexpectedArgsWithUsage(t *testing.T) {
	cmd := newDoctorCommand(func() []pmgsandbox.Probe { return nil })
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"extra"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "unknown command")
	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "doctor [flags]")
	assert.Contains(t, stdout.String(), "pmg sandbox doctor --driver landlock")
}

func TestDoctorCommandRuntimeErrorUsesSandboxErrorExit(t *testing.T) {
	cmd := newDoctorCommand(func() []pmgsandbox.Probe { return nil })
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--driver", "bogus"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Contains(t, err.Error(), "unknown driver")
}

func TestRunDoctor_DriverFilter(t *testing.T) {
	factory := func() []pmgsandbox.Probe {
		return []pmgsandbox.Probe{
			newStub("driver.seatbelt.available", pmgsandbox.ProbeStatusOK),
			newStub("driver.bwrap.available", pmgsandbox.ProbeStatusOK),
			newStub("canary.bubblewrap", pmgsandbox.ProbeStatusOK),
		}
	}

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, &doctorOptions{driver: "bubblewrap"}, factory)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "Bubblewrap driver")
	assert.Contains(t, out, "Bubblewrap canary")
	assert.False(t, strings.Contains(out, "Seatbelt driver"), "seatbelt should be filtered out:\n%s", out)
}

func TestDoctorFailError_ExitCode(t *testing.T) {
	e := &doctorFailError{}
	assert.Equal(t, ExitCodeProbeFailure, e.ExitCode())
}
