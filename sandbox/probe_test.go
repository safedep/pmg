package sandbox

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeProbe struct {
	name   string
	result ProbeResult
	ran    bool
}

func (f *fakeProbe) Name() string { return f.name }
func (f *fakeProbe) Run(_ context.Context) ProbeResult {
	f.ran = true
	if f.result.Name == "" {
		f.result.Name = f.name
	}
	return f.result
}

func TestRunProbes_PreservesOrderAndStatus(t *testing.T) {
	probes := []Probe{
		&fakeProbe{name: "a", result: ProbeResult{Status: ProbeStatusOK, Summary: "a ok"}},
		&fakeProbe{name: "b", result: ProbeResult{Status: ProbeStatusWarn, Summary: "b warn"}},
		&fakeProbe{name: "c", result: ProbeResult{Status: ProbeStatusFail, Summary: "c fail"}},
	}

	results := RunProbes(context.Background(), probes)

	assert.Len(t, results, 3)
	assert.Equal(t, "a", results[0].Name)
	assert.Equal(t, ProbeStatusOK, results[0].Status)
	assert.Equal(t, "b", results[1].Name)
	assert.Equal(t, ProbeStatusWarn, results[1].Status)
	assert.Equal(t, "c", results[2].Name)
	assert.Equal(t, ProbeStatusFail, results[2].Status)
}

func TestRunProbes_HonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := &fakeProbe{name: "a", result: ProbeResult{Status: ProbeStatusOK}}
	b := &fakeProbe{name: "b", result: ProbeResult{Status: ProbeStatusOK}}

	results := RunProbes(ctx, []Probe{a, b})

	assert.Len(t, results, 2)
	assert.False(t, a.ran)
	assert.False(t, b.ran)
	assert.Equal(t, ProbeStatusSkipped, results[0].Status)
	assert.Equal(t, ProbeStatusSkipped, results[1].Status)
}

func TestRunProbes_EmptySlice(t *testing.T) {
	results := RunProbes(context.Background(), nil)
	assert.Empty(t, results)
}
