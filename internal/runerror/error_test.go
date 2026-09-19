package runerror

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapNil(t *testing.T) {
	assert.NoError(t, Wrap(nil, ReasonProxySetupFailed))
	assert.Nil(t, From(nil))
}

func TestWrapPreservesCauseAndInfo(t *testing.T) {
	cause := errors.New("private transport detail")
	inner := Wrap(cause, ReasonProxySetupFailed)
	outer := Wrap(fmt.Errorf("run failed: %w", inner), ReasonExecutionSetupFailed)

	require.ErrorIs(t, outer, cause)
	info := From(outer)
	require.NotNil(t, info)
	assert.Equal(t, ReasonProxySetupFailed, info.Reason)
	assert.Equal(t, SourcePMG, info.Source)
	assert.Equal(t, "private transport detail", info.Message)
}

func TestFromOrdinaryErrorReturnsNil(t *testing.T) {
	info := From(errors.New("private detail"))
	assert.Nil(t, info)
}

func TestWrapBoundsErrorMessage(t *testing.T) {
	err := Wrap(errors.New(strings.Repeat("a", 1023)+"\xfftail"), ReasonProxySetupFailed)

	info := From(err)
	require.NotNil(t, info)
	assert.True(t, utf8.ValidString(info.Message))
	assert.LessOrEqual(t, len(info.Message), 1024)
}

func TestWrapOmitsChildProcessMessage(t *testing.T) {
	info := From(Wrap(errors.New("npm exited with code 42"), ReasonProcessExited))

	require.NotNil(t, info)
	assert.Empty(t, info.Message)
}

func TestSourceForReason(t *testing.T) {
	tests := []struct {
		name   string
		reason Reason
		want   Source
	}{
		{"unspecified", ReasonUnspecified, SourceUnspecified},
		{"process exited", ReasonProcessExited, SourceChildProcess},
		{"process signaled", ReasonProcessSignaled, SourceChildProcess},
		{"parse", ReasonCommandParseFailed, SourcePMG},
		{"configuration", ReasonConfigurationInvalid, SourcePMG},
		{"ecosystem", ReasonEcosystemUnsupported, SourcePMG},
		{"certificate", ReasonCertificateSetupFailed, SourcePMG},
		{"analyzer", ReasonAnalyzerInitializationFailed, SourcePMG},
		{"proxy", ReasonProxySetupFailed, SourcePMG},
		{"executable missing", ReasonExecutableNotFound, SourcePMG},
		{"executable resolution", ReasonExecutableResolutionFailed, SourcePMG},
		{"launch", ReasonProcessLaunchFailed, SourcePMG},
		{"execution setup", ReasonExecutionSetupFailed, SourcePMG},
		{"future value", Reason(100), SourceUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sourceForReason(tt.reason))
		})
	}
}
