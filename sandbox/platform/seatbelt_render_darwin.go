//go:build darwin
// +build darwin

package platform

import (
	"fmt"

	"github.com/safedep/pmg/sandbox"
)

// RenderSeatbelt translates a SandboxPolicy into its native Seatbelt Profile
// Language (SBPL) source. This is a thin wrapper around the internal seatbelt
// translator and is intended for inspection use cases such as
// `pmg setup sandbox profile show --driver=seatbelt`.
//
// The output contains a per-render random log tag (PMG_SBX_<random>) used at
// runtime to correlate violations; callers comparing renders should normalize
// it.
func RenderSeatbelt(policy *sandbox.SandboxPolicy) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	t := newSeatbeltPolicyTranslator()
	out, err := t.translate(policy)
	if err != nil {
		return nil, err
	}

	return []byte(out), nil
}
