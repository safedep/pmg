//go:build linux
// +build linux

package platform

import (
	"fmt"
	"strings"

	"github.com/safedep/pmg/sandbox"
)

// RenderBubblewrap translates a SandboxPolicy into the bwrap argv that the
// Bubblewrap driver would invoke at runtime, encoded as one argument per
// line. One-arg-per-line is chosen over shell-quoted joining because bwrap
// arguments routinely contain absolute paths and option flags that would
// require non-trivial shell quoting; the per-line form is unambiguous and
// trivially round-trippable.
//
// This is a thin wrapper over the internal bubblewrap translator and is
// intended for inspection use cases such as
// `pmg setup sandbox profile show --driver=bwrap`.
func RenderBubblewrap(policy *sandbox.SandboxPolicy) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	t := newBubblewrapPolicyTranslator(newDefaultBubblewrapConfig())
	args, err := t.translate(policy)
	if err != nil {
		return nil, err
	}

	return []byte(strings.Join(args, "\n") + "\n"), nil
}
