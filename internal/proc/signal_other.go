//go:build windows

package proc

// SignalInfo on non-unix platforms cannot decode signal termination from the
// process status, so it always reports not-signaled and the raw exit code is
// used verbatim by callers.
func SignalInfo(_ any) (signum int, signaled bool) {
	return 0, false
}
