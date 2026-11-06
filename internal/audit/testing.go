package audit

import "testing"

// UseSinksForTest sends the audit events of this process to sinks until the
// returned function restores the previous auditor. A test outside this
// package uses it to check the events of a flow.
func UseSinksForTest(sinks ...Sink) (restore func()) {
	if !testing.Testing() {
		panic("audit: UseSinksForTest called outside a test")
	}
	previous := global
	setGlobal(newAuditor(sinks...))
	return func() { setGlobal(previous) }
}
