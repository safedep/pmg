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

// UseSpawnerForTest replaces the spawner and clears the request and the
// suppression until restore runs.
func UseSpawnerForTest(spawn func(name string, args ...string) error) (restore func()) {
	if !testing.Testing() {
		panic("audit: UseSpawnerForTest called outside a test")
	}
	previous, requested, suppressed := spawnDetached, backgroundSyncRequested, backgroundSyncSuppressed
	spawnDetached, backgroundSyncRequested, backgroundSyncSuppressed = spawn, false, false
	return func() {
		spawnDetached, backgroundSyncRequested, backgroundSyncSuppressed = previous, requested, suppressed
	}
}
