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

// UseSpawnerForTest sends the background sync spawns of this process to spawn
// and clears the request and the suppression of the background sync. The
// returned function restores the previous spawner, request and suppression.
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
