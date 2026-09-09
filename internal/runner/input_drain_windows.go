//go:build windows

package runner

// waitForInputReader does not wait. PMG selects the PTY mode only when stdin
// is a terminal, so the stdin reader is always blocked in a read on a console
// handle, and a read on the Windows console cannot be cancelled. The reader
// can therefore never see the cancelled context, and any wait here would add
// its full length to the exit of every interactive run and change nothing.
//
// Leaving the reader parked is safe. The child has already exited by the time
// PMG tears the session down, so the reader has no work left, it owns nothing
// the process needs, and it dies with the process. Waiting for it is what held
// `pmg npm install` open until the developer pressed a key.
func waitForInputReader(<-chan struct{}) {}
