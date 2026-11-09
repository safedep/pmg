package ui

import (
	"os"
	"sync"
)

var (
	exitHookMu sync.Mutex
	exitHook   func()
)

// SetExitHook sets a function that runs once before pmg exits through this
// package. main uses it to close the audit system and to start the
// background sync child on every exit path, also after a blocked install.
func SetExitHook(hook func()) {
	exitHookMu.Lock()
	defer exitHookMu.Unlock()
	exitHook = hook
}

// RunExitHook runs the exit hook, at most once.
func RunExitHook() {
	exitHookMu.Lock()
	hook := exitHook
	exitHook = nil
	exitHookMu.Unlock()

	if hook != nil {
		hook()
	}
}

// osExit is os.Exit. A test replaces it.
var osExit = os.Exit

// exit runs the exit hook and exits with code.
func exit(code int) {
	RunExitHook()
	osExit(code)
}
