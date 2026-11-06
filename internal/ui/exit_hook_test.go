package ui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExitRunsTheHookOnceBeforeExit(t *testing.T) {
	var events []string
	origExit := osExit
	t.Cleanup(func() {
		osExit = origExit
		SetExitHook(nil)
	})
	osExit = func(code int) { events = append(events, "exit") }

	SetExitHook(func() { events = append(events, "hook") })
	ErrorExit(errors.New("blocked"))
	Fatalf("again")

	assert.Equal(t, []string{"hook", "exit", "exit"}, events)
}
