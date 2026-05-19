package sandbox

import "errors"

// Wrap these with %w so cmd-layer code can classify via errors.Is
// instead of inspecting message text.
var (
	ErrProfileNotFound = errors.New("sandbox profile not found")
	ErrProfileInvalid  = errors.New("sandbox profile invalid")
)
