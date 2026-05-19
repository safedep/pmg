package sandbox

import "errors"

// Sentinel errors for the sandbox profile registry. Wrap with %w so callers
// can classify via errors.Is without inspecting error message text.
var (
	// ErrProfileNotFound is returned when a profile name does not resolve to a
	// built-in profile, a file under the user profile directory, or a literal
	// path on disk. Also returned when a profile's `inherits:` parent cannot
	// be located.
	ErrProfileNotFound = errors.New("sandbox profile not found")

	// ErrProfileInvalid is returned for profiles that fail to parse, fail
	// schema validation, or violate inheritance rules (e.g. chained inherits).
	ErrProfileInvalid = errors.New("sandbox profile invalid")
)
