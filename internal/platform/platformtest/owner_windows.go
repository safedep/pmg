package platformtest

import "testing"

// TrustCurrentUser does nothing on Windows. A test there needs an elevated
// process to create a path that platform.RequireSystemControlled accepts.
func TrustCurrentUser(*testing.T) {}
