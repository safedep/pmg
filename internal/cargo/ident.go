// Package cargo holds the identity rules of crates that the Cargo command
// parser and the Cargo registry interceptor share.
package cargo

import "regexp"

// exactVersion matches a fully-specified semver version. Anything else
// (^1.0, ~1, 1.0, wildcard requirements) is a range cargo resolves.
var exactVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// crateName matches valid crate names. A crate name has no dot, so a name
// never runs into the version in a "<name>-<version>.crate" file name.
var crateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// IsExactVersion reports whether version is a full semver version.
func IsExactVersion(version string) bool { return exactVersion.MatchString(version) }

// IsCrateName reports whether name is a valid crate name.
func IsCrateName(name string) bool { return crateName.MatchString(name) }
