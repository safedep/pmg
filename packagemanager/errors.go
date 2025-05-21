package packagemanager

import (
	"errors"
)

var (
	ErrPackageNotFound      = errors.New("package not found")
	ErrFailedToFetchPackage = errors.New("failed to fetch package")
	ErrFailedToParsePackage = errors.New("failed to parse package")
	ErrNoPackagesFound      = errors.New("no packages found")
	ErrAuthorNotFound       = errors.New("author not found")

	ErrGitHubRateLimitExceeded = errors.New("github api rate limit exceeded")
)
