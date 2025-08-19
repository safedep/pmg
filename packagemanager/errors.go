package packagemanager

import (
	"github.com/safedep/pmg/usefulerror"
)

var (
	ErrPackageNotFound = usefulerror.Useful().
				WithCode("package_not_found").
				WithHumanError("The requested package could not be found.").
				WithHelp("Please check the package name and try again.")

	ErrFailedToFetchPackage = usefulerror.Useful().
				WithCode("fetch_failed").
				WithHumanError("Failed to retrieve the requested package.").
				WithHelp("Check your network connection and try again. If the problem persists, the package repository may be temporarily unavailable.").
				Msg("failed to fetch package")

	ErrFailedToResolveVersion = usefulerror.Useful().
					WithCode("resolve_version_failed").
					WithHumanError("Failed to resolve the requested package version.").
					WithHelp("Check your network connection and try again. If the problem persists, the package repository may be temporarily unavailable.").
					Msg("failed to resolve package version")

	ErrFailedToResolveDependencies = usefulerror.Useful().
					WithCode("resolve_failed").
					WithHumanError("Failed to resolve dependencies.").
					WithHelp("Check your network connection and try again. If the problem persists, the package repository may be temporarily unavailable.").
					Msg("failed to resolve dependencies")

	ErrFailedToParsePackage = usefulerror.Useful().
				WithCode("parse_failed").
				WithHumanError("The package data could not be processed.").
				WithHelp("The package may be corrupted or in an unsupported format.").
				Msg("failed to parse package")

	ErrAuthorNotFound = usefulerror.Useful().
				WithCode("author_not_found").
				WithHumanError("The package author information could not be found.").
				WithHelp("This may be due to incomplete package metadata or network issues.").
				Msg("author not found")

	ErrGitHubRateLimitExceeded = usefulerror.Useful().
					WithCode("github_rate_limit").
					WithHumanError("GitHub API rate limit has been exceeded.").
					WithHelp("Wait for the rate limit to reset or configure authentication to increase your rate limit.").
					Msg("github api rate limit exceeded")
)
