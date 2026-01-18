package packagemanager

import (
	"github.com/safedep/pmg/usefulerror"
)

const (
	errDependencyResolutionFailed = "DependencyResolutionFailed"
	errPackageParseFailed         = "PackageParseFailed"
	errPackageAuthorNotFound      = "PackageAuthorNotFound"
	errGitHubRateLimitExceeded    = "GitHubRateLimitExceeded"
)

var (
	ErrPackageNotFound = usefulerror.Useful().
				WithCode(usefulerror.ErrCodeNotFound).
				WithHumanError("The requested package could not be found.").
				WithHelp("Please check the package name and try again.")

	ErrFailedToFetchPackage = usefulerror.Useful().
				WithCode(usefulerror.ErrCodeNetwork).
				WithHumanError("Failed to retrieve the requested package.").
				WithHelp("Check your network connection and try again.").
				Msg("failed to fetch package")

	ErrFailedToResolveVersion = usefulerror.Useful().
					WithCode(usefulerror.ErrCodeNetwork).
					WithHumanError("Failed to resolve the requested package version.").
					WithHelp("Check your network connection and try again.").
					Msg("failed to resolve package version")

	ErrFailedToResolveDependencies = usefulerror.Useful().
					WithCode(errDependencyResolutionFailed).
					WithHumanError("Failed to resolve dependencies.").
					WithHelp("Check your network connection and try again.").
					Msg("failed to resolve dependencies")

	ErrFailedToParsePackage = usefulerror.Useful().
				WithCode(errPackageParseFailed).
				WithHumanError("The package data could not be processed.").
				WithHelp("The package may be corrupted or in an unsupported format.").
				Msg("failed to parse package")

	ErrAuthorNotFound = usefulerror.Useful().
				WithCode(errPackageAuthorNotFound).
				WithHumanError("The package author information could not be found.").
				WithHelp("This may be due to incomplete package metadata or network issues.").
				Msg("author not found")

	ErrGitHubRateLimitExceeded = usefulerror.Useful().
					WithCode(errGitHubRateLimitExceeded).
					WithHumanError("GitHub API rate limit has been exceeded.").
					WithHelp("Wait for the rate limit to reset or configure authentication to increase your rate limit.").
					Msg("github api rate limit exceeded")
)
