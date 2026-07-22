package packagemanager

import (
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

var (
	ErrFailedToResolveVersion = usefulerror.NewUsefulError().
					WithCode(errcodes.Network).
					WithHumanError("Failed to resolve the requested package version.").
					WithHelp("Check your network connection and try again.").
					WithMsg("failed to resolve package version")

	ErrFailedToParsePackage = usefulerror.NewUsefulError().
				WithCode(errcodes.PackageParseFailed).
				WithHumanError("The package data could not be processed.").
				WithHelp("The package may be corrupted or in an unsupported format.").
				WithMsg("failed to parse package")

	ErrAuthorNotFound = usefulerror.NewUsefulError().
				WithCode(errcodes.PackageAuthorNotFound).
				WithHumanError("The package author information could not be found.").
				WithHelp("This may be due to incomplete package metadata or network issues.").
				WithMsg("author not found")

	ErrGitHubRateLimitExceeded = usefulerror.NewUsefulError().
					WithCode(errcodes.GitHubRateLimitExceeded).
					WithHumanError("GitHub API rate limit has been exceeded.").
					WithHelp("Wait for the rate limit to reset or configure authentication to increase your rate limit.").
					WithMsg("github api rate limit exceeded")
)
