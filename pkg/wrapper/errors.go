package wrapper

import "errors"

const (
	ErrPackageInstallationDeny = "PACKAGE_INSTALLATION_DENIED"
)

var (
	ErrPackageInstall = errors.New(ErrPackageInstallationDeny)
)
