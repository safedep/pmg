package platform

import (
	"errors"
	"fmt"
	"os"
	"os/user"
)

// PasswdHomeDir returns the home directory of the current user from the user
// database, so a HOME that another account left in the environment does not
// steer it. In a build without cgo, Go's os/user takes HOME when the database
// has no entry for the user. Tests replace it.
var PasswdHomeDir = passwdHomeDir

func passwdHomeDir() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("user %s has no home directory in the user database", u.Username)
	}
	return u.HomeDir, nil
}

// UserHomeDir returns the home directory that the environment names, which
// is the one the child processes of pmg use. When the environment names none,
// as in a systemd unit without User=, it returns PasswdHomeDir. Package
// managers such as npm and pip resolve their home the same way.
func UserHomeDir() (string, error) {
	home, envErr := os.UserHomeDir()
	if envErr == nil {
		return home, nil
	}

	home, err := PasswdHomeDir()
	if err != nil {
		return "", errors.Join(envErr, err)
	}
	return home, nil
}
