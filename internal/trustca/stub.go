//go:build !darwin

package trustca

func installDarwinUserKeychain(_ string) error {
	return nil
}

func removeDarwinUserKeychain() error {
	return nil
}

func darwinUserTrustInstalled() bool {
	return false
}
