//go:build unix && !linux && !darwin

package platform

func isReadOnlyMount(string) bool { return false }
